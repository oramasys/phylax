"""GitHub CLI evidence is fresh, exact, and never stores credentials."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phylax.github_device_approval import (
    GitHubCliModelApprovalVerifier,
    MODEL_AUTH_MARKER,
    approval_body,
    begin_fresh_github_login,
)
from phylax.model_launch_approval import ModelLaunchApprovalAuthority, ModelLaunchIntent
from phylax.p5_approval import SqliteP5ApprovalStore


NOW = datetime(2026, 10, 23, tzinfo=UTC)


def intent(*, expires_in: int = 300) -> ModelLaunchIntent:
    """Create one fully bound launch independent of another test module."""
    return ModelLaunchIntent.from_launch("control-plane", {
        "request_id": "request-a", "task_id": "task-a", "run_id": "run-a",
        "operation_id": "operation-a", "harness_path": "provider-a",
        "model_id": "model-a", "effort": "medium", "fast": False,
        "budget_cap": "cap-reference-a", "scope": "task-a",
        "mode": "standard", "policy_revision": "policy-a",
        "review_expires_at": int(NOW.timestamp()) + expires_in,
    })


def states(path: Path) -> list[str]:
    """Inspect durable P5 state rather than asserting a mocked write."""
    with closing(sqlite3.connect(path)) as database:
        return [row[0] for row in database.execute("SELECT state FROM p5_approvals")]


class Runner:
    """Record CLI calls and return harmless pre-arranged output."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = iter(responses)
        self.calls: list[tuple[list[str], dict[str, str], bool]] = []

    def __call__(self, command: list[str], *, env: dict[str, str], capture_output: bool) -> str:
        self.calls.append((command, env, capture_output))
        return next(self._responses)


@pytest.fixture(autouse=True)
def no_ambient_github_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep ordinary adapter tests independent of workstation token exports."""
    for name in (
        "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_COPILOT_PAT",
    ):
        monkeypatch.delenv(name, raising=False)


def marker(config_dir: Path, *, account: str = "operator", issued_at: int | None = None) -> None:
    """Write the proof produced after a human performs the fresh login."""
    config_dir.mkdir(mode=0o700)
    path = config_dir / MODEL_AUTH_MARKER
    path.write_text(json.dumps({
        "schema": 1,
        "account": account,
        "issued_at": int(NOW.timestamp()) if issued_at is None else issued_at,
    }), encoding="utf-8")
    path.chmod(0o600)


def comment(
    launch: ModelLaunchIntent, *, account: str = "operator", body: str | None = None,
    created_at: str = "2026-10-23T00:00:00Z",
) -> str:
    """Return a minimal GitHub API comment response."""
    return json.dumps({
        "id": 17,
        "html_url": "https://github.com/acme/control/issues/7#issuecomment-17",
        "user": {"login": account},
        "body": body or approval_body(launch),
        "created_at": created_at,
        "updated_at": created_at,
    })


def verifier(config_dir: Path, responses: list[str], *, now=NOW) -> tuple[GitHubCliModelApprovalVerifier, Runner]:
    """Create a real verifier around a fake subprocess seam."""
    runner = Runner(responses)
    return (
        GitHubCliModelApprovalVerifier(
            config_dir=config_dir,
            repository="acme/control",
            approvers={"operator": "control-plane"},
            runner=runner,
            clock=lambda: now,
        ),
        runner,
    )


def test_fresh_cli_login_and_exact_comment_create_approved_p5_authority(tmp_path: Path) -> None:
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, runner = verifier(config_dir, ["operator\n", comment(launch)])
    authority = ModelLaunchApprovalAuthority(
        signing_key=b"test-key", store=SqliteP5ApprovalStore(str(tmp_path / "p5.db")),
        evidence_verifier=adapter, clock=lambda: NOW,
    )

    receipt = authority.approve_model_launch(
        launch, evidence_ref="https://github.com/acme/control/issues/7#issuecomment-17"
    )

    assert states(tmp_path / "p5.db") == ["approved"]
    assert receipt.approved_duration_seconds == 5_400
    assert runner.calls[0][0] == ["gh", "api", "user", "--jq", ".login"]
    assert runner.calls[1][0] == ["gh", "api", "repos/acme/control/issues/comments/17"]
    assert all("GITHUB_TOKEN" not in environment for _, environment, _ in runner.calls)
    assert not (config_dir / MODEL_AUTH_MARKER).exists()


@pytest.mark.parametrize("account,body,updated_at", [
    ("other", None, "2026-10-23T00:00:00Z"),
    ("operator", "different", "2026-10-23T00:00:00Z"),
    ("operator", None, "2026-10-23T00:00:01Z"),
])
def test_only_allowlisted_unedited_exact_confirmation_creates_authority(
    tmp_path: Path, account: str, body: str | None, updated_at: str,
) -> None:
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    raw = json.loads(comment(launch, account=account, body=body))
    raw["updated_at"] = updated_at
    adapter, _ = verifier(config_dir, ["operator\n", json.dumps(raw)])
    authority = ModelLaunchApprovalAuthority(
        signing_key=b"test-key", store=SqliteP5ApprovalStore(str(tmp_path / "p5.db")),
        evidence_verifier=adapter, clock=lambda: NOW,
    )

    with pytest.raises(ValueError):
        authority.approve_model_launch(
            launch, evidence_ref="https://github.com/acme/control/issues/7#issuecomment-17"
        )
    assert states(tmp_path / "p5.db") == []
    assert not (config_dir / MODEL_AUTH_MARKER).exists()


def test_marker_cannot_outlive_original_five_minute_review_window(tmp_path: Path) -> None:
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir, issued_at=int((NOW - timedelta(seconds=301)).timestamp()))
    adapter, runner = verifier(config_dir, [])

    with pytest.raises(ValueError, match="fresh GitHub login"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    assert runner.calls == []


@pytest.mark.parametrize("unsafe_marker", ("symlink", "broad"))
def test_unsafe_marker_is_refused_before_cli_readback(
    tmp_path: Path, unsafe_marker: str,
) -> None:
    config_dir = tmp_path / "isolated"
    marker(config_dir)
    path = config_dir / MODEL_AUTH_MARKER
    if unsafe_marker == "symlink":
        target = tmp_path / "other-marker.json"
        target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target)
    else:
        path.chmod(0o644)
    adapter, runner = verifier(config_dir, [])

    with pytest.raises(ValueError, match="marker is unreadable"):
        adapter.verify(intent(), "https://github.com/acme/control/issues/7#issuecomment-17")
    assert runner.calls == []


def test_symlinked_config_directory_is_refused_before_marker_readback(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    marker(actual)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    adapter, runner = verifier(alias, [])

    with pytest.raises(ValueError, match="config directory"):
        adapter.verify(intent(), "https://github.com/acme/control/issues/7#issuecomment-17")
    assert runner.calls == []


def test_marker_is_spent_even_when_readback_fails(tmp_path: Path) -> None:
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, _ = verifier(config_dir, ["operator\n", "not-json"])

    with pytest.raises(ValueError, match="GitHub comment"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    assert not (config_dir / MODEL_AUTH_MARKER).exists()


def test_comment_from_before_fresh_login_cannot_be_reused(tmp_path: Path) -> None:
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, _ = verifier(config_dir, [
        "operator\n", comment(launch, created_at="2026-10-22T23:59:59Z"),
    ])

    with pytest.raises(ValueError, match="predates"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    assert not (config_dir / MODEL_AUTH_MARKER).exists()


def test_begin_login_uses_new_isolated_config_without_capturing_device_code(tmp_path: Path) -> None:
    config_dir = tmp_path / "isolated"
    runner = Runner(["", "operator\n"])

    account = begin_fresh_github_login(config_dir, runner=runner, clock=lambda: NOW)

    assert account == "operator"
    assert runner.calls[0][0] == [
        "gh", "auth", "login", "--web", "--hostname", "github.com", "--git-protocol", "https",
    ]
    assert runner.calls[0][2] is False
    assert runner.calls[1][0] == ["gh", "api", "user", "--jq", ".login"]
    saved = json.loads((config_dir / MODEL_AUTH_MARKER).read_text(encoding="utf-8"))
    assert saved == {"account": "operator", "issued_at": int(NOW.timestamp()), "schema": 1}


def test_token_environment_is_refused_before_any_human_approval_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-be-used")
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, runner = verifier(config_dir, ["operator\n", comment(launch)])

    with pytest.raises(ValueError, match="token environment"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    assert runner.calls == []
    assert (config_dir / MODEL_AUTH_MARKER).exists()
