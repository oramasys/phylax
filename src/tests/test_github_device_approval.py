"""GitHub CLI evidence is fresh, exact, and never stores credentials."""

from __future__ import annotations

import json
import sqlite3
import subprocess
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
        """Queue the CLI outputs to return, in call order."""
        self._responses = iter(responses)
        self.calls: list[tuple[list[str], dict[str, str], bool, float | None]] = []

    def __call__(
        self, command: list[str], *, env: dict[str, str], capture_output: bool, timeout: float | None,
    ) -> str:
        """Record one CLI invocation and return the next queued output."""
        self.calls.append((command, env, capture_output, timeout))
        return next(self._responses)


@pytest.fixture(autouse=True)
def no_ambient_github_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep ordinary adapter tests independent of workstation token exports."""
    for name in (
        "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_COPILOT_PAT",
        "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST", "GITHUB_HOST", "GH_REPO",
        "GH_PROMPT_DISABLED", "GH_NO_UPDATE_NOTIFIER", "GH_DEBUG", "GH_PAGER", "PAGER",
        "CLICOLOR_FORCE", "NO_COLOR",
    ):
        monkeypatch.delenv(name, raising=False)


def marker(
    config_dir: Path, *, account: str = "operator", account_id: int = 7,
    issued_at: int | None = None,
) -> None:
    """Write the proof produced after a human performs the fresh login."""
    config_dir.mkdir(mode=0o700)
    path = config_dir / MODEL_AUTH_MARKER
    path.write_text(json.dumps({
        "schema": 1,
        "account": account,
        "account_id": account_id,
        "issued_at": int(NOW.timestamp()) if issued_at is None else issued_at,
    }), encoding="utf-8")
    path.chmod(0o600)


def account(*, login: str = "operator", user_id: int = 7) -> str:
    """Return the stable identity response exposed by the GitHub API."""
    return json.dumps({"login": login, "id": user_id})


def fake_gh(directory: Path) -> Path:
    """Create one absolute executable seam for GitHub CLI command tests."""
    executable = directory / "gh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def comment(
    launch: ModelLaunchIntent, *, account: str = "operator", user_id: int = 7, body: str | None = None,
    created_at: str = "2026-10-23T00:00:00Z",
) -> str:
    """Return a minimal GitHub API comment response."""
    return json.dumps({
        "id": 17,
        "html_url": "https://github.com/acme/control/issues/7#issuecomment-17",
        "user": {"login": account, "id": user_id},
        "body": body or approval_body(launch),
        "created_at": created_at,
        "updated_at": created_at,
    })


def verifier(
    config_dir: Path, responses: list[str], *, now: datetime = NOW,
) -> tuple[GitHubCliModelApprovalVerifier, Runner]:
    """Create a real verifier around a fake subprocess seam."""
    runner = Runner(responses)
    return (
        GitHubCliModelApprovalVerifier(
            config_dir=config_dir,
            repository="acme/control",
            approvers={7: "control-plane"},
            runner=runner,
            gh_executable=fake_gh(config_dir.parent),
            clock=lambda: now,
        ),
        runner,
    )


def test_fresh_cli_login_and_exact_comment_create_approved_p5_authority(tmp_path: Path) -> None:
    """A fresh marker and an exact allowlisted comment create one approved P5 record via pinned calls."""
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, runner = verifier(config_dir, [account(), comment(launch)])
    authority = ModelLaunchApprovalAuthority(
        signing_key=b"test-key", store=SqliteP5ApprovalStore(str(tmp_path / "p5.db")),
        evidence_verifier=adapter, clock=lambda: NOW,
    )

    receipt = authority.approve_model_launch(
        launch, evidence_ref="https://github.com/acme/control/issues/7#issuecomment-17"
    )

    assert states(tmp_path / "p5.db") == ["approved"]
    assert receipt.approved_duration_seconds == 5_400
    assert Path(runner.calls[0][0][0]).is_absolute()
    assert runner.calls[0][0][1:] == ["api", "--hostname", "github.com", "user"]
    assert runner.calls[1][0][1:] == [
        "api", "--hostname", "github.com", "repos/acme/control/issues/comments/17",
    ]
    assert all("GITHUB_TOKEN" not in environment for _, environment, _, _ in runner.calls)
    assert not (config_dir / MODEL_AUTH_MARKER).exists()


@pytest.mark.parametrize("comment_login,comment_user_id,body,updated_at", [
    ("other", 8, None, "2026-10-23T00:00:00Z"),
    ("operator", 7, "different", "2026-10-23T00:00:00Z"),
    ("operator", 7, None, "2026-10-23T00:00:01Z"),
])
def test_only_allowlisted_unedited_exact_confirmation_creates_authority(
    tmp_path: Path, comment_login: str, comment_user_id: int, body: str | None, updated_at: str,
) -> None:
    """Another author, a different body or an edited comment creates no authority and still spends the marker."""
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    raw = json.loads(comment(launch, account=comment_login, user_id=comment_user_id, body=body))
    raw["updated_at"] = updated_at
    adapter, _ = verifier(config_dir, [account(), json.dumps(raw)])
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


def test_authorization_uses_stable_numeric_id_not_mutable_login(tmp_path: Path) -> None:
    """Authorization follows the numeric GitHub user ID, so a renamed login still maps to its principal."""
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir, account="renamed-operator")
    adapter, _ = verifier(config_dir, [
        account(login="renamed-operator"),
        comment(launch, account="another-display-name"),
    ])

    verified = adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")

    assert verified.operator_principal == "control-plane"


def test_marker_cannot_outlive_original_five_minute_review_window(tmp_path: Path) -> None:
    """A marker older than five minutes is refused before any CLI call."""
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
    """A symlinked or group/world-readable marker is refused before any CLI call."""
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
    """A config directory reached through a symlink is refused before the marker is read."""
    actual = tmp_path / "actual"
    marker(actual)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    adapter, runner = verifier(alias, [])

    with pytest.raises(ValueError, match="config directory"):
        adapter.verify(intent(), "https://github.com/acme/control/issues/7#issuecomment-17")
    assert runner.calls == []


def test_marker_is_spent_even_when_readback_fails(tmp_path: Path) -> None:
    """The marker is spent before comment readback, so a failed readback cannot be retried with it."""
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, _ = verifier(config_dir, [account(), "not-json"])

    with pytest.raises(ValueError, match="GitHub comment"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    assert not (config_dir / MODEL_AUTH_MARKER).exists()


def test_comment_from_before_fresh_login_cannot_be_reused(tmp_path: Path) -> None:
    """A comment created before the fresh login is refused, so old approvals cannot be replayed."""
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, _ = verifier(config_dir, [
        account(), comment(launch, created_at="2026-10-22T23:59:59Z"),
    ])

    with pytest.raises(ValueError, match="predates"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    assert not (config_dir / MODEL_AUTH_MARKER).exists()


def test_begin_login_uses_new_isolated_config_without_capturing_device_code(tmp_path: Path) -> None:
    """Login runs uncaptured in a new isolated config with insecure storage, then writes the marker."""
    config_dir = tmp_path / "isolated"
    executable = fake_gh(tmp_path)
    runner = Runner(["", account()])

    login = begin_fresh_github_login(
        config_dir, runner=runner, gh_executable=executable, clock=lambda: NOW,
    )

    assert login == "operator"
    assert runner.calls[0][0] == [
        str(executable), "auth", "login", "--web", "--hostname", "github.com", "--git-protocol", "https",
        "--insecure-storage",
    ]
    assert runner.calls[0][2] is False
    assert runner.calls[0][3] is None
    assert runner.calls[1][0] == [str(executable), "api", "--hostname", "github.com", "user"]
    assert runner.calls[1][3] == 20.0
    saved = json.loads((config_dir / MODEL_AUTH_MARKER).read_text(encoding="utf-8"))
    assert saved == {
        "account": "operator",
        "account_id": 7,
        "issued_at": int(NOW.timestamp()),
        "schema": 1,
    }


@pytest.mark.parametrize("token_name", (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
    "GITHUB_COPILOT_PAT",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
))
def test_token_environment_is_refused_before_any_human_approval_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token_name: str,
) -> None:
    """Any ambient GitHub token variable is refused before any CLI call, leaving the marker unspent."""
    monkeypatch.setenv(token_name, "must-not-be-used")
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, runner = verifier(config_dir, [account(), comment(launch)])

    with pytest.raises(ValueError, match="token environment"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    assert runner.calls == []
    assert (config_dir / MODEL_AUTH_MARKER).exists()


def test_host_overrides_are_removed_and_public_github_is_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Host, repo, pager and debug overrides are stripped and every call is pinned to github.com."""
    monkeypatch.setenv("GH_HOST", "internal.example")
    monkeypatch.setenv("GITHUB_HOST", "internal.example")
    monkeypatch.setenv("GH_REPO", "internal/control")
    monkeypatch.setenv("GH_PROMPT_DISABLED", "1")
    monkeypatch.setenv("GH_NO_UPDATE_NOTIFIER", "1")
    monkeypatch.setenv("GH_DEBUG", "api")
    monkeypatch.setenv("GH_PAGER", "cat")
    monkeypatch.setenv("PAGER", "cat")
    monkeypatch.setenv("CLICOLOR_FORCE", "1")
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, runner = verifier(config_dir, [account(), comment(launch)])

    adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")

    for _command, environment, _captured, _timeout in runner.calls:
        assert environment["GH_HOST"] == "github.com"
        assert "GITHUB_HOST" not in environment
        assert "GH_REPO" not in environment
        assert "GH_PROMPT_DISABLED" not in environment
        assert "GH_NO_UPDATE_NOTIFIER" not in environment
        assert "GH_DEBUG" not in environment
        assert "GH_PAGER" not in environment
        assert "PAGER" not in environment
        assert "CLICOLOR_FORCE" not in environment
        assert environment["NO_COLOR"] == "1"


def test_unsafe_config_parent_is_refused_before_cli_readback(tmp_path: Path) -> None:
    """A config directory under a group-writable, non-sticky parent is refused before any CLI call."""
    parent = tmp_path / "unsafe-parent"
    parent.mkdir(mode=0o700)
    config_dir = parent / "isolated"
    marker(config_dir)
    parent.chmod(0o770)
    adapter, runner = verifier(config_dir, [])

    try:
        with pytest.raises(ValueError, match="unsafe parent"):
            adapter.verify(intent(), "https://github.com/acme/control/issues/7#issuecomment-17")
    finally:
        parent.chmod(0o700)
    assert runner.calls == []


def test_sticky_config_parent_is_accepted(tmp_path: Path) -> None:
    """A world-writable parent with the sticky bit (like /tmp) is an accepted config parent."""
    parent = tmp_path / "sticky-parent"
    parent.mkdir(mode=0o700)
    config_dir = parent / "isolated"
    marker(config_dir)
    parent.chmod(0o1777)
    launch = intent()
    adapter, _ = verifier(config_dir, [account(), comment(launch)])

    try:
        verified = adapter.verify(
            launch, "https://github.com/acme/control/issues/7#issuecomment-17"
        )
    finally:
        parent.chmod(0o700)
    assert verified.operator_principal == "control-plane"


@pytest.mark.parametrize("raw", [
    json.dumps({"login": "operator", "id": 7, "padding": "x" * 262_144}),
    '{"login":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":{"nested":0}}}}}}}}}}}}}}}}},"id":7}',
])
def test_bounded_account_readback_is_refused_before_marker_spend(tmp_path: Path, raw: str) -> None:
    """An oversized or deeply nested account response is refused before the marker is spent."""
    config_dir = tmp_path / "isolated"
    marker(config_dir)
    adapter, _ = verifier(config_dir, [raw])

    with pytest.raises(ValueError, match="did not identify"):
        adapter.verify(intent(), "https://github.com/acme/control/issues/7#issuecomment-17")
    assert (config_dir / MODEL_AUTH_MARKER).exists()


@pytest.mark.parametrize("failure", [
    subprocess.TimeoutExpired(["gh", "api"], 20),
    subprocess.CalledProcessError(1, ["gh", "api"]),
    FileNotFoundError("gh"),
    OSError("runner failure"),
])
def test_cli_failures_are_normalized_and_spend_marker_after_account_readback(
    tmp_path: Path, failure: BaseException,
) -> None:
    """Every CLI failure surfaces as one public error, and the marker is spent once readback starts."""
    class FailingRunner:
        """Answer account readback, then raise the parametrized failure on the next call."""
        def __init__(self) -> None:
            """Start with no calls recorded."""
            self.calls = 0

        def __call__(
            self, command: list[str], *, env: dict[str, str], capture_output: bool, timeout: float | None,
        ) -> str:
            """Return the account on the first call and raise the failure afterwards."""
            self.calls += 1
            if self.calls == 1:
                return account()
            raise failure

    config_dir = tmp_path / "isolated"
    marker(config_dir)
    runner = FailingRunner()
    adapter = GitHubCliModelApprovalVerifier(
        config_dir=config_dir,
        repository="acme/control",
        approvers={7: "control-plane"},
        runner=runner,
        gh_executable=fake_gh(tmp_path),
        clock=lambda: NOW,
    )

    with pytest.raises(ValueError, match="GitHub CLI invocation failed"):
        adapter.verify(intent(), "https://github.com/acme/control/issues/7#issuecomment-17")
    assert not (config_dir / MODEL_AUTH_MARKER).exists()


def test_second_verify_of_the_same_marker_fails_closed_before_comment_readback(tmp_path: Path) -> None:
    """A second verification with a spent marker fails closed before any further CLI call."""
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    adapter, runner = verifier(config_dir, [account(), comment(launch)])

    adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    with pytest.raises(ValueError, match="already spent"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")

    assert len(runner.calls) == 2


def test_marker_that_expires_during_account_readback_is_not_spent(tmp_path: Path) -> None:
    """The clock is read again after account readback, so a marker that expired meanwhile fails.

    The marker is 299 seconds old at the first read and 302 seconds old after the network call:
    it must be refused before it is spent and before any comment readback.
    """
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir, issued_at=int((NOW - timedelta(seconds=299)).timestamp()))
    readings = iter((NOW, NOW + timedelta(seconds=3)))
    runner = Runner([account(), comment(launch)])
    adapter = GitHubCliModelApprovalVerifier(
        config_dir=config_dir,
        repository="acme/control",
        approvers={7: "control-plane"},
        runner=runner,
        gh_executable=fake_gh(tmp_path),
        clock=lambda: next(readings),
    )

    with pytest.raises(ValueError, match="expired or invalid"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")

    assert len(runner.calls) == 1  # account readback only; no comment readback
    assert (config_dir / MODEL_AUTH_MARKER).exists()  # not spent


@pytest.mark.parametrize("comment_response", ("ok", "not-json"))
def test_cli_credentials_are_discarded_after_readback_but_the_spent_marker_stays(
    tmp_path: Path, comment_response: str,
) -> None:
    """After comment readback, success or failure, only Phylax's spent marker remains."""
    config_dir = tmp_path / "isolated"
    launch = intent()
    marker(config_dir)
    (config_dir / "hosts.yml").write_text("github.com:\n  oauth_token: synthetic\n", encoding="utf-8")
    (config_dir / "state").mkdir()
    response = comment(launch) if comment_response == "ok" else "not-json"
    adapter, runner = verifier(config_dir, [account(), response])

    if comment_response == "ok":
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    else:
        with pytest.raises(ValueError, match="GitHub comment"):
            adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")

    assert sorted(p.name for p in config_dir.iterdir()) == [f"{MODEL_AUTH_MARKER}.spent"]
    with pytest.raises(ValueError, match="already spent"):
        adapter.verify(launch, "https://github.com/acme/control/issues/7#issuecomment-17")
    assert len(runner.calls) == 2


def test_cli_credentials_are_discarded_when_the_account_is_refused(tmp_path: Path) -> None:
    """An unauthorized account ends the ceremony: the credential is removed, the marker is not spent."""
    config_dir = tmp_path / "isolated"
    marker(config_dir, account_id=99)
    (config_dir / "hosts.yml").write_text("synthetic\n", encoding="utf-8")
    adapter, _ = verifier(config_dir, [account(user_id=99)])

    with pytest.raises(ValueError):
        adapter.verify(intent(), "https://github.com/acme/control/issues/7#issuecomment-17")

    assert sorted(p.name for p in config_dir.iterdir()) == [MODEL_AUTH_MARKER]


@pytest.mark.parametrize("account_response", ("not-json", json.dumps({"login": "x"})))
def test_begin_login_removes_its_config_directory_when_setup_fails(
    tmp_path: Path, account_response: str,
) -> None:
    """A failure after login leaves no isolated config, token or marker behind."""
    config_dir = tmp_path / "isolated"
    runner = Runner(["", account_response])

    with pytest.raises(ValueError):
        begin_fresh_github_login(
            config_dir, runner=runner, gh_executable=fake_gh(tmp_path), clock=lambda: NOW,
        )

    assert not config_dir.exists()
