"""GitHub CLI evidence for a human-approved model launch.

GitHub CLI owns the OAuth device flow. This adapter deliberately neither creates
a GitHub OAuth client nor receives a device code or access token. A human runs
``begin_fresh_github_login`` in a fresh isolated CLI configuration, posts an
exact launch-confirmation comment, and supplies that comment URL to Phylax.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import re
import subprocess
from typing import Callable, Mapping

from .model_launch_approval import ModelLaunchIntent, VerifiedModelApproval

_TOKEN_ENVIRONMENT = (
    "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_COPILOT_PAT",
)
_COMMENT_REFERENCE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:issues|pull)/(\d+)#issuecomment-(\d+)$"
)
_SCHEMA = "oramasys-model-launch-approval: v1"
_FRESH_TTL = timedelta(seconds=300)
MODEL_AUTH_MARKER = "model-launch-fresh-auth.v1.json"


def _utc_timestamp(value: datetime) -> int:
    """Return an integral UTC timestamp while rejecting naive clock values."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("GitHub approval clock must be timezone-aware")
    return int(value.astimezone(UTC).timestamp())


def _load_json(path: Path) -> object:
    """Load one JSON object without silently accepting duplicate fields."""
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("fresh GitHub login marker is unreadable") from exc


def _environment(config_dir: Path) -> dict[str, str]:
    """Return a credential-clean environment bound to one isolated gh config."""
    if not config_dir.is_absolute() or not config_dir.is_dir():
        raise ValueError("GitHub config directory must be an existing absolute directory")
    if any(os.environ.get(name) for name in _TOKEN_ENVIRONMENT):
        raise ValueError("token environment variables are forbidden for human approval")
    result = os.environ.copy()
    for name in _TOKEN_ENVIRONMENT:
        result.pop(name, None)
    result["GH_CONFIG_DIR"] = str(config_dir)
    return result


def _run(command: list[str], *, env: dict[str, str], capture_output: bool) -> str:
    """Run gh without a shell and return stdout only when requested."""
    completed = subprocess.run(
        command, env=env, check=True, text=True, capture_output=capture_output,
    )
    return completed.stdout if capture_output else ""


def _active_account(config_dir: Path, runner: Callable[..., str]) -> str:
    """Ask the isolated GitHub CLI for the active account, never a token value."""
    account = runner(
        ["gh", "api", "user", "--jq", ".login"], env=_environment(config_dir), capture_output=True,
    ).strip()
    if not account:
        raise ValueError("fresh GitHub login did not identify an account")
    return account


def _marker_path(config_dir: Path) -> Path:
    """Return the one-time local proof path for the isolated CLI configuration."""
    return config_dir / MODEL_AUTH_MARKER


def begin_fresh_github_login(
    config_dir: Path, *, runner: Callable[..., str] = _run,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> str:
    """Start a human-operated device/web login and create its short-lived marker.

    The caller must be an operator-facing command. This function intentionally
    does not capture login output, so a transient GitHub user code is neither
    persisted nor returned to Phylax.
    """
    if not config_dir.is_absolute() or config_dir.exists():
        raise ValueError("fresh GitHub config directory must be a new absolute path")
    config_dir.mkdir(mode=0o700, parents=True)
    runner(
        ["gh", "auth", "login", "--web", "--hostname", "github.com", "--git-protocol", "https"],
        env=_environment(config_dir), capture_output=False,
    )
    account = _active_account(config_dir, runner)
    _marker_path(config_dir).write_text(
        json.dumps({"schema": 1, "account": account, "issued_at": _utc_timestamp(clock())}, sort_keys=True),
        encoding="utf-8",
    )
    os.chmod(_marker_path(config_dir), 0o600)
    return account


def approval_body(intent: ModelLaunchIntent, *, approved_duration_seconds: int = 5_400) -> str:
    """Render the exact operator comment bound to the complete model intent."""
    if approved_duration_seconds != 5_400:
        raise ValueError("human model approval duration must be the ratified default")
    payload = intent.preview_payload()
    return "\n".join((
        _SCHEMA,
        f"operator_principal: {intent.operator_principal}",
        f"task_id: {payload['task_id']}",
        f"request_digest: {intent.preview_digest()}",
        f"review_expires_at: {payload['review_expires_at']}",
        f"approved_duration_seconds: {approved_duration_seconds}",
    )) + "\n"


def _comment_reference(reference: str) -> tuple[str, int, int]:
    """Parse one immutable GitHub comment reference."""
    matched = _COMMENT_REFERENCE.fullmatch(reference)
    if matched is None:
        raise ValueError("model approval requires a GitHub issue or pull comment URL")
    issue, comment = int(matched.group(2)), int(matched.group(3))
    if issue < 1 or comment < 1:
        raise ValueError("model approval comment reference is invalid")
    return matched.group(1), issue, comment


def _created_at(value: object) -> datetime:
    """Parse GitHub's UTC comment creation time for freshness checks."""
    if not isinstance(value, str):
        raise ValueError("GitHub comment creation time is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("GitHub comment creation time is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("GitHub comment creation time is invalid")
    return parsed


@dataclass(frozen=True, slots=True)
class GitHubCliModelApprovalVerifier:
    """Verify fresh isolated-gh login plus an exact unedited operator comment."""

    config_dir: Path
    repository: str
    approvers: Mapping[str, str]
    runner: Callable[..., str] = _run
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def verify(self, intent: ModelLaunchIntent, evidence_ref: str) -> VerifiedModelApproval:
        """Spend fresh login evidence and translate an exact comment into P5 facts."""
        repository, _issue, comment_id = _comment_reference(evidence_ref)
        if repository != self.repository:
            raise ValueError("model approval comment targets another repository")
        now = self.clock()
        now_timestamp = _utc_timestamp(now)
        marker = _load_json(_marker_path(self.config_dir))
        if not isinstance(marker, dict) or marker.get("schema") != 1:
            raise ValueError("fresh GitHub login marker is invalid")
        issued_at = marker.get("issued_at")
        if (
            isinstance(issued_at, bool)
            or not isinstance(issued_at, int)
            or issued_at > now_timestamp
            or now_timestamp - issued_at > int(_FRESH_TTL.total_seconds())
        ):
            raise ValueError("fresh GitHub login marker is expired or invalid")
        account = _active_account(self.config_dir, self.runner)
        if marker.get("account") != account:
            raise ValueError("fresh GitHub login marker is expired or invalid")
        principal = self.approvers.get(account)
        if not isinstance(principal, str) or principal != intent.operator_principal:
            raise ValueError("GitHub account is not authorized for this model approval")

        # The fresh-login ceremony is one-use even if API readback fails.
        _marker_path(self.config_dir).unlink()
        raw = self.runner(
            ["gh", "api", f"repos/{repository}/issues/comments/{comment_id}"],
            env=_environment(self.config_dir), capture_output=True,
        )
        try:
            comment = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("GitHub comment readback is invalid") from exc
        if not isinstance(comment, dict):
            raise ValueError("GitHub comment readback is invalid")
        user = comment.get("user")
        if (
            comment.get("id") != comment_id
            or comment.get("html_url") != evidence_ref
            or not isinstance(user, dict)
            or user.get("login") != account
            or comment.get("body") != approval_body(intent)
            or comment.get("created_at") != comment.get("updated_at")
        ):
            raise ValueError("GitHub comment does not prove the exact human approval")
        approved_at = _created_at(comment.get("created_at"))
        approved_timestamp = _utc_timestamp(approved_at)
        if approved_timestamp < issued_at:
            raise ValueError("GitHub approval comment predates the fresh login")
        if approved_timestamp > now_timestamp:
            raise ValueError("GitHub approval comment is from the future")
        expires_at = min(
            approved_at + _FRESH_TTL,
            datetime.fromtimestamp(intent.preview_payload()["review_expires_at"], tz=UTC),
        )
        if _utc_timestamp(expires_at) <= now_timestamp:
            raise ValueError("GitHub approval comment is expired")
        return VerifiedModelApproval(
            approval_id=evidence_ref,
            operator_principal=principal,
            task_id=str(intent.preview_payload()["task_id"]),
            request_digest=intent.preview_digest(),
            approved_at=approved_at,
            expires_at=expires_at,
            evidence_ref=evidence_ref,
        )
