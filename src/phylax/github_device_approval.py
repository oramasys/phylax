"""GitHub CLI evidence for a human-approved model launch.

GitHub CLI owns the OAuth device flow. This adapter deliberately neither creates
a GitHub OAuth client nor receives a device code or access token. A human runs
``begin_fresh_github_login`` in a fresh isolated CLI configuration, posts an
exact launch-confirmation comment, and supplies that comment URL to Phylax.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import re
import subprocess
from typing import Callable, Mapping

from .model_launch_approval import ModelLaunchIntent, VerifiedModelApproval

_TOKEN_ENVIRONMENT = (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
    "GITHUB_COPILOT_PAT",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
)
_HOST_ENVIRONMENT = ("GH_HOST", "GITHUB_HOST", "GH_REPO")
_GITHUB_HOST = "github.com"
_GH_TIMEOUT_SECONDS = 20.0
_COMMENT_REFERENCE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:issues|pull)/(\d+)#issuecomment-(\d+)$"
)
_SCHEMA = "oramasys-model-launch-approval: v1"
_FRESH_TTL = timedelta(seconds=300)
MODEL_AUTH_MARKER = "model-launch-fresh-auth.v1.json"
_SPENT_MARKER_SUFFIX = ".spent"


@dataclass(frozen=True, slots=True)
class _GitHubAccount:
    """Stable GitHub identity plus a login retained only for diagnostics."""

    user_id: int
    login: str


def _utc_timestamp(value: datetime) -> int:
    """Return an integral UTC timestamp while rejecting naive clock values."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("GitHub approval clock must be timezone-aware")
    return int(value.astimezone(UTC).timestamp())


def _load_json(path: Path) -> object:
    """Load a private regular marker without accepting duplicate fields."""
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, encoding="utf-8") as marker:
            metadata = os.fstat(marker.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise ValueError("fresh GitHub login marker has unsafe permissions")
            return json.loads(marker.read(), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("fresh GitHub login marker is unreadable") from exc


def _environment(config_dir: Path) -> dict[str, str]:
    """Return a credential-clean environment bound to one isolated gh config."""
    if not config_dir.is_absolute():
        raise ValueError("GitHub config directory must be a private absolute directory")
    try:
        metadata = config_dir.lstat()
    except OSError as exc:
        raise ValueError("GitHub config directory must be an existing absolute directory") from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
        raise ValueError("GitHub config directory must be a private absolute directory")
    if any(os.environ.get(name) for name in _TOKEN_ENVIRONMENT):
        raise ValueError("token environment variables are forbidden for human approval")
    result = os.environ.copy()
    for name in (*_TOKEN_ENVIRONMENT, *_HOST_ENVIRONMENT):
        result.pop(name, None)
    result["GH_CONFIG_DIR"] = str(config_dir)
    result["GH_HOST"] = _GITHUB_HOST
    return result


def _run(
    command: list[str], *, env: dict[str, str], capture_output: bool,
    timeout: float = _GH_TIMEOUT_SECONDS,
) -> str:
    """Run gh without a shell and return stdout only when requested."""
    try:
        completed = subprocess.run(
            command, env=env, check=True, text=True, capture_output=capture_output,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        raise ValueError("GitHub CLI invocation failed") from exc
    return completed.stdout if capture_output else ""


def _invoke(
    runner: Callable[..., str], command: list[str], *, env: dict[str, str], capture_output: bool,
) -> str:
    """Normalize every GitHub CLI failure to the verifier's public error type."""
    try:
        return runner(command, env=env, capture_output=capture_output, timeout=_GH_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        raise ValueError("GitHub CLI invocation failed") from exc


def _active_account(config_dir: Path, runner: Callable[..., str]) -> _GitHubAccount:
    """Ask the isolated GitHub CLI for stable numeric account identity."""
    raw = _invoke(
        runner,
        ["gh", "api", "--hostname", _GITHUB_HOST, "user"],
        env=_environment(config_dir),
        capture_output=True,
    )
    try:
        account = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("fresh GitHub login did not identify an account") from exc
    if not isinstance(account, dict):
        raise ValueError("fresh GitHub login did not identify an account")
    login, user_id = account.get("login"), account.get("id")
    if (
        not isinstance(login, str)
        or not login
        or isinstance(user_id, bool)
        or not isinstance(user_id, int)
        or user_id < 1
    ):
        raise ValueError("fresh GitHub login did not identify an account")
    return _GitHubAccount(user_id=user_id, login=login)


def _marker_path(config_dir: Path) -> Path:
    """Return the one-time local proof path for the isolated CLI configuration."""
    return config_dir / MODEL_AUTH_MARKER


def _spent_marker_path(config_dir: Path) -> Path:
    """Return the exclusive claim record that makes a marker single-use."""
    marker = _marker_path(config_dir)
    return marker.with_name(f"{marker.name}{_SPENT_MARKER_SUFFIX}")


def _write_marker(config_dir: Path, *, account: str, issued_at: int) -> None:
    """Create the one-time marker privately without following a preexisting path."""
    contents = json.dumps({"schema": 1, "account": account, "issued_at": issued_at}, sort_keys=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_marker_path(config_dir), flags, 0o600)
    except OSError as exc:
        raise ValueError("fresh GitHub login marker could not be created") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as marker:
        marker.write(contents)


def _spend_marker(config_dir: Path) -> None:
    """Atomically claim and remove a marker before remote evidence readback."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_spent_marker_path(config_dir), flags, 0o600)
    except FileExistsError as exc:
        raise ValueError("fresh GitHub login marker is already spent") from exc
    except OSError as exc:
        raise ValueError("fresh GitHub login marker could not be spent") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as spent:
        spent.write("spent\n")
    try:
        _marker_path(config_dir).unlink()
    except OSError as exc:
        raise ValueError("fresh GitHub login marker could not be spent") from exc


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
    _invoke(
        runner,
        ["gh", "auth", "login", "--web", "--hostname", "github.com", "--git-protocol", "https"],
        env=_environment(config_dir), capture_output=False,
    )
    account = _active_account(config_dir, runner)
    _write_marker(config_dir, account=account.login, issued_at=_utc_timestamp(clock()))
    return account.login


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
    approvers: Mapping[int, str]
    runner: Callable[..., str] = _run
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def verify(self, intent: ModelLaunchIntent, evidence_ref: str) -> VerifiedModelApproval:
        """Spend fresh login evidence and translate an exact comment into P5 facts."""
        repository, _issue, comment_id = _comment_reference(evidence_ref)
        if repository != self.repository:
            raise ValueError("model approval comment targets another repository")
        _environment(self.config_dir)
        now = self.clock()
        now_timestamp = _utc_timestamp(now)
        if _spent_marker_path(self.config_dir).exists():
            raise ValueError("fresh GitHub login marker is already spent")
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
        if marker.get("account") != account.login:
            raise ValueError("fresh GitHub login marker is expired or invalid")
        principal = self.approvers.get(account.user_id)
        if not isinstance(principal, str) or principal != intent.operator_principal:
            raise ValueError("GitHub account is not authorized for this model approval")

        # The fresh-login ceremony is one-use even if API readback fails.
        _spend_marker(self.config_dir)
        raw = _invoke(
            self.runner,
            ["gh", "api", "--hostname", _GITHUB_HOST, f"repos/{repository}/issues/comments/{comment_id}"],
            env=_environment(self.config_dir),
            capture_output=True,
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
            or user.get("id") != account.user_id
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
