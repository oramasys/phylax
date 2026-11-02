"""Effect-issuance approval through the GitHub device ceremony (D1=A, D2)."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from phylax.adjustment_grant import RotatingIssuerKeyring
from phylax.effect_grant import EffectGrantAuthority, EffectGrantRequest
from phylax.github_device_approval import MODEL_AUTH_MARKER
from phylax.github_effect_approval import (
    ASSURANCE,
    GitHubCliEffectApprovalVerifier,
    effect_approval_body,
    effect_request_digest,
    issue_with_github_approval,
)
from phylax.grant_store import SqliteGrantAuthorityStore
from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority

NOW = datetime(2026, 10, 23, tzinfo=UTC)
EXPIRES = int(NOW.timestamp()) + 300
EVIDENCE = "https://github.com/acme/control/issues/7#issuecomment-17"


@pytest.fixture(autouse=True)
def no_ambient_github_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the ceremony independent of workstation token exports."""
    for name in (
        "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_COPILOT_PAT",
        "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST", "GITHUB_HOST", "GH_REPO",
        "GH_PROMPT_DISABLED", "GH_NO_UPDATE_NOTIFIER", "GH_DEBUG", "GH_PAGER", "PAGER",
        "CLICOLOR_FORCE", "NO_COLOR",
    ):
        monkeypatch.delenv(name, raising=False)


class Seeds:
    """Deterministic issuer seed."""

    def load_seed(self, seed_ref: str) -> bytes:
        """Return the fixture seed."""
        return b"e" * 32


class Runner:
    """Queue harmless CLI output."""

    def __init__(self, responses: list[str]) -> None:
        """Queue responses in call order."""
        self._responses = iter(responses)
        self.calls = 0

    def __call__(self, command, *, env, capture_output, timeout) -> str:
        """Return the next response."""
        self.calls += 1
        return next(self._responses)


def request(**overrides: object) -> EffectGrantRequest:
    """Return a valid effect request for the ceremony principal."""
    base = {
        "principal": "control-plane", "run_id": "run-1", "operation_id": "operation-1",
        "request_digest": "a" * 64, "effect_class": "inert.simulation", "ledger_store_id": "ledger-1",
        "consumer_lease_epoch": 3, "second_approval_ref": "", "issuer_ref": "phylax-1",
        "revocation_ref": "phylax://revocations/v1",
    }
    return EffectGrantRequest(**{**base, **overrides})


def comment(body: str, *, user_id: int = 7, updated: str = "2026-10-23T00:00:00Z") -> str:
    """Return a GitHub comment response."""
    return json.dumps({
        "id": 17, "html_url": EVIDENCE, "user": {"login": "operator", "id": user_id}, "body": body,
        "created_at": "2026-10-23T00:00:00Z", "updated_at": updated,
    })


@pytest.fixture
def parts(tmp_path: Path):
    """Return (authority, config_dir, fake gh path, store)."""
    store = SqliteGrantAuthorityStore(tmp_path / "grants.sqlite3")
    keyring = RotatingIssuerKeyring(key_id="issuer-1", seed_ref="seed-1", seed_provider=Seeds(), store=store)
    authority = EffectGrantAuthority(
        keyring=keyring,
        p5_approval=P5ApprovalAuthority(signing_key=b"p5", store=InMemoryP5ApprovalStore(), clock=lambda: NOW),
        clock=lambda: NOW,
    )
    config = tmp_path / "isolated"
    config.mkdir(mode=0o700)
    marker = config / MODEL_AUTH_MARKER
    marker.write_text(json.dumps({
        "schema": 1, "account": "operator", "account_id": 7, "issued_at": int(NOW.timestamp()),
    }), encoding="utf-8")
    marker.chmod(0o600)
    gh = tmp_path / "gh"
    gh.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    gh.chmod(0o700)
    return authority, config, gh, store


def build_verifier(config: Path, gh: Path, responses: list[str]):
    """Create a real verifier around the fake CLI seam."""
    runner = Runner(responses)
    return GitHubCliEffectApprovalVerifier(
        config_dir=config, repository="acme/control", approvers={7: "control-plane"},
        runner=runner, gh_executable=gh, clock=lambda: NOW,
    ), runner


ACCOUNT = json.dumps({"login": "operator", "id": 7})


def issued_count(store) -> int:
    """Count durable issued grants."""
    with closing(sqlite3.connect(store.path)) as db:
        return db.execute("SELECT COUNT(*) FROM issued_grants").fetchone()[0]


def test_exact_comment_issues_one_grant_and_states_its_assurance(parts) -> None:
    """A fresh login plus the exact comment issues a verifiable grant with procedural assurance."""
    authority, config, gh, store = parts
    req = request()
    verifier, _runner = build_verifier(config, gh, [ACCOUNT, comment(effect_approval_body(req, review_expires_at=EXPIRES))])
    grant = issue_with_github_approval(
        authority, verifier, req, authenticated_principal="control-plane",
        evidence_ref=EVIDENCE, review_expires_at=EXPIRES,
    )
    assert authority.verify(grant.to_wire()).grant_id == grant.grant_id
    assert issued_count(store) == 1
    body = effect_approval_body(req, review_expires_at=EXPIRES)
    assert "not an independently attested MFA claim" in body and ASSURANCE in body


def test_evidence_declares_it_is_not_mfa(parts) -> None:
    """The verified evidence object carries the assurance class and mfa_attested=False."""
    _authority, config, gh, _store = parts
    req = request()
    verifier, _ = build_verifier(config, gh, [ACCOUNT, comment(effect_approval_body(req, review_expires_at=EXPIRES))])
    evidence = verifier.verify(req, EVIDENCE, review_expires_at=EXPIRES)
    assert (evidence.assurance, evidence.mfa_attested) == (ASSURANCE, False)
    assert evidence.request_digest == effect_request_digest(req)


@pytest.mark.parametrize("field,value", [
    ("run_id", "run-2"), ("operation_id", "operation-2"), ("request_digest", "b" * 64),
    ("effect_class", "inert.other"), ("ledger_store_id", "ledger-2"), ("consumer_lease_epoch", 4),
    ("issuer_ref", "phylax-2"), ("revocation_ref", "phylax://revocations/v2"),
])
def test_comment_binds_every_request_field(parts, field, value) -> None:
    """A comment approving one request never authorizes a request differing in any field."""
    authority, config, gh, store = parts
    approved = request()
    other = replace(approved, **{field: value})
    verifier, _ = build_verifier(config, gh, [ACCOUNT, comment(effect_approval_body(approved, review_expires_at=EXPIRES))])
    with pytest.raises(ValueError):
        issue_with_github_approval(
            authority, verifier, other, authenticated_principal="control-plane",
            evidence_ref=EVIDENCE, review_expires_at=EXPIRES,
        )
    assert issued_count(store) == 0


def test_unqualified_class_never_issues(parts) -> None:
    """An unqualified effect class creates no grant even with a valid ceremony."""
    authority, config, gh, store = parts
    req = request(effect_class="shell.execute")
    verifier, _ = build_verifier(config, gh, [ACCOUNT, comment(effect_approval_body(req, review_expires_at=EXPIRES))])
    with pytest.raises(ValueError, match="not qualified"):
        issue_with_github_approval(
            authority, verifier, req, authenticated_principal="control-plane",
            evidence_ref=EVIDENCE, review_expires_at=EXPIRES,
        )
    assert issued_count(store) == 0


def test_changed_review_deadline_never_issues(parts) -> None:
    """A comment approving one review deadline does not authorize another."""
    authority, config, gh, store = parts
    req = request()
    verifier, runner = build_verifier(
        config, gh, [ACCOUNT, comment(effect_approval_body(req, review_expires_at=EXPIRES + 60))]
    )
    with pytest.raises(ValueError, match="does not prove the exact human approval"):
        issue_with_github_approval(
            authority, verifier, req, authenticated_principal="control-plane",
            evidence_ref=EVIDENCE, review_expires_at=EXPIRES,
        )
    assert issued_count(store) == 0 and runner.calls == 2


def test_authenticated_principal_mismatch_refuses_before_any_cli_call(parts) -> None:
    """A caller authenticated as someone else is refused before the ceremony is spent."""
    authority, config, gh, _store = parts
    req = request()
    verifier, runner = build_verifier(config, gh, [])
    with pytest.raises(ValueError, match="authenticated principal"):
        issue_with_github_approval(
            authority, verifier, req, authenticated_principal="someone-else",
            evidence_ref=EVIDENCE, review_expires_at=EXPIRES,
        )
    with pytest.raises(ValueError, match="requires human evidence"):
        issue_with_github_approval(
            authority, verifier, req, authenticated_principal="control-plane",
            evidence_ref="  ", review_expires_at=EXPIRES,
        )
    assert runner.calls == 0 and (config / MODEL_AUTH_MARKER).exists()


@pytest.mark.parametrize("user_id,updated", [(8, "2026-10-23T00:00:00Z"), (7, "2026-10-23T00:00:09Z")])
def test_other_author_or_edited_comment_issues_nothing_and_spends_the_login(parts, user_id, updated) -> None:
    """A different author or an edited comment issues nothing; the fresh login is still consumed."""
    authority, config, gh, store = parts
    req = request()
    verifier, _ = build_verifier(
        config, gh, [ACCOUNT, comment(effect_approval_body(req, review_expires_at=EXPIRES), user_id=user_id, updated=updated)]
    )
    with pytest.raises(ValueError):
        issue_with_github_approval(
            authority, verifier, req, authenticated_principal="control-plane",
            evidence_ref=EVIDENCE, review_expires_at=EXPIRES,
        )
    assert issued_count(store) == 0 and not (config / MODEL_AUTH_MARKER).exists()


def test_login_is_single_use_across_two_issuances(parts) -> None:
    """The fresh login funds exactly one issuance; reuse is refused."""
    authority, config, gh, store = parts
    req = request()
    body = comment(effect_approval_body(req, review_expires_at=EXPIRES))
    verifier, _ = build_verifier(config, gh, [ACCOUNT, body, ACCOUNT, body])
    issue_with_github_approval(
        authority, verifier, req, authenticated_principal="control-plane",
        evidence_ref=EVIDENCE, review_expires_at=EXPIRES,
    )
    with pytest.raises(ValueError):
        issue_with_github_approval(
            authority, verifier, req, authenticated_principal="control-plane",
            evidence_ref=EVIDENCE, review_expires_at=EXPIRES,
        )
    assert issued_count(store) == 1


def test_body_requires_a_real_deadline() -> None:
    """The deadline is part of the signed-by-human text and must be a real epoch second."""
    for bad in (0, -1, True, "5"):
        with pytest.raises(ValueError):
            effect_approval_body(request(), review_expires_at=bad)
