"""Effect-grant v2 issuance and verification contract."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


def test_effect_grant_is_domain_separated_bound_and_revocable(tmp_path: Path) -> None:
    """Only the verified v2 effect projection crosses into a consumer."""
    from phylax.adjustment_grant import RotatingIssuerKeyring
    from phylax.effect_grant import (
        EffectGrantAuthority,
        EffectGrantRefusal,
        EffectGrantRefusalReason,
        EffectGrantRequest,
    )
    from phylax.grant_store import SqliteGrantAuthorityStore
    from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority

    class Seeds:
        def load_seed(self, seed_ref: str) -> bytes:
            assert seed_ref == "seed-1"
            return b"e" * 32

    now = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    store = SqliteGrantAuthorityStore(tmp_path / "grants.sqlite3")
    keyring = RotatingIssuerKeyring(
        key_id="issuer-1", seed_ref="seed-1", seed_provider=Seeds(), store=store
    )
    authority = EffectGrantAuthority(
        keyring=keyring,
        p5_approval=P5ApprovalAuthority(
            signing_key=b"p5-test-secret", store=InMemoryP5ApprovalStore(), clock=lambda: now
        ),
        clock=lambda: now,
    )
    request = EffectGrantRequest(
        principal="principal-1", run_id="run-1", operation_id="operation-1",
        request_digest="a" * 64, effect_class="inert.simulation", ledger_store_id="ledger-1",
        consumer_lease_epoch=3, second_approval_ref="approval-1", issuer_ref="phylax-1",
        revocation_ref="phylax://revocations/v1",
    )

    grant = authority.issue(
        request, authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1"
    )
    verified = authority.verify(grant.to_wire())
    assert (verified.grant_id, verified.second_approval_ref, verified.use_limit) == (
        grant.grant_id, "approval-1", 1
    )
    assert verified.expires_at - verified.issued_at == timedelta(seconds=5_400)

    authority.revoke(grant.grant_id)
    with pytest.raises(EffectGrantRefusal) as refusal:
        authority.verify(grant.to_wire())
    assert refusal.value.reason is EffectGrantRefusalReason.GRANT_REVOKED
