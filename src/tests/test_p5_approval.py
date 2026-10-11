"""Strict P5 approval tests: no boolean bypass, drift rejection, and one-time use."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from phylax.p5_approval import (
    InMemoryP5ApprovalStore,
    P5ApprovalAuthority,
    P5ApprovalIntent,
    SqliteP5ApprovalStore,
)


class Clock:
    """Mutable UTC clock used for deterministic expiry tests."""

    def __init__(self) -> None:
        """Start at a fixed instant."""
        self.now = datetime(2026, 10, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        """Return the current fixed instant."""
        return self.now


def intent() -> P5ApprovalIntent:
    """Return one immutable swarm-launch approval intent."""
    return P5ApprovalIntent.from_preview(
        "control-plane",
        {
            "objective": "verify a change",
            "task_type": "code-review",
            "optimize_for": "safety",
            "preferred_device": "shared",
            "assignments": [{"role": "reviewer"}, {"role": "verifier"}],
        },
    )


def authority(clock: Clock | None = None) -> P5ApprovalAuthority:
    """Return a strict authority with injected in-memory state."""
    return P5ApprovalAuthority(signing_key=b"test-p5-secret", store=InMemoryP5ApprovalStore(), clock=clock)


def approved(policy: P5ApprovalAuthority):
    """Issue then bind trusted operator evidence to one preview."""
    preview = policy.issue_preview(intent())
    return policy.approve(preview.preview_id, operator_evidence_ref="audit://operator/decision-1")


def test_p5_binds_immutable_intent_and_consumes_a_receipt_once() -> None:
    """A verified receipt returns its exact intent once and cannot replay."""
    policy = authority()
    receipt = approved(policy)

    decision = policy.consume(receipt, intent())

    assert decision.intent == intent()
    assert decision.operator_evidence_ref == "audit://operator/decision-1"
    assert decision.approved_duration_seconds == 5_400
    with pytest.raises(ValueError, match="already consumed"):
        policy.consume(receipt, intent())


def test_p5_rejects_payload_drift_even_with_a_valid_token() -> None:
    """A receipt for one preview cannot authorize changed swarm assignments."""
    policy = authority()
    receipt = approved(policy)

    with pytest.raises(ValueError, match="intent mismatch"):
        policy.consume(
            receipt,
            P5ApprovalIntent.from_preview(
                "control-plane",
                {**intent().preview_payload(), "assignments": [{"role": "different-reviewer"}]},
            ),
        )


def test_p5_rejects_tampered_token_without_consuming_the_valid_receipt() -> None:
    """Bad MAC text fails closed and leaves the valid receipt usable."""
    policy = authority()
    receipt = approved(policy)
    encoded_body, encoded_mac = receipt.approval_token.split(".", 1)
    replacement = "A" if encoded_mac[0] != "A" else "B"
    tampered = replace(receipt, approval_token=f"{encoded_body}.{replacement}{encoded_mac[1:]}")

    with pytest.raises(ValueError, match="invalid P5 approval token"):
        policy.consume(tampered, intent())
    assert policy.consume(receipt, intent()).intent == intent()


def test_p5_token_binds_preview_by_digest_without_exposing_raw_preview_or_evidence() -> None:
    """The signed receipt carries a digest, not assignments or evidence text."""
    import base64
    import json

    policy = authority()
    receipt = approved(policy)
    encoded_payload = receipt.approval_token.split(".", 1)[0]
    payload = json.loads(base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4)))

    assert payload["preview_digest"] == intent().preview_digest()
    assert "assignments" not in payload
    assert "operator_evidence_ref" not in payload


def test_p5_requires_operator_evidence_and_has_no_boolean_approval_path() -> None:
    """Approval requires opaque trusted evidence rather than a client approved flag."""
    policy = authority()
    preview = policy.issue_preview(intent())

    with pytest.raises(ValueError, match="operator_evidence_ref is required"):
        policy.approve(preview.preview_id, operator_evidence_ref="")


def test_p5_expiry_applies_before_approval_and_before_consumption() -> None:
    """Expired previews cannot be approved or consumed."""
    clock = Clock()
    policy = authority(clock)
    preview = policy.issue_preview(intent())
    clock.now += timedelta(minutes=5)

    with pytest.raises(ValueError, match="expired"):
        policy.approve(preview.preview_id, operator_evidence_ref="audit://operator/decision-1")

    clock = Clock()
    policy = authority(clock)
    receipt = approved(policy)
    clock.now += timedelta(minutes=5)
    with pytest.raises(ValueError, match="expired"):
        policy.consume(receipt, intent())


def test_p5_duration_is_p5_output_with_ratified_bounds() -> None:
    """The authority defaults the human duration and rejects values over its ceiling."""
    policy = authority()
    preview = policy.issue_preview(intent())
    receipt = policy.approve(
        preview.preview_id,
        operator_evidence_ref="audit://operator/decision-1",
        approved_duration_seconds=9_900,
    )
    assert receipt.approved_duration_seconds == 9_900

    preview = policy.issue_preview(
        P5ApprovalIntent.from_preview(
            "control-plane",
            {**intent().preview_payload(), "assignments": [{"role": "reviewer-2"}]},
        )
    )
    with pytest.raises(ValueError, match="issuance ceiling"):
        policy.approve(
            preview.preview_id,
            operator_evidence_ref="audit://operator/decision-2",
            approved_duration_seconds=9_901,
        )


def test_p5_requires_a_secret_and_rejects_invalid_intent_fields() -> None:
    """Missing cryptographic material and incomplete swarm scope are fail-closed."""
    with pytest.raises(ValueError, match="signing_key is required"):
        P5ApprovalAuthority(signing_key=b"", store=InMemoryP5ApprovalStore())
    with pytest.raises(ValueError, match="fields are incomplete"):
        P5ApprovalIntent.from_preview("control-plane", {**intent().preview_payload(), "objective": ""})


def test_sqlite_store_survives_reopen_and_rejects_replay(tmp_path: Path) -> None:
    """Durable storage preserves a consumed receipt across a new authority instance."""
    database = tmp_path / "p5.db"
    first = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database)))
    receipt = approved(first)

    reloaded = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database)))
    assert reloaded.consume(receipt, intent()).intent == intent()

    after_consume = P5ApprovalAuthority(
        signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database))
    )
    with pytest.raises(ValueError, match="already consumed"):
        after_consume.consume(receipt, intent())


def test_sqlite_store_allows_exactly_one_concurrent_consumer(tmp_path: Path) -> None:
    """Independent authorities cannot both consume one durable approval."""
    database = tmp_path / "p5-race.db"
    issuer = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database)))
    receipt = approved(issuer)

    def consume_once() -> bool:
        policy = P5ApprovalAuthority(
            signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database))
        )
        try:
            policy.consume(receipt, intent())
        except ValueError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: consume_once(), range(2)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1
