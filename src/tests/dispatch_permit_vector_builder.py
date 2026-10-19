"""Deterministic builder for ``docs/vectors/dispatch-permit-v1.json``.

Run ``PYTHONPATH=src python3 src/tests/dispatch_permit_vector_builder.py`` to regenerate the file; the
test suite fails if the committed file differs from this output, so the vectors and the wire
module cannot drift apart.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from nacl.bindings import crypto_sign_seed_keypair

from phylax import dispatch_wire as wire

VECTOR_PATH = Path(__file__).resolve().parents[2] / "docs" / "vectors" / "dispatch-permit-v1.json"
SEED = hashlib.sha256(b"phylax-dispatch-permit-vector-key-1").digest()
KEY_ID = "phylax-vector-key-1"
DIGEST_A, DIGEST_B, DIGEST_C = "a" * 64, "b" * 64, "c" * 64


def build_vectors() -> dict[str, object]:
    """Build every positive vector from fixed inputs and the fixed vector signing seed."""
    public_key, _ = crypto_sign_seed_keypair(SEED)

    prior_digest = wire.finalization_event_digest(1, "fin-vector-prior", wire.GENESIS_EVENT_DIGEST)
    final_digest = wire.finalization_event_digest(2, "fin-vector-0001", prior_digest)
    events = []
    for version, fid, previous, digest in (
        (1, "fin-vector-prior", wire.GENESIS_EVENT_DIGEST, prior_digest),
        (2, "fin-vector-0001", prior_digest, final_digest),
    ):
        events.append({
            "body": {"finalization_id": fid}, "event_digest": digest, "issuer_key_id": KEY_ID,
            "kind": "finalization", "previous_event_digest": previous,
            "signature": wire.sign_event(SEED, digest), "version": version,
        })

    request = {
        "grant_id": "grant-vector-0001", "grant_payload_digest": DIGEST_A,
        "operation_id": "op-vector-0001", "request_digest": DIGEST_B, "artifact_digest": DIGEST_C,
        "reservation_id": "res-vector-0001", "ledger_store_id": "vector-ledger",
        "configuration_policy_epoch": 3, "authority_epoch": 5, "consumer_acked_through": 1,
        "attempt_id": "attempt-vector-0001", "requested_at": "2026-10-19T04:00:00.000000Z",
    }
    permit_body = {
        "schema_version": 1, **request, "permit_id": "permit-vector-0001", "revocation_version": 1,
        "issuer_authority_version": 1, "issued_at": "2026-10-19T04:00:01.000000Z",
        "expires_at": "2026-10-19T04:01:31.000000Z", "issuer_key_id": KEY_ID,
    }
    permit_signature = wire.sign_permit(SEED, permit_body)
    permit_digest = wire.permit_payload_digest(permit_body)

    fin_request = {
        "permit_id": "permit-vector-0001", "permit_digest": permit_digest,
        "attempt_id": "attempt-vector-0001", "reservation_id": "res-vector-0001",
        "ledger_store_id": "vector-ledger", "consumer_acked_through": 1, "authority_epoch": 5,
        "requested_at": "2026-10-19T04:00:30.000000Z",
    }
    fin_body = {
        "schema_version": 1, **fin_request, "finalization_id": "fin-vector-0001",
        "revocation_version": 2, "revocation_event_digest": final_digest,
        "issued_at": "2026-10-19T04:00:31.000000Z", "expires_at": "2026-10-19T04:01:31.000000Z",
    }
    fin_signature = wire.sign_finalization(SEED, fin_body)

    return {
        "schema": "phylax.dispatch-permit.conformance.v1",
        "issuer_key_id": KEY_ID,
        "public_key": public_key.hex(),
        "genesis_event_digest": wire.GENESIS_EVENT_DIGEST,
        "permit_request": request,
        "permit": {
            "body": permit_body, "body_bytes": wire.permit_body_bytes(permit_body).decode("utf-8"),
            "payload_digest": permit_digest, "signature": permit_signature,
            "wire": wire.permit_wire_bytes(permit_body, permit_signature).decode("utf-8"),
        },
        "finalization_request": fin_request,
        "finalization": {
            "body": fin_body, "body_bytes": wire.finalization_body_bytes(fin_body).decode("utf-8"),
            "finalization_digest": wire.finalization_digest(fin_body), "signature": fin_signature,
            "wire": wire.finalization_wire_bytes(fin_body, fin_signature).decode("utf-8"),
        },
        "events": events,
        "event_preimage_example": wire.canonical_bytes({
            "body": {"finalization_id": "fin-vector-0001"}, "kind": "finalization",
            "previous_event_digest": prior_digest, "version": 2,
        }).decode("utf-8"),
    }


def render() -> str:
    """Return the exact committed text of the vector file."""
    return json.dumps(build_vectors(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    VECTOR_PATH.write_text(render(), encoding="utf-8")
