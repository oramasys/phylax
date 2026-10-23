"""Deterministic builder for ``docs/vectors/dispatch-events-v1.json`` (Part 3 Sections 1-2).

Run ``PYTHONPATH=src python3 src/tests/dispatch_event_vector_builder.py`` to regenerate the file;
the test suite fails if the committed file differs from this output. Oramasys vendors the file
byte-for-byte and records its SHA-256, so both repositories test the same signed events and the
same malformed bodies.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from nacl.bindings import crypto_sign_seed_keypair

from phylax import dispatch_wire as wire

VECTOR_PATH = Path(__file__).resolve().parents[2] / "docs" / "vectors" / "dispatch-events-v1.json"
SEED = hashlib.sha256(b"phylax-dispatch-event-vector-key-1").digest()
KEY_ID = "phylax-event-vector-key-1"

GOOD_BODIES: tuple[tuple[str, dict[str, object]], ...] = (
    ("revocation", {"subject_kind": "grant", "subject_id": "grant-vector-0001"}),
    ("revocation", {"subject_kind": "approval", "subject_id": "approval-vector-0001"}),
    ("cascade", {
        "approval_id": "approval-vector-0001",
        "grant_ids": ["grant-vector-0002", "grant-vector-0003"],
        "issuer_authority_version": 1,
    }),
    ("revocation", {"subject_kind": "issuer", "subject_id": "issuer-vector-0001"}),
)


def _revocation(**overrides: object) -> dict[str, object]:
    """Return a valid revocation body with ``overrides`` applied."""
    return {"subject_kind": "grant", "subject_id": "grant-1", **overrides}


def _cascade(**overrides: object) -> dict[str, object]:
    """Return a valid cascade body with ``overrides`` applied."""
    return {
        "approval_id": "approval-1", "grant_ids": ["grant-1", "grant-2"],
        "issuer_authority_version": 1, **overrides,
    }


def malformed_cases() -> list[dict[str, object]]:
    """Return every malformed body that both the issuer and the consumer must refuse."""
    cases: list[tuple[str, str, object]] = [
        ("revocation extra field", "revocation", {**_revocation(), "disposition_ref": "x"}),
        ("revocation missing subject_id", "revocation", {"subject_kind": "grant"}),
        ("revocation missing subject_kind", "revocation", {"subject_id": "grant-1"}),
        ("revocation null subject_id", "revocation", _revocation(subject_id=None)),
        ("revocation unknown kind", "revocation", _revocation(subject_kind="approvals")),
        ("revocation wrong-case kind", "revocation", _revocation(subject_kind="Grant")),
        ("revocation empty body", "revocation", {}),
        ("revocation blank id", "revocation", _revocation(subject_id="")),
        ("revocation whitespace id", "revocation", _revocation(subject_id=" ")),
        ("revocation padded id", "revocation", _revocation(subject_id=" grant-1")),
        ("revocation inner space id", "revocation", _revocation(subject_id="grant 1")),
        ("revocation non-ascii id", "revocation", _revocation(subject_id="grant-é")),
        ("revocation control id", "revocation", _revocation(subject_id="grant\u00001")),
        ("revocation overlong id", "revocation", _revocation(subject_id="x" * 1025)),
        ("revocation numeric id", "revocation", _revocation(subject_id=7)),
        ("cascade extra field", "cascade", {**_cascade(), "executed": True}),
        ("cascade missing approval_id", "cascade", {
            "grant_ids": [], "issuer_authority_version": 1}),
        ("cascade missing grant_ids", "cascade", {
            "approval_id": "approval-1", "issuer_authority_version": 1}),
        ("cascade missing version", "cascade", {"approval_id": "approval-1", "grant_ids": []}),
        ("cascade blank approval", "cascade", _cascade(approval_id="")),
        ("cascade null approval", "cascade", _cascade(approval_id=None)),
        ("cascade grant_ids string", "cascade", _cascade(grant_ids="grant-1")),
        ("cascade grant_ids null", "cascade", _cascade(grant_ids=None)),
        ("cascade grant_ids object", "cascade", _cascade(grant_ids={"grant-1": 1})),
        ("cascade non-string element", "cascade", _cascade(grant_ids=["grant-1", 2])),
        ("cascade blank element", "cascade", _cascade(grant_ids=["grant-1", ""])),
        ("cascade unsorted", "cascade", _cascade(grant_ids=["grant-2", "grant-1"])),
        ("cascade duplicate", "cascade", _cascade(grant_ids=["grant-1", "grant-1"])),
        ("cascade duplicate tail", "cascade", _cascade(grant_ids=["a", "b", "b"])),
        ("cascade case order", "cascade", _cascade(grant_ids=["a", "A"])),
        ("cascade version zero", "cascade", _cascade(issuer_authority_version=0)),
        ("cascade version negative", "cascade", _cascade(issuer_authority_version=-1)),
        ("cascade version boolean", "cascade", _cascade(issuer_authority_version=True)),
        ("cascade version unsafe", "cascade", _cascade(issuer_authority_version=2**53)),
        ("cascade version string", "cascade", _cascade(issuer_authority_version="1")),
        ("cascade version float", "cascade", _cascade(issuer_authority_version=1.5)),
    ]
    return [{"name": name, "kind": kind, "body": body} for name, kind, body in cases]


def build_vectors() -> dict[str, object]:
    """Build the signed event chain and the malformed set from fixed inputs."""
    public_key, _ = crypto_sign_seed_keypair(SEED)
    events: list[dict[str, object]] = []
    previous = wire.GENESIS_EVENT_DIGEST
    for version, (kind, body) in enumerate(GOOD_BODIES, start=1):
        digest = wire.event_digest(version, kind, body, previous)
        events.append({
            "body": body, "event_digest": digest, "issuer_key_id": KEY_ID, "kind": kind,
            "previous_event_digest": previous, "signature": wire.sign_event(SEED, digest),
            "version": version,
        })
        previous = digest
    return {
        "schema": "phylax.issuer-event-bodies.conformance.v1",
        "issuer_key_id": KEY_ID,
        "public_key": public_key.hex(),
        "genesis_event_digest": wire.GENESIS_EVENT_DIGEST,
        "events": events,
        "canonical_bodies": [wire.canonical_bytes(body).decode("utf-8") for _, body in GOOD_BODIES],
        "malformed": malformed_cases(),
    }


def render() -> str:
    """Return the exact committed text of the vector file."""
    return json.dumps(build_vectors(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    VECTOR_PATH.write_text(render(), encoding="utf-8")
