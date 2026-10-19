"""Conformance tests for the frozen E1 C2 dispatch wire encoding and its committed vectors."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

from phylax import dispatch_wire as wire

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dispatch_permit_vector_builder as builder  # noqa: E402  (helper beside this file)

VECTORS = json.loads(builder.VECTOR_PATH.read_text(encoding="utf-8"))
PUBLIC_KEY = bytes.fromhex(VECTORS["public_key"])


def test_committed_vectors_equal_the_builder_output() -> None:
    """The committed file is exactly what the wire module produces, so they cannot drift."""
    assert builder.VECTOR_PATH.read_text(encoding="utf-8") == builder.render()


def test_frozen_field_counts() -> None:
    """The ratified spec fixes 12, 21, 8 and 15 fields."""
    assert len(wire.PERMIT_REQUEST_FIELDS) == 12
    assert len(wire.PERMIT_WIRE_FIELDS) == 21
    assert len(wire.FINALIZATION_REQUEST_FIELDS) == 8
    assert len(wire.FINALIZATION_WIRE_FIELDS) == 15


def test_permit_vector_digest_signature_and_wire() -> None:
    """Digest is SHA-256 of the canonical body; the signature verifies; the wire has 21 fields."""
    permit = VECTORS["permit"]
    body = permit["body"]
    assert hashlib.sha256(permit["body_bytes"].encode("utf-8")).hexdigest() == permit["payload_digest"]
    assert wire.verify_permit(PUBLIC_KEY, body, permit["signature"])
    assert len(json.loads(permit["wire"])) == 21


def test_finalization_vector_signature_digest_and_wire() -> None:
    """The finalization signature verifies, has 15 wire fields, and binds the permit digest."""
    fin = VECTORS["finalization"]
    assert wire.verify_finalization(PUBLIC_KEY, fin["body"], fin["signature"])
    assert len(json.loads(fin["wire"])) == 15
    assert fin["body"]["permit_digest"] == VECTORS["permit"]["payload_digest"]
    assert fin["finalization_digest"] == hashlib.sha256(fin["body_bytes"].encode("utf-8")).hexdigest()


def test_event_chain_links_signs_and_matches_the_finalization() -> None:
    """Each event digest commits to the previous one; the last equals the finalization's digest."""
    previous = wire.GENESIS_EVENT_DIGEST
    for event in VECTORS["events"]:
        digest = wire.event_digest(event["version"], event["kind"], event["body"], previous)
        assert digest == event["event_digest"]
        assert event["previous_event_digest"] == previous
        assert wire.verify_event(PUBLIC_KEY, digest, event["signature"])
        previous = digest
    fin = VECTORS["finalization"]["body"]
    assert fin["revocation_event_digest"] == previous
    assert fin["revocation_version"] == VECTORS["events"][-1]["version"]
    assert json.loads(VECTORS["event_preimage_example"])["version"] == fin["revocation_version"]


def test_binding_digest_covers_exactly_the_nine_fields() -> None:
    """The retry-identity digest ignores requested_at, the acknowledgement and attempt_id."""
    request = copy.deepcopy(VECTORS["permit_request"])
    assert wire.binding_digest(request) == VECTORS["binding_digest"]
    for ignored in ("requested_at", "consumer_acked_through", "attempt_id"):
        changed = {**request, ignored: "x" if ignored != "consumer_acked_through" else 9}
        assert wire.binding_digest(changed) == VECTORS["binding_digest"]
    assert wire.binding_digest({**request, "reservation_id": "res-other"}) != VECTORS["binding_digest"]
    assert len(wire.BINDING_FIELDS) == 9


def test_refusal_vocabulary_is_closed_and_disjoint() -> None:
    """Permit and finalization refusal codes are separate, namespaced and never overlap abort outcomes."""
    assert all(code.startswith("permit.") for code in wire.PERMIT_REFUSAL_CODES)
    assert all(code.startswith("finalization.") for code in wire.FINALIZATION_REFUSAL_CODES)
    assert not wire.REFUSAL_CODES & wire.ABORT_OUTCOMES


def test_epochs_must_be_positive_like_the_merged_consumer_helper() -> None:
    """Zero epochs are refused, matching the consumer helper's minimum of 1."""
    wire_obj = json.loads(VECTORS["permit"]["wire"])
    for name in ("configuration_policy_epoch", "authority_epoch", "issuer_authority_version"):
        with pytest.raises(wire.WireError):
            wire.validate_fields({**wire_obj, name: 0}, wire.PERMIT_WIRE_FIELDS)
    wire.validate_fields({**wire_obj, "consumer_acked_through": 0}, wire.PERMIT_WIRE_FIELDS)


def test_finalization_id_alone_is_never_the_preimage() -> None:
    """Hashing the bare identifier gives a different digest from the canonical wrapper object."""
    last = VECTORS["events"][-1]
    assert hashlib.sha256(last["body"]["finalization_id"].encode("utf-8")).hexdigest() != last["event_digest"]


def test_domain_separation_between_permit_finalization_and_event() -> None:
    """A signature made under one domain never verifies under another."""
    body = VECTORS["permit"]["body"]
    signature = wire.b64url_decode(VECTORS["permit"]["signature"])
    assert wire._verify(PUBLIC_KEY, signature, wire.PERMIT_DOMAIN, wire.permit_body_bytes(body))
    assert not wire._verify(PUBLIC_KEY, signature, wire.FINALIZATION_DOMAIN, wire.permit_body_bytes(body))
    assert not wire._verify(PUBLIC_KEY, signature, wire.EVENT_DOMAIN, wire.permit_body_bytes(body))


def test_a_tampered_field_breaks_digest_and_signature() -> None:
    """Changing any bound field changes the digest and invalidates the signature."""
    body = copy.deepcopy(VECTORS["permit"]["body"])
    body["attempt_id"] = "attempt-vector-9999"
    assert wire.permit_payload_digest(body) != VECTORS["permit"]["payload_digest"]
    assert not wire.verify_permit(PUBLIC_KEY, body, VECTORS["permit"]["signature"])


def _permit_wire() -> dict[str, object]:
    """Return a fresh copy of the vector permit wire for mutation."""
    return json.loads(VECTORS["permit"]["wire"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda w: w.update(extra_field="x"),
        lambda w: w.pop("attempt_id"),
        lambda w: w.update(attempt_id=None),
        lambda w: w.update(authority_epoch=True),
        lambda w: w.update(authority_epoch=5.0),
        lambda w: w.update(authority_epoch=-1),
        lambda w: w.update(authority_epoch=2**53),
        lambda w: w.update(request_digest="B" * 64),
        lambda w: w.update(request_digest="b" * 63),
        lambda w: w.update(issuer_signature=w["issuer_signature"] + "="),
        lambda w: w.update(issued_at="2026-10-19T04:00:01Z"),
        lambda w: w.update(issued_at="2026-10-19T04:00:01.000000+00:00"),
        lambda w: w.update(schema_version=2),
        lambda w: w.update(grant_id=""),
        lambda w: w.update(grant_id="g" * 1025),
    ],
)
def test_malformed_permit_wire_is_refused(mutate) -> None:
    """Extra, missing, null, boolean, float, out-of-range, padded or mis-formed values are refused."""
    mutated = _permit_wire()
    mutate(mutated)
    with pytest.raises(wire.WireError):
        wire.validate_fields(mutated, wire.PERMIT_WIRE_FIELDS)


def test_non_canonical_serialization_is_not_the_signed_form() -> None:
    """Whitespace or reordered keys produce different bytes, so only one form can be signed."""
    body = VECTORS["permit"]["body"]
    spaced = json.dumps(body, sort_keys=True).encode("utf-8")
    assert spaced != wire.permit_body_bytes(body)
    assert wire.canonical_bytes(dict(reversed(list(body.items())))) == wire.permit_body_bytes(body)


def test_event_digest_refuses_unknown_kind_bad_version_and_bad_previous() -> None:
    """Event preimage inputs are strictly validated."""
    ok = {"finalization_id": "f"}
    with pytest.raises(wire.WireError):
        wire.event_digest(1, "mystery", ok, wire.GENESIS_EVENT_DIGEST)
    with pytest.raises(wire.WireError):
        wire.event_digest(0, "finalization", ok, wire.GENESIS_EVENT_DIGEST)
    with pytest.raises(wire.WireError):
        wire.event_digest(1, "finalization", ok, "Z" * 64)
    with pytest.raises(wire.WireError):
        wire.event_digest(1, "finalization", {"finalization_id": "f", "grant_id": "g"}, wire.GENESIS_EVENT_DIGEST)


def test_wire_size_limit_is_enforced() -> None:
    """A permit larger than 65,536 bytes is refused."""
    body = copy.deepcopy(VECTORS["permit"]["body"])
    original = wire.MAX_WIRE_BYTES
    try:
        wire.MAX_WIRE_BYTES = 100  # type: ignore[misc]
        with pytest.raises(wire.WireError):
            wire.permit_wire_bytes(body, VECTORS["permit"]["signature"])
    finally:
        wire.MAX_WIRE_BYTES = original  # type: ignore[misc]
