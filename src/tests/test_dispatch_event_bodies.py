"""E1 C2 Part 3 Sections 1-2: signed revocation and cascade event bodies (issuer side).

Every expected digest comes from ``oracle_digest`` below, which uses only ``hashlib`` and ``json``
and imports nothing from Phylax, so the wire module is checked against an independent reading of
the specification and not against itself.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from nacl.bindings import crypto_sign_seed_keypair

from phylax import dispatch_permit_store as store_module
from phylax import dispatch_wire as wire
from phylax.dispatch_permit_store import SqliteDispatchPermitStore

sys.path.insert(0, str(Path(__file__).parent))
import dispatch_event_vector_builder as builder  # noqa: E402  (helper beside this file)

VECTORS = json.loads(builder.VECTOR_PATH.read_text(encoding="utf-8"))
SEED = hashlib.sha256(b"phylax-event-body-test-key-1").digest()
PUBLIC_KEY = crypto_sign_seed_keypair(SEED)[0]
KEY_ID = "event-body-test-key-1"
GENESIS = "0" * 64

ORACLE_DIGESTS = (
    "8bae016107341fde2b9d9241b1b450b66791018f913a0c62299de8e2bba1302f",
    "d6f41cebbb64a45186ccc4c0bcd1e0dd66ed37f0e0c1689cdcc7cf4856538aed",
    "36469ce85187f112ed8c0953a0ec9ecae7a1ed99075b82aeed7029d6cb90e466",
    "c32f896b4e5c05a24ba137ccde6f2fdd923feaf516d03fd0baee8a0ea09b0858",
)
FROZEN_REFUSAL_CODES = frozenset({
    "permit.conflict", "permit.attempt_aborted", "permit.grant_mismatch", "permit.grant_revoked",
    "permit.grant_expired", "permit.issuer_rolled_back", "permit.invalid_request",
    "finalization.conflict", "finalization.catchup_required", "finalization.permit_unusable",
    "finalization.grant_revoked", "finalization.issuer_rolled_back", "finalization.key_rotated",
    "finalization.invalid_request",
})
BAD_IDENTIFIERS: tuple[object, ...] = (
    "", " ", " a", "a ", "a b", "a\tb", "a\nb", "a\x00b", "a\x7fb", "grant-é", "x" * 1025,
    7, None, True, b"grant", ["grant"],
)
GOOD_IDENTIFIERS = ("a", "~", "urn:uuid:6f1c0a52-2f1e-4bb0-9c3a-0d6b9d6f3a10", "x" * 1024)


def oracle_digest(version: int, kind: str, body: dict[str, Any], previous: str) -> str:
    """Digest an event with the standard library only (the independent specification oracle)."""
    wrapper = {"body": body, "kind": kind, "previous_event_digest": previous, "version": version}
    canonical = json.dumps(
        wrapper, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Signer:
    """Issuer signer port with a fixed test seed; it holds no consumer state."""

    def active_key_id(self) -> str:
        """Return the fixed test key id."""
        return KEY_ID

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign an event digest."""
        assert key_id == KEY_ID
        return wire.sign_event(SEED, digest)


@pytest.fixture
def store(tmp_path: Path) -> SqliteDispatchPermitStore:
    """Return a fresh durable issuer store."""
    return SqliteDispatchPermitStore(tmp_path / "issuer.db")


def revocation(kind: str = "grant", subject: object = "grant-1") -> dict[str, object]:
    """Build a revocation body."""
    return {"subject_kind": kind, "subject_id": subject}


def cascade(
    approval: object = "approval-1", grants: object = ("grant-1", "grant-2"), version: object = 1
) -> dict[str, object]:
    """Build a cascade body."""
    return {
        "approval_id": approval,
        "grant_ids": list(grants) if isinstance(grants, tuple) else grants,
        "issuer_authority_version": version,
    }


def refused(kind: str, body: object) -> None:
    """Assert the wire module refuses the body for its kind as malformed."""
    with pytest.raises(wire.WireError):
        wire.event_digest(1, kind, body, GENESIS)  # type: ignore[arg-type]


def test_revocation_body_is_closed() -> None:
    """Section 1: exactly subject_kind and subject_id, nothing missing, extra or null."""
    wire.event_digest(1, "revocation", revocation(), GENESIS)
    refused("revocation", {"subject_kind": "grant"})
    refused("revocation", {"subject_id": "grant-1"})
    refused("revocation", {**revocation(), "disposition_ref": "x"})
    refused("revocation", {**revocation(), "revocation_epoch": 1})
    refused("revocation", {"subject_kind": None, "subject_id": "grant-1"})
    refused("revocation", {})


@pytest.mark.parametrize("kind", ["grant", "approval", "issuer"])
def test_every_closed_subject_kind_is_accepted(kind: str) -> None:
    """Section 1: each of the three kinds is a valid revocation."""
    wire.event_digest(1, "revocation", revocation(kind), GENESIS)


@pytest.mark.parametrize(
    "bad", ["Grant", "GRANT", "grants", "approvals", "issuers", "", " grant", "grant ", "any", None, 1]
)
def test_revocation_subject_kind_vocabulary_is_closed(bad: object) -> None:
    """Section 1: any other subject_kind is malformed, with no case folding or trimming."""
    refused("revocation", revocation(bad))  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", BAD_IDENTIFIERS)
def test_identifier_must_be_canonical(bad: object) -> None:
    """Locked rule 2: subject_id, approval_id and each grant_ids element must be canonical."""
    refused("revocation", revocation("grant", bad))
    refused("cascade", cascade(approval=bad))
    refused("cascade", cascade(grants=["grant-1", bad]))


@pytest.mark.parametrize("good", GOOD_IDENTIFIERS)
def test_canonical_identifiers_are_accepted(good: str) -> None:
    """Locked rule 2: printable ASCII without space, 1 to 1024 bytes, is accepted unchanged."""
    wire.event_digest(1, "revocation", revocation("grant", good), GENESIS)
    wire.event_digest(1, "cascade", cascade(approval=good, grants=[good]), GENESIS)


def test_cascade_body_is_closed() -> None:
    """Section 2: exactly approval_id, grant_ids and issuer_authority_version."""
    wire.event_digest(1, "cascade", cascade(), GENESIS)
    for missing in ("approval_id", "grant_ids", "issuer_authority_version"):
        refused("cascade", {k: v for k, v in cascade().items() if k != missing})
    refused("cascade", {**cascade(), "executed": True})
    refused("cascade", {**cascade(), "consumer_state": "dispatched"})
    refused("cascade", {**cascade(), "approval_id": None})
    refused("cascade", {})


@pytest.mark.parametrize(
    "grants",
    [
        ["grant-2", "grant-1"],
        ["grant-1", "grant-1"],
        ["grant-1", "grant-2", "grant-2"],
        ["grant-1", "grant-3", "grant-2"],
        "grant-1",
        {"grant-1": 1},
        None,
        7,
    ],
)
def test_cascade_grant_ids_must_be_strictly_ascending(grants: object) -> None:
    """Locked rule 3: a duplicate, an unsorted pair or a non-array is malformed."""
    refused("cascade", cascade(grants=grants))


def test_cascade_grant_ids_must_be_a_json_array_not_a_tuple() -> None:
    """Locked rule 3: only an array is a valid ``grant_ids``; a tuple is not a JSON array."""
    refused("cascade", {**cascade(), "grant_ids": ("grant-1",)})


def test_append_cascade_refuses_a_bare_string_not_a_list_of_characters(
    store: SqliteDispatchPermitStore,
) -> None:
    """A string must never be split into one-character grant ids, even when they sort cleanly."""
    with pytest.raises(wire.WireError):
        store.append_cascade("approval-1", "abc", 1, signer=Signer())  # type: ignore[arg-type]
    assert store.current_counter() == 0


def test_cascade_grant_ids_accept_empty_and_single() -> None:
    """Locked rule 3: an empty array and a single id are valid; order is by code point."""
    wire.event_digest(1, "cascade", cascade(grants=[]), GENESIS)
    wire.event_digest(1, "cascade", cascade(grants=["grant-1"]), GENESIS)
    wire.event_digest(1, "cascade", cascade(grants=["A", "a", "b"]), GENESIS)
    refused("cascade", cascade(grants=["a", "A"]))


@pytest.mark.parametrize("bad", [0, -1, 2**53, 2**63, True, False, "1", 1.0, None, [1]])
def test_cascade_authority_version_is_a_positive_safe_integer(bad: object) -> None:
    """Locked rule 3: issuer_authority_version is an integer from 1 to 2^53 - 1."""
    refused("cascade", cascade(version=bad))


@pytest.mark.parametrize("good", [1, 2, 2**53 - 1])
def test_cascade_authority_version_bounds_are_accepted(good: int) -> None:
    """Locked rule 3: both ends of the safe positive range are valid."""
    wire.event_digest(1, "cascade", cascade(version=good), GENESIS)


def _grants(count: int, width: int = 1020) -> list[str]:
    """Return ``count`` strictly ascending identifiers of ``width + 4`` bytes each."""
    return [f"{i:04d}" + "x" * width for i in range(count)]


def test_event_wire_size_is_bounded(store: SqliteDispatchPermitStore) -> None:
    """Locked rule 4: the complete canonical event is at most 65,536 bytes, checked before writing."""
    assert wire.MAX_WIRE_BYTES == 65_536
    signer = Signer()
    fits = store.append_cascade("approval-1", _grants(60), 1, signer=signer)
    assert len(wire.canonical_bytes(fits)) <= wire.MAX_WIRE_BYTES

    with pytest.raises(wire.WireError):
        store.append_cascade("approval-1", _grants(64), 1, signer=signer)

    assert store.current_counter() == 1


def test_event_wire_size_boundary_is_exact() -> None:
    """An event of exactly 65,536 canonical bytes passes and one byte more is refused."""
    base = {
        "version": 1, "kind": "revocation", "body": {"subject_kind": "grant", "subject_id": "g"},
        "previous_event_digest": GENESIS, "event_digest": GENESIS, "issuer_key_id": "",
        "signature": "A" * 86,
    }
    pad = wire.MAX_WIRE_BYTES - len(wire.canonical_bytes(base))
    wire.check_event_wire_size({**base, "issuer_key_id": "k" * pad})
    with pytest.raises(wire.WireError):
        wire.check_event_wire_size({**base, "issuer_key_id": "k" * (pad + 1)})


def test_event_digest_still_refuses_unknown_kinds_and_keeps_finalization_exact() -> None:
    """The existing kind, version and finalization rules are unchanged by the new bodies."""
    refused("other", {"x": 1})
    refused("finalization", {"finalization_id": "f1", "extra": 1})
    wire.event_digest(1, "finalization", {"finalization_id": "f1"}, GENESIS)


def test_canonical_event_vectors_match_the_independent_oracle() -> None:
    """The wire digests for the four slice vectors equal the standard-library oracle."""
    bodies = (
        ("revocation", revocation("grant", "grant-vector-0001")),
        ("revocation", revocation("approval", "approval-vector-0001")),
        ("cascade", cascade("approval-vector-0001", ["grant-vector-0002", "grant-vector-0003"], 1)),
        ("revocation", revocation("issuer", "issuer-vector-0001")),
    )
    previous = GENESIS
    for version, ((kind, body), expected) in enumerate(zip(bodies, ORACLE_DIGESTS), start=1):
        assert oracle_digest(version, kind, body, previous) == expected
        assert wire.event_digest(version, kind, body, previous) == expected
        previous = expected


def test_append_signs_chains_and_persists_each_kind(store: SqliteDispatchPermitStore) -> None:
    """Valid revocation and cascade events append as one signed, chained, verifiable sequence."""
    signer = Signer()
    first = store.append_revocation("grant", "grant-vector-0001", signer=signer)
    second = store.append_revocation("approval", "approval-vector-0001", signer=signer)
    third = store.append_cascade(
        "approval-vector-0001", ["grant-vector-0002", "grant-vector-0003"], 1, signer=signer
    )
    fourth = store.append_revocation("issuer", "issuer-vector-0001", signer=signer)

    stored = store.events(1, 4)
    assert stored == [first, second, third, fourth]
    previous = GENESIS
    for event, expected in zip(stored, ORACLE_DIGESTS):
        assert event["event_digest"] == expected
        assert event["previous_event_digest"] == previous
        assert event["issuer_key_id"] == KEY_ID
        assert wire.verify_event(PUBLIC_KEY, expected, str(event["signature"]))
        previous = expected
    assert [e["kind"] for e in stored] == ["revocation", "revocation", "cascade", "revocation"]
    assert store.current_counter() == 4


@pytest.mark.parametrize(
    "call",
    [
        lambda s, g: s.append_revocation("grants", "grant-1", signer=g),
        lambda s, g: s.append_revocation("grant", " ", signer=g),
        lambda s, g: s.append_cascade("approval-1", ["b", "a"], 1, signer=g),
        lambda s, g: s.append_cascade("approval-1", ["a", "a"], 1, signer=g),
        lambda s, g: s.append_cascade("approval-1", ["a"], 0, signer=g),
    ],
)
def test_refused_body_consumes_no_version(store: SqliteDispatchPermitStore, call: Any) -> None:
    """Locked rule 5 and matrix row 8: a malformed body writes no row and uses no version."""
    signer = Signer()
    store.append_revocation("grant", "grant-1", signer=signer)
    before = store.events(1, 10)

    with pytest.raises(wire.WireError):
        call(store, signer)

    assert store.events(1, 10) == before
    assert store.current_counter() == 1


def test_identical_revocation_is_idempotent(store: SqliteDispatchPermitStore) -> None:
    """Locked rule 5: recording an identical revocation returns the existing event, appends none."""
    signer = Signer()
    first = store.append_revocation("grant", "grant-1", signer=signer)
    again = store.append_revocation("grant", "grant-1", signer=signer)
    other_kind = store.append_revocation("approval", "grant-1", signer=signer)
    other_subject = store.append_revocation("grant", "grant-2", signer=signer)

    assert again == first
    assert store.current_counter() == 3
    assert other_kind["version"] == 2 and other_subject["version"] == 3


def test_cascade_is_always_a_new_commit(store: SqliteDispatchPermitStore) -> None:
    """Section 2: each cascade is its own commit at its own version."""
    signer = Signer()
    one = store.append_cascade("approval-1", ["grant-1"], 1, signer=signer)
    two = store.append_cascade("approval-1", ["grant-1"], 1, signer=signer)

    assert (one["version"], two["version"]) == (1, 2)
    assert one["event_digest"] != two["event_digest"]


def test_append_api_takes_no_consumer_state() -> None:
    """Locked rule 5: the issuer's append methods accept no consumer execution input."""
    revoke = inspect.signature(SqliteDispatchPermitStore.append_revocation)
    cascade_sig = inspect.signature(SqliteDispatchPermitStore.append_cascade)

    assert list(revoke.parameters) == ["self", "subject_kind", "subject_id", "signer"]
    assert list(cascade_sig.parameters) == [
        "self", "approval_id", "grant_ids", "issuer_authority_version", "signer",
    ]


def test_append_does_not_mutate_the_callers_grant_list(store: SqliteDispatchPermitStore) -> None:
    """The stored body copies the list; later changes to the caller's list cannot alter history."""
    grants = ["grant-1", "grant-2"]
    event = store.append_cascade("approval-1", grants, 1, signer=Signer())
    grants.append("grant-3")

    assert store.events(1, 1)[0]["body"]["grant_ids"] == ["grant-1", "grant-2"]  # type: ignore[index]
    assert event["body"]["grant_ids"] == ["grant-1", "grant-2"]  # type: ignore[index]


def test_refusal_vocabulary_is_unchanged() -> None:
    """Locked rule 8: no shared wire refusal code was added or removed."""
    assert wire.REFUSAL_CODES == FROZEN_REFUSAL_CODES
    assert store_module.PermitRefused("permit.conflict").code == "permit.conflict"
    with pytest.raises(ValueError):
        store_module.PermitRefused("event.malformed_body")


def test_committed_event_vectors_equal_the_builder_output() -> None:
    """The committed vector file is exactly what the wire module produces, so they cannot drift."""
    assert builder.VECTOR_PATH.read_text(encoding="utf-8") == builder.render()


def test_event_vectors_chain_verify_and_equal_the_oracle() -> None:
    """The signed vector chain matches the oracle digests and verifies under the vector key."""
    public_key = bytes.fromhex(VECTORS["public_key"])
    previous = GENESIS
    for event, expected in zip(VECTORS["events"], ORACLE_DIGESTS, strict=True):
        assert event["event_digest"] == expected
        assert event["event_digest"] == oracle_digest(
            event["version"], event["kind"], event["body"], previous
        )
        assert event["previous_event_digest"] == previous
        assert wire.verify_event(public_key, expected, event["signature"])
        assert set(event) == set(wire.EVENT_WIRE_FIELDS)
        previous = expected
    assert VECTORS["canonical_bodies"] == [
        wire.canonical_bytes(event["body"]).decode("utf-8") for event in VECTORS["events"]
    ]


@pytest.mark.parametrize("case", VECTORS["malformed"], ids=lambda case: case["name"])
def test_every_malformed_vector_is_refused(case: dict[str, Any]) -> None:
    """Each shared malformed body is refused by the issuer wire module (the consumer runs the same set)."""
    refused(case["kind"], case["body"])


def test_no_malformed_vector_is_also_a_valid_body() -> None:
    """The malformed set has unique names and never contains one of the valid vector bodies."""
    names = [case["name"] for case in VECTORS["malformed"]]
    valid = [event["body"] for event in VECTORS["events"]]
    assert len(names) == len(set(names))
    assert all(case["body"] not in valid for case in VECTORS["malformed"])
