"""Signed public revocation state, durable feed and combined lookup (decision D3)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.bindings import crypto_sign_seed_keypair

from phylax import dispatch_wire as wire
from phylax.dispatch_permit_store import SqliteDispatchPermitStore
from phylax.dispatch_retention import RetainedEventFeed, RetentionLedger
from phylax.revocation_publication import (
    SEGMENT_SIZE,
    CombinedRevocationLookup,
    DirectoryMedium,
    FeedPublisher,
    PublicationRefused,
    build_state,
    sign_state_body,
    verify_state,
    verify_state_against_chain,
)

NOW = datetime(2026, 11, 2, 4, 0, 0, tzinfo=UTC)
SEED = b"1" * 32
ISSUER = "issuer-1"
VECTORS = json.loads((Path(__file__).parents[2] / "docs/vectors/revocation-lookup-v1.json").read_text())


class Signer:
    """Event and state signer over a fixed seed."""

    def active_key_id(self) -> str:
        """Return the key id."""
        return "key-1"

    def sign_permit(self, key_id: str, body: dict) -> str:
        """Sign a permit body."""
        return wire.sign_permit(SEED, body)

    def sign_finalization(self, key_id: str, body: dict) -> str:
        """Sign a finalization body."""
        return wire.sign_finalization(SEED, body)

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign an event digest."""
        return wire.sign_event(SEED, digest)

    def sign_state(self, key_id: str, body: dict) -> str:
        """Sign a state body."""
        return sign_state_body(SEED, body)


class Resolver:
    """Resolve the single test key."""

    def public_key(self, key_id: str) -> bytes | None:
        """Return the key or None."""
        return crypto_sign_seed_keypair(SEED)[0] if key_id == "key-1" else None


@pytest.fixture
def parts(tmp_path: Path):
    """Return (store, ledger, feed, signer)."""
    store = SqliteDispatchPermitStore(tmp_path / "p.db")
    ledger = RetentionLedger(tmp_path / "r.db")
    return store, ledger, RetainedEventFeed(store, ledger), Signer()


def load(store, signer, revoked, cascades) -> int:
    """Append the vector's revocations and cascades; return the head version."""
    for kind, subject in revoked:
        store.append_revocation(kind, subject, signer=signer)
    for index, (approval, grants) in enumerate(cascades, start=1):
        store.append_cascade(approval, sorted(grants), index, signer=signer)
    return store.current_counter()


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_lookup_matches_the_shared_truth_table(parts, case) -> None:
    """Every vector row is reproduced by the state built from a real chain."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, case["revoked"], case["cascades"])
    raw = build_state(feed, issuer_id=VECTORS["issuer_id"], head_version=head, signer=signer, now=NOW)
    state = verify_state(raw, resolver=Resolver(), issuer_id=VECTORS["issuer_id"], now=NOW)
    assert CombinedRevocationLookup(state).reason(case["grant"], case["approval_ref"]) == case["expect"]


def test_state_signature_freshness_and_binding(parts) -> None:
    """A forged, stale, future-dated, wrong-issuer or tampered state is refused."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1")], [])
    raw = build_state(feed, issuer_id=ISSUER, head_version=head, signer=signer, now=NOW)
    verify_state(raw, resolver=Resolver(), issuer_id=ISSUER, now=NOW + timedelta(seconds=60))

    def refused(code: str, data: bytes, **kw) -> None:
        with pytest.raises(PublicationRefused) as caught:
            verify_state(data, **{"resolver": Resolver(), "issuer_id": ISSUER, "now": NOW, **kw})
        assert caught.value.code == code

    refused("publication.stale", raw, now=NOW + timedelta(seconds=61))
    refused("publication.stale", raw, now=NOW - timedelta(seconds=10))
    refused("publication.issuer_mismatch", raw, issuer_id="issuer-2")
    document = json.loads(raw)
    document["body"]["revoked_grants"] = []
    refused("publication.signature", wire.canonical_bytes(document))
    document = json.loads(raw)
    document["issuer_key_id"] = "key-9"
    refused("publication.unknown_key", wire.canonical_bytes(document))
    refused("publication.malformed", raw + b" ")
    refused("publication.malformed", b"nope")
    document = json.loads(raw)
    document["body"]["extra"] = 1
    refused("publication.malformed", wire.canonical_bytes(document))
    document = json.loads(raw)
    document["body"]["revoked_grants"] = ["b", "a"]
    refused("publication.malformed", wire.canonical_bytes(document))


def test_state_head_is_cross_checked_against_the_chain(parts) -> None:
    """The state names a head; a chain that disagrees with it is refused."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1"), ("grant", "g2")], [])
    raw = build_state(feed, issuer_id=ISSUER, head_version=head, signer=signer, now=NOW)
    state = verify_state(raw, resolver=Resolver(), issuer_id=ISSUER, now=NOW)
    events = feed.events(1, head)
    verify_state_against_chain(state, events, resolver=Resolver())
    with pytest.raises(PublicationRefused) as short:
        verify_state_against_chain(state, events[:1], resolver=Resolver())
    assert short.value.code == "publication.head_mismatch"
    empty = verify_state(
        build_state(feed, issuer_id=ISSUER, head_version=0, signer=signer, now=NOW),
        resolver=Resolver(), issuer_id=ISSUER, now=NOW,
    )
    verify_state_against_chain(empty, [], resolver=Resolver())
    with pytest.raises(PublicationRefused):
        verify_state_against_chain(empty, events, resolver=Resolver())


def test_publish_writes_segments_then_state_and_reads_back(parts, tmp_path) -> None:
    """Publishing 70 events makes two segments plus the state; the feed verifies from genesis."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", f"g-{i:03d}") for i in range(SEGMENT_SIZE + 6)], [])
    medium = DirectoryMedium(tmp_path / "public")
    publisher = FeedPublisher(feed, medium, Resolver(), issuer_id=ISSUER, signer=signer, clock=lambda: NOW)
    raw = publisher.publish(head)
    assert medium.get("state.json") == raw
    assert medium.get(publisher.segment_name(1, SEGMENT_SIZE)) is not None
    assert len(publisher.read_feed(head)) == head
    state = verify_state(raw, resolver=Resolver(), issuer_id=ISSUER, now=NOW)
    verify_state_against_chain(state, publisher.read_feed(head), resolver=Resolver())
    assert publisher.publish(head)  # idempotent segments, replaced state


def test_unreadable_medium_is_unavailable_never_empty_success(parts, tmp_path) -> None:
    """A medium that drops, corrupts or fails reads fails the publication closed."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1")], [])

    class Dropping(DirectoryMedium):
        def get(self, name: str):
            return None

    class Corrupting(DirectoryMedium):
        def get(self, name: str):
            data = super().get(name)
            return None if data is None else data[:-1] + b"X"

    class Failing(DirectoryMedium):
        def put(self, name: str, data: bytes) -> None:
            raise OSError("disk full")

    for medium, code in (
        (Dropping(tmp_path / "a"), "publication.unavailable"),
        (Corrupting(tmp_path / "b"), "publication.readback_mismatch"),
        (Failing(tmp_path / "c"), "publication.unavailable"),
    ):
        publisher = FeedPublisher(feed, medium, Resolver(), issuer_id=ISSUER, signer=signer, clock=lambda: NOW)
        with pytest.raises(PublicationRefused) as caught:
            publisher.publish(head)
        assert caught.value.code == code


def test_read_feed_detects_missing_tampered_and_misnamed_segments(parts, tmp_path) -> None:
    """A reader refuses a missing segment, a body swap and a segment under the wrong name."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1"), ("grant", "g2")], [])
    medium = DirectoryMedium(tmp_path / "public")
    publisher = FeedPublisher(feed, medium, Resolver(), issuer_id=ISSUER, signer=signer, clock=lambda: NOW)
    publisher.publish(head)
    name = publisher.segment_name(1, head)
    good = medium.get(name)
    (medium.root / name).unlink()
    with pytest.raises(PublicationRefused) as missing:
        publisher.read_feed(head)
    assert missing.value.code == "publication.unavailable"
    segment = json.loads(good)
    segment["events"][0]["body"]["subject_id"] = "evil"
    (medium.root / name).write_bytes(wire.canonical_bytes(segment))
    with pytest.raises(PublicationRefused) as tampered:
        publisher.read_feed(head)
    assert tampered.value.code == "publication.malformed"
    segment = json.loads(good)
    segment["events"][0]["signature"] = wire.sign_event(b"9" * 32, segment["events"][0]["event_digest"])
    (medium.root / name).write_bytes(wire.canonical_bytes(segment))
    with pytest.raises(PublicationRefused) as forged:
        publisher.read_feed(head)
    assert forged.value.code == "publication.signature"
    (medium.root / name).write_bytes(good.replace(b'"from_version":1', b'"from_version":2'))
    with pytest.raises(PublicationRefused) as renamed:
        publisher.read_feed(head)
    assert renamed.value.code == "publication.malformed"


def test_medium_protects_immutable_names(tmp_path) -> None:
    """Segment names cannot be rewritten with different bytes; the state name can."""
    medium = DirectoryMedium(tmp_path / "m")
    medium.put("events-1.json", b"a")
    medium.put("events-1.json", b"a")
    with pytest.raises(FileExistsError):
        medium.put("events-1.json", b"b")
    medium.put("state.json", b"1")
    medium.put("state.json", b"2")
    assert medium.get("state.json") == b"2" and medium.get("missing") is None
    for bad in ("../x", ".hidden", "a/b"):
        with pytest.raises(ValueError):
            medium.put(bad, b"x")
        assert medium.get(bad) is None


def test_state_survives_pruning(parts) -> None:
    """The state replays through the stitched feed, so history already archived still counts."""
    import sqlite3

    store, ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1")] + [("grant", f"x{i}") for i in range(5)], [])
    ledger.append_archive(feed.events(1, 3), now=NOW)  # what a verified prune leaves behind
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM issuer_events WHERE version < 4")
    raw = build_state(feed, issuer_id=ISSUER, head_version=head, signer=signer, now=NOW)
    state = verify_state(raw, resolver=Resolver(), issuer_id=ISSUER, now=NOW)
    assert CombinedRevocationLookup(state).reason("g1", "") == "grant_revoked"


def test_refusal_vocabulary_is_closed() -> None:
    """Unknown publication codes are rejected."""
    with pytest.raises(ValueError):
        PublicationRefused("publication.invented")
