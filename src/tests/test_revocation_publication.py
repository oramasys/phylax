"""Signed public revocation state, durable feed and combined lookup (decision D3)."""
from __future__ import annotations

import json
import os
import stat
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.bindings import crypto_sign_seed_keypair

from phylax import dispatch_wire as wire
from phylax import revocation_publication as publication
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


@pytest.mark.parametrize("bad_genesis", [False, True])
def test_state_chain_requires_exact_genesis_boundary(parts, bad_genesis) -> None:
    """A signed summary cannot relabel version 2 as head 1 or invent a genesis digest."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1")], [])
    document = json.loads(build_state(feed, issuer_id=ISSUER, head_version=head,
                                     signer=signer, now=NOW))
    if bad_genesis:
        events = []
        document["body"].update(head_version=0, revoked_grants=[],
                                head_event_digest=wire.GENESIS_EVENT_DIGEST)
    else:
        event = feed.events(1, head)[0]
        event["version"] = 2
        event["event_digest"] = wire.event_digest(
            2, event["kind"], event["body"], event["previous_event_digest"])
        event["signature"] = wire.sign_event(SEED, event["event_digest"])
        events = [event]
        document["body"]["head_event_digest"] = event["event_digest"]
    document["signature"] = sign_state_body(SEED, document["body"])
    state = verify_state(wire.canonical_bytes(document), resolver=Resolver(),
                         issuer_id=ISSUER, now=NOW)
    if bad_genesis:
        state = replace(state, head_event_digest="a" * 64)
    with pytest.raises(PublicationRefused, match="publication.head_mismatch"):
        verify_state_against_chain(state, events, resolver=Resolver())


@pytest.mark.parametrize("overrides", [
    {"schema_version": True}, {"schema_version": 1.0},
    {"head_version": wire.MAX_SAFE_INTEGER + 1, "head_event_digest": "a" * 64},
    {"head_version": 0, "head_event_digest": "a" * 64},
    {"head_version": 1, "head_event_digest": wire.GENESIS_EVENT_DIGEST},
])
def test_state_rejects_noninteger_schema_unsafe_head_and_inconsistent_genesis(parts, overrides) -> None:
    """Signature validity cannot relax the closed wire's integer and genesis constraints."""
    _store, _ledger, feed, signer = parts
    document = json.loads(build_state(feed, issuer_id=ISSUER, head_version=0,
                                     signer=signer, now=NOW))
    document["body"].update(overrides)
    document["signature"] = sign_state_body(SEED, document["body"])
    with pytest.raises(PublicationRefused, match="publication.malformed"):
        verify_state(wire.canonical_bytes(document), resolver=Resolver(), issuer_id=ISSUER, now=NOW)


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
    assert CombinedRevocationLookup(state, clock=lambda: NOW).reason(case["grant"], case["approval_ref"]) == case["expect"]


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
    assert CombinedRevocationLookup(state, clock=lambda: NOW).reason("g1", "") == "grant_revoked"


def test_refusal_vocabulary_is_closed() -> None:
    """Unknown publication codes are rejected."""
    with pytest.raises(ValueError):
        PublicationRefused("publication.invented")


def _publisher(parts, tmp_path: Path):
    """Return (publisher, medium, head) for a two-event feed."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1"), ("grant", "g2")], [])
    medium = DirectoryMedium(tmp_path / "public")
    return FeedPublisher(feed, medium, Resolver(), issuer_id=ISSUER, signer=signer, clock=lambda: NOW), medium, head


def test_concurrent_writers_never_mix_bytes_and_keep_the_name_immutable(tmp_path: Path) -> None:
    """Racing writers of one immutable name: exactly one payload wins, the rest are refused or equal."""
    medium = DirectoryMedium(tmp_path / "public")
    payloads = [bytes([65 + i]) * 4096 for i in range(12)]
    outcomes: list[object] = []
    barrier = threading.Barrier(len(payloads))

    def write(data: bytes) -> None:
        barrier.wait()
        try:
            medium.put("events-000000000001-000000000001.json", data)
            outcomes.append(data)
        except FileExistsError:
            outcomes.append(None)

    threads = [threading.Thread(target=write, args=(data,)) for data in payloads]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stored = medium.get("events-000000000001-000000000001.json")
    assert stored in payloads
    assert [o for o in outcomes if o is not None] == [stored]  # only the winner reported success
    assert outcomes.count(None) == len(payloads) - 1
    assert sorted(p.name for p in medium.root.iterdir() if p.name.endswith(".tmp")) == []


def test_identical_concurrent_writers_all_succeed(tmp_path: Path) -> None:
    """Racing writers of the same bytes all succeed and leave no temporary files."""
    medium = DirectoryMedium(tmp_path / "public")
    errors: list[BaseException] = []

    def write() -> None:
        try:
            medium.put("events-000000000001-000000000001.json", b"same")
        except BaseException as error:  # noqa: BLE001 - the test reports any failure
            errors.append(error)

    threads = [threading.Thread(target=write) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == [] and medium.get("events-000000000001-000000000001.json") == b"same"
    assert [p.name for p in medium.root.iterdir() if p.name.endswith(".tmp")] == []


def test_directory_is_synced_after_the_rename(tmp_path: Path, monkeypatch) -> None:
    """File fsync, then rename, then a directory fsync: only then is success reported."""
    events: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd: int) -> None:
        events.append("fsync-dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync-file")
        real_fsync(fd)

    def replace(source, target) -> None:
        events.append("replace")
        real_replace(source, target)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    DirectoryMedium(tmp_path / "public").put("events-000000000001-000000000001.json", b"x")
    assert events == ["fsync-file", "replace", "fsync-dir"]
    events.clear()
    DirectoryMedium(tmp_path / "public").put("events-000000000001-000000000001.json", b"x")  # identical rewrite
    assert events == ["fsync-dir"]


def test_failed_write_leaves_no_temporary_file(tmp_path: Path, monkeypatch) -> None:
    """A write that fails after the temporary file exists removes it."""
    medium = DirectoryMedium(tmp_path / "public")

    def boom(source, target) -> None:
        raise OSError("disk gone")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        medium.put("state.json", b"x")
    assert list(medium.root.glob(".*.tmp")) == [] and medium.get("state.json") is None


def test_read_feed_requires_exactly_the_requested_versions(parts, tmp_path: Path) -> None:
    """A canonical segment with the right labels but missing events is refused, not treated as empty."""
    publisher, medium, head = _publisher(parts, tmp_path)
    publisher.publish(head)
    name = publisher.segment_name(1, head)
    good = json.loads(medium.get(name))
    for events in ([], good["events"][:1], good["events"][::-1], [good["events"][0], good["events"][0]], "xx", [None, None]):
        forged = dict(good, events=events)
        (medium.root / name).write_bytes(wire.canonical_bytes(forged))
        with pytest.raises(PublicationRefused) as caught:
            publisher.read_feed(head)
        assert caught.value.code == "publication.malformed"
    (medium.root / name).write_bytes(wire.canonical_bytes(good))
    assert len(publisher.read_feed(head)) == head


def test_oversize_state_is_refused_and_never_replaces_the_last_good_state(parts, tmp_path: Path, monkeypatch) -> None:
    """A state past the size limit is refused before any write; the previous state.json is untouched."""
    publisher, medium, head = _publisher(parts, tmp_path)
    good = publisher.publish(head)
    monkeypatch.setattr(publication, "MAX_STATE_BYTES", len(good) - 1)
    with pytest.raises(PublicationRefused) as caught:
        publisher.publish(head)
    assert caught.value.code == "publication.state_too_large"
    assert medium.get("state.json") == good
    with pytest.raises(PublicationRefused) as direct:
        verify_state(good, resolver=Resolver(), issuer_id=ISSUER, now=NOW)
    assert direct.value.code == "publication.state_too_large"


def test_lookup_expires_with_its_state(parts, tmp_path: Path) -> None:
    """A kept-alive lookup raises stale once the state ages out (or is dated in the future)."""
    publisher, _medium, head = _publisher(parts, tmp_path)
    state = verify_state(publisher.publish(head), resolver=Resolver(), issuer_id=ISSUER, now=NOW)
    clock = [NOW]
    lookup = CombinedRevocationLookup(state, clock=lambda: clock[0])
    assert lookup.reason("g1", "") == "grant_revoked" and lookup.reason("clean", "") is None
    clock[0] = NOW + timedelta(seconds=60)
    assert lookup.reason("clean", "") is None  # exactly at the limit is still fresh
    clock[0] = NOW + timedelta(seconds=61)
    for grant in ("clean", "g1"):
        with pytest.raises(PublicationRefused) as stale:
            lookup.reason(grant, "")
        assert stale.value.code == "publication.stale"
    clock[0] = NOW - timedelta(seconds=6)
    with pytest.raises(PublicationRefused):
        lookup.reason("clean", "")
    short = CombinedRevocationLookup(state, clock=lambda: NOW + timedelta(seconds=10), max_age_seconds=5)
    with pytest.raises(PublicationRefused):
        short.reason("clean", "")


def _resign(raw: bytes, mutate) -> bytes:
    """Return a correctly signed state whose body was changed by ``mutate``."""
    document = json.loads(raw)
    mutate(document["body"])
    document["signature"] = sign_state_body(SEED, document["body"])
    return wire.canonical_bytes(document)


def test_chain_cross_check_covers_the_summary_sets(parts) -> None:
    """A correct head with a dropped revocation, or a head-0 state with revocations, is refused."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1"), ("grant", "g2")], [("a1", ["g3"])])
    raw = build_state(feed, issuer_id=ISSUER, head_version=head, signer=signer, now=NOW)
    events = feed.events(1, head)
    for mutate in (
        lambda b: b.update(revoked_grants=["g2"]),
        lambda b: b.update(issuer_revoked=True),
        lambda b: b.update(revoked_approvals=["a9"]),
        lambda b: b.update(cascades=[]),
    ):
        forged = verify_state(_resign(raw, mutate), resolver=Resolver(), issuer_id=ISSUER, now=NOW)
        with pytest.raises(PublicationRefused) as caught:
            verify_state_against_chain(forged, events, resolver=Resolver())
        assert caught.value.code == "publication.head_mismatch"
    empty = build_state(feed, issuer_id=ISSUER, head_version=0, signer=signer, now=NOW)
    forged_empty = verify_state(_resign(empty, lambda b: b.update(revoked_grants=["x"])),
                                resolver=Resolver(), issuer_id=ISSUER, now=NOW)
    with pytest.raises(PublicationRefused) as caught:
        verify_state_against_chain(forged_empty, [], resolver=Resolver())
    assert caught.value.code == "publication.head_mismatch"


@pytest.mark.parametrize("version", [0, -1, True, 1.5, "1", 2**53])
def test_cascade_version_must_be_a_positive_safe_integer(parts, version) -> None:
    """A signed state whose cascade version is not a positive safe integer is malformed."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [], [("a1", ["g1"])])
    raw = build_state(feed, issuer_id=ISSUER, head_version=head, signer=signer, now=NOW)
    forged = _resign(raw, lambda b: b["cascades"][0].update(version=version))
    with pytest.raises(PublicationRefused) as caught:
        verify_state(forged, resolver=Resolver(), issuer_id=ISSUER, now=NOW)
    assert caught.value.code == "publication.malformed"


@pytest.mark.parametrize("age", [0, 61, 3600, True, 30.0])
def test_freshness_ceiling_cannot_be_loosened(parts, age) -> None:
    """Neither verify_state nor the lookup accepts an age limit outside 1..60 seconds."""
    _store, _ledger, feed, signer = parts
    raw = build_state(feed, issuer_id=ISSUER, head_version=0, signer=signer, now=NOW)
    with pytest.raises(ValueError):
        verify_state(raw, resolver=Resolver(), issuer_id=ISSUER, now=NOW, max_age_seconds=age)
    state = verify_state(raw, resolver=Resolver(), issuer_id=ISSUER, now=NOW)
    with pytest.raises(ValueError):
        CombinedRevocationLookup(state, clock=lambda: NOW, max_age_seconds=age)


def test_publish_verifies_the_chain_before_writing_anything(parts, tmp_path) -> None:
    """A corrupted retained event stops publication before any segment or state is written."""
    store, _ledger, feed, signer = parts
    head = load(store, signer, [("grant", "g1"), ("grant", "g2")], [])

    class Corrupt:
        """Feed double returning a tampered first event."""

        def events(self, low, high):
            """Return the real events with event 1's subject changed."""
            out = [json.loads(json.dumps(e)) for e in feed.events(low, high)]
            if out and out[0]["version"] == 1:
                out[0]["body"]["subject_id"] = "forged"
            return out

    medium = DirectoryMedium(tmp_path / "public")
    publisher = FeedPublisher(Corrupt(), medium, Resolver(), issuer_id=ISSUER, signer=signer, clock=lambda: NOW)
    with pytest.raises(PublicationRefused):
        publisher.publish(head)
    assert [p.name for p in (tmp_path / "public").iterdir() if not p.name.startswith(".")] == []
