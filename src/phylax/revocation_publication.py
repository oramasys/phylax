"""Signed public revocation state, a durable event feed and the combined revocation lookup.

Implements decision D3 additively. The state is a signed *summary* of the issuer's event chain; it
is never the authority by itself, because it names the chain head (version and digest) that a
verifier cross-checks against the signed feed. Contract: ``docs/revocation-publication.md``.

* :func:`build_state` replays every event (archive plus hot rows) into closed sets and signs the
  result under its own domain.
* :class:`FeedPublisher` writes immutable, hash-linked feed segments and the state to a
  :class:`PublicationMedium`, reads each artifact back and verifies it before reporting success.
  A medium that cannot be read back is ``unavailable``, never an empty success.
* :class:`CombinedRevocationLookup` answers from a verified, fresh state across grant,
  approval-chain, issuer and cascade revocation with the consumer's own ordering (vector-pinned).
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final, Protocol

from nacl import exceptions as nacl_exceptions
from nacl.bindings import (
    crypto_sign_ed25519ph_final_create,
    crypto_sign_ed25519ph_final_verify,
    crypto_sign_ed25519ph_state,
    crypto_sign_ed25519ph_update,
    crypto_sign_seed_keypair,
)

from . import dispatch_wire as wire
from .dispatch_retention import (
    IssuerKeyResolver,
    RetainedEventFeed,
    RetentionRefused,
    verify_chain,
)

STATE_DOMAIN: Final = b"phylax-revocation-state-v1\x00"
SEGMENT_SIZE: Final = 64
DEFAULT_MAX_STATE_AGE_SECONDS: Final = 60
MAX_FUTURE_SKEW_SECONDS: Final = 5
MAX_STATE_BYTES: Final = wire.MAX_WIRE_BYTES * 16
PUBLICATION_REFUSAL_CODES: Final = frozenset({
    "publication.malformed", "publication.signature", "publication.stale",
    "publication.head_mismatch", "publication.unavailable", "publication.readback_mismatch",
    "publication.unknown_key", "publication.issuer_mismatch", "publication.state_too_large",
})
_STATE_FIELDS = (
    "schema_version", "issuer_id", "head_version", "head_event_digest", "generated_at",
    "issuer_revoked", "revoked_grants", "revoked_approvals", "cascades",
)
_CASCADE_FIELDS = ("version", "approval_id", "issuer_authority_version", "grant_ids")


class PublicationRefused(Exception):
    """A closed-vocabulary publication refusal; consumers must treat any of them as 'revoked'."""

    def __init__(self, code: str) -> None:
        """Record the code, which must belong to the publication vocabulary."""
        if code not in PUBLICATION_REFUSAL_CODES:
            raise ValueError(f"unknown publication refusal code: {code}")
        super().__init__(code)
        self.code = code


class StateSigner(Protocol):
    """Injected issuer signer for state documents."""

    def active_key_id(self) -> str:
        """Return the active issuer key id."""

    def sign_state(self, key_id: str, body: Mapping[str, object]) -> str:
        """Return the base64url signature over the domain-separated canonical state body."""


class PublicationMedium(Protocol):
    """Injected durable public medium; ``get`` returns None only for an absent name."""

    def put(self, name: str, data: bytes) -> None:
        """Durably store ``data`` under ``name`` (immutable names are never overwritten)."""

    def get(self, name: str) -> bytes | None:
        """Return the stored bytes, or None if the name does not exist."""


def sign_state_body(seed: bytes, body: Mapping[str, object]) -> str:
    """Sign a state body (Ed25519ph over the state domain and the canonical body)."""
    _public, secret = crypto_sign_seed_keypair(seed)
    state = crypto_sign_ed25519ph_state()
    crypto_sign_ed25519ph_update(state, STATE_DOMAIN)
    crypto_sign_ed25519ph_update(state, wire.canonical_bytes(body))
    return wire.b64url_encode(crypto_sign_ed25519ph_final_create(state, secret))


def _verify_state_signature(public_key: bytes, body: Mapping[str, object], signature: str) -> bool:
    """Return True only when the state signature verifies."""
    try:
        raw = wire.b64url_decode(signature)
        state = crypto_sign_ed25519ph_state()
        crypto_sign_ed25519ph_update(state, STATE_DOMAIN)
        crypto_sign_ed25519ph_update(state, wire.canonical_bytes(body))
        return bool(crypto_sign_ed25519ph_final_verify(state, raw, public_key))
    except (wire.WireError, nacl_exceptions.BadSignatureError, nacl_exceptions.ValueError):
        return False


def build_state(
    feed: RetainedEventFeed, *, issuer_id: str, head_version: int, signer: StateSigner, now: datetime
) -> bytes:
    """Replay events 1..head into closed sets and return the signed state envelope bytes."""
    events = feed.events(1, head_version) if head_version >= 1 else []
    grants: set[str] = set()
    approvals: set[str] = set()
    issuer_revoked = False
    cascades: list[dict[str, object]] = []
    for event in events:
        body = event["body"]
        if event["kind"] == "revocation":
            kind, subject = body["subject_kind"], body["subject_id"]
            if kind == "grant":
                grants.add(subject)
            elif kind == "approval":
                approvals.add(subject)
            elif kind == "issuer" and subject == issuer_id:
                issuer_revoked = True
        elif event["kind"] == "cascade":
            cascades.append({
                "version": event["version"], "approval_id": body["approval_id"],
                "issuer_authority_version": body["issuer_authority_version"],
                "grant_ids": list(body["grant_ids"]),
            })
    head_digest = events[-1]["event_digest"] if events else wire.GENESIS_EVENT_DIGEST
    body = {
        "schema_version": wire.SCHEMA_VERSION, "issuer_id": issuer_id, "head_version": head_version,
        "head_event_digest": head_digest, "generated_at": wire.timestamp(now),
        "issuer_revoked": issuer_revoked, "revoked_grants": sorted(grants),
        "revoked_approvals": sorted(approvals), "cascades": cascades,
    }
    key_id = signer.active_key_id()
    wire.validate_key_id(key_id)
    envelope = {"body": body, "signature": signer.sign_state(key_id, body), "issuer_key_id": key_id}
    return wire.canonical_bytes(envelope)


@dataclass(frozen=True, slots=True)
class VerifiedState:
    """A signature-checked, freshness-checked public revocation state."""

    issuer_id: str
    head_version: int
    head_event_digest: str
    generated_at: datetime
    issuer_revoked: bool
    revoked_grants: frozenset[str]
    revoked_approvals: frozenset[str]
    cascade_grants: frozenset[str]


def _refuse(code: str) -> PublicationRefused:
    """Build a refusal (keeps raise sites short)."""
    return PublicationRefused(code)


def _is_fresh(generated: datetime, now: datetime, max_age_seconds: int) -> bool:
    """Return True when ``generated`` is at most ``max_age_seconds`` old and not from the future."""
    return (
        now - generated <= timedelta(seconds=max_age_seconds)
        and generated - now <= timedelta(seconds=MAX_FUTURE_SKEW_SECONDS)
    )


def verify_state(
    raw: bytes, *, resolver: IssuerKeyResolver, issuer_id: str, now: datetime,
    max_age_seconds: int = DEFAULT_MAX_STATE_AGE_SECONDS,
) -> VerifiedState:
    """Verify signature, closed shape, issuer binding and freshness; refuse anything else."""
    if not isinstance(raw, (bytes, bytearray)):
        raise _refuse("publication.malformed")
    if len(raw) > MAX_STATE_BYTES:
        raise _refuse("publication.state_too_large")
    try:
        document = json.loads(bytes(raw).decode("utf-8"))
        if wire.canonical_bytes(document) != bytes(raw):
            raise _refuse("publication.malformed")
        body, signature, key_id = document["body"], document["signature"], document["issuer_key_id"]
        if set(document) != {"body", "signature", "issuer_key_id"} or set(body) != set(_STATE_FIELDS):
            raise _refuse("publication.malformed")
        wire.validate_key_id(key_id)
        if body["schema_version"] != wire.SCHEMA_VERSION:
            raise _refuse("publication.malformed")
        generated = wire.parse_timestamp(body["generated_at"])
        grants, approvals = body["revoked_grants"], body["revoked_approvals"]
        for group in (grants, approvals):
            if not isinstance(group, list) or group != sorted(set(group)):
                raise _refuse("publication.malformed")
            for item in group:
                wire.validate_identifier("subject_id", item)
        if not isinstance(body["issuer_revoked"], bool):
            raise _refuse("publication.malformed")
        cascade_grants = _cascade_grants(body["cascades"])
        head = body["head_version"]
        if isinstance(head, bool) or not isinstance(head, int) or head < 0:
            raise _refuse("publication.malformed")
        if not wire._is_digest(body["head_event_digest"]):
            raise _refuse("publication.malformed")
    except PublicationRefused:
        raise
    except (ValueError, KeyError, TypeError, wire.WireError) as error:
        raise _refuse("publication.malformed") from error
    if body["issuer_id"] != issuer_id:
        raise _refuse("publication.issuer_mismatch")
    public_key = resolver.public_key(key_id)
    if public_key is None:
        raise _refuse("publication.unknown_key")
    if not _verify_state_signature(public_key, body, signature):
        raise _refuse("publication.signature")
    if not _is_fresh(generated, now, max_age_seconds):
        raise _refuse("publication.stale")
    return VerifiedState(
        issuer_id, head, body["head_event_digest"], generated, body["issuer_revoked"],
        frozenset(grants), frozenset(approvals), cascade_grants,
    )


def _cascade_grants(cascades: object) -> frozenset[str]:
    """Validate the closed cascade list and return every grant it names."""
    if not isinstance(cascades, list):
        raise _refuse("publication.malformed")
    out: set[str] = set()
    for cascade in cascades:
        if not isinstance(cascade, dict) or set(cascade) != set(_CASCADE_FIELDS):
            raise _refuse("publication.malformed")
        wire.validate_cascade_body({
            "approval_id": cascade["approval_id"], "grant_ids": cascade["grant_ids"],
            "issuer_authority_version": cascade["issuer_authority_version"],
        })
        out.update(cascade["grant_ids"])
    return frozenset(out)


class CombinedRevocationLookup:
    """Rule 4 reasons from a verified fresh state; identical ordering to the consumer's lookup.

    Freshness is re-checked on every ``reason`` call against the injected clock, so a lookup that is
    kept alive past the state's age limit raises ``publication.stale`` (treat as revoked) instead of
    answering "nothing revoked" from an expired state.
    """

    def __init__(
        self, state: VerifiedState, *, clock: Callable[[], datetime],
        max_age_seconds: int = DEFAULT_MAX_STATE_AGE_SECONDS,
    ) -> None:
        """Bind a verified state, the clock that judges its age and the age limit."""
        self._state, self._clock, self._max_age = state, clock, max_age_seconds

    def reason(self, grant_id: str, approval_ref: str | None) -> str | None:
        """Return the refusal reason or None; raise ``publication.stale`` once the state has expired.

        ``approval_ref`` ``""`` means a single approval (matches no approval revocation); ``None``
        means undeclared, so any approval revocation refuses it.
        """
        state = self._state
        if not _is_fresh(state.generated_at, self._clock(), self._max_age):
            raise _refuse("publication.stale")
        if state.issuer_revoked:
            return "issuer_revoked"
        if grant_id in state.revoked_grants:
            return "grant_revoked"
        if approval_ref and approval_ref in state.revoked_approvals:
            return "approval_revoked"
        if grant_id in state.cascade_grants:
            return "cascade_listed"
        if approval_ref is None and state.revoked_approvals:
            return "approval_undeclared"
        return None


def verify_state_against_chain(
    state: VerifiedState, events: Sequence[Mapping[str, object]], *, resolver: IssuerKeyResolver
) -> None:
    """Cross-check the state head against a verified signed event chain from genesis."""
    if state.head_version == 0:
        if events:
            raise _refuse("publication.head_mismatch")
        return
    tip = verify_chain(events, previous_digest=wire.GENESIS_EVENT_DIGEST, resolver=resolver)
    if len(events) != state.head_version or tip != state.head_event_digest:
        raise _refuse("publication.head_mismatch")


class DirectoryMedium:
    """A directory-backed medium with atomic writes and immutable segment names."""

    def __init__(self, root: str | Path, *, mutable: frozenset[str] = frozenset({"state.json"})) -> None:
        """Create the directory; only names in ``mutable`` may be replaced."""
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._mutable = mutable

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize writers across processes with an advisory lock on a dot-named lock file."""
        with (self.root / ".publish.lock").open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _sync_directory(self) -> None:
        """fsync the directory so a completed rename survives a crash (POSIX)."""
        descriptor = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def put(self, name: str, data: bytes) -> None:
        """Write atomically and durably; refuse to alter an immutable name.

        Writers are serialized by a lock so the immutable-name check and the write cannot interleave;
        each write uses its own temporary file, and the directory is synced after the rename before
        success is reported (an identical immutable rewrite is synced too).
        """
        if "/" in name or name.startswith("."):
            raise ValueError("invalid publication name")
        target = self.root / name
        with self._locked():
            if target.exists() and name not in self._mutable:
                if target.read_bytes() == data:
                    self._sync_directory()
                    return
                raise FileExistsError(name)
            descriptor, temp_name = tempfile.mkstemp(dir=self.root, prefix=f".{name}.", suffix=".tmp")
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, target)
            except BaseException:
                Path(temp_name).unlink(missing_ok=True)
                raise
            self._sync_directory()

    def get(self, name: str) -> bytes | None:
        """Return the stored bytes or None when absent."""
        if "/" in name or name.startswith("."):
            return None
        try:
            return (self.root / name).read_bytes()
        except FileNotFoundError:
            return None


class FeedPublisher:
    """Publishes hash-linked feed segments plus the signed state, verifying every read-back."""

    def __init__(
        self, feed: RetainedEventFeed, medium: PublicationMedium, resolver: IssuerKeyResolver,
        *, issuer_id: str, signer: StateSigner, clock: Callable[[], datetime],
    ) -> None:
        """Bind the retained feed, the public medium and the issuer identity."""
        self._feed, self._medium, self._resolver = feed, medium, resolver
        self._issuer_id, self._signer, self._clock = issuer_id, signer, clock

    @staticmethod
    def segment_name(low: int, high: int) -> str:
        """Return the immutable name of the segment holding versions low..high."""
        return f"events-{low:012d}-{high:012d}.json"

    def publish(self, head_version: int) -> bytes:
        """Publish all full or tail segments up to ``head_version`` and then the state.

        Segments are written before the state that names their head, so a reader that sees a
        state can always find its segments. Every artifact is read back and compared.
        """
        low = 1
        while low <= head_version:
            high = min(low + SEGMENT_SIZE - 1, head_version)
            events = self._feed.events(low, high)
            data = wire.canonical_bytes({"events": events, "from_version": low, "through_version": high})
            name = self.segment_name(low, high)
            self._store_and_verify(name, data)
            low = high + 1
        now = self._clock()
        state = build_state(
            self._feed, issuer_id=self._issuer_id, head_version=head_version, signer=self._signer, now=now
        )
        # Verify first: an unverifiable state (for example one past the size limit) must never
        # replace the last good state.json.
        verify_state(state, resolver=self._resolver, issuer_id=self._issuer_id, now=now)
        self._store_and_verify("state.json", state)
        return state

    def _store_and_verify(self, name: str, data: bytes) -> None:
        """Put an artifact and require the medium to return identical bytes."""
        try:
            self._medium.put(name, data)
            stored = self._medium.get(name)
        except OSError as error:
            raise _refuse("publication.unavailable") from error
        if stored is None:
            raise _refuse("publication.unavailable")
        if stored != data:
            raise _refuse("publication.readback_mismatch")

    def read_feed(self, head_version: int) -> list[dict[str, object]]:
        """Read and verify the published feed from genesis through ``head_version``."""
        events: list[dict[str, object]] = []
        low = 1
        while low <= head_version:
            high = min(low + SEGMENT_SIZE - 1, head_version)
            try:
                raw = self._medium.get(self.segment_name(low, high))
            except OSError as error:
                raise _refuse("publication.unavailable") from error
            if raw is None:
                raise _refuse("publication.unavailable")
            try:
                segment = json.loads(raw.decode("utf-8"))
                if wire.canonical_bytes(segment) != raw or segment["from_version"] != low or segment["through_version"] != high:
                    raise _refuse("publication.malformed")
                segment_events = segment["events"]
                if not isinstance(segment_events, list):
                    raise _refuse("publication.malformed")
                versions = [e.get("version") if isinstance(e, dict) else None for e in segment_events]
                if versions != list(range(low, high + 1)):
                    raise _refuse("publication.malformed")
                events.extend(segment_events)
            except PublicationRefused:
                raise
            except (ValueError, KeyError, TypeError, wire.WireError) as error:
                raise _refuse("publication.malformed") from error
            low = high + 1
        if events:
            try:
                verify_chain(events, previous_digest=wire.GENESIS_EVENT_DIGEST, resolver=self._resolver)
            except RetentionRefused as error:
                code = {
                    "retention.signature_invalid": "publication.signature",
                    "retention.unknown_key": "publication.unknown_key",
                }.get(error.code, "publication.malformed")
                raise _refuse(code) from error
        return events
