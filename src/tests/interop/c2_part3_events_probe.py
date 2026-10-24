"""Interop probe, E1 C2 Part 3 Sections 1-2: real Phylax issuer events x real Oramasys consumer.

Run: python3 c2_part3_events_probe.py <phylax-checkout> <oramasys-checkout>   (needs only PyNaCl)
This file is byte-identical in the Phylax and Oramasys repositories (src/tests/interop/); each
repository's CI runs it against the other at a pinned commit. Signatures are real Ed25519ph through
the issuer's wire module; Oramasys itself stays crypto-free. Prints a JSON receipt; exit 0 only if
every expectation holds. It enables nothing and promotes no pin.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

PHYLAX, ORAMASYS = (Path(arg).resolve() for arg in sys.argv[1:3])
sys.path[:0] = [str(PHYLAX / "src"), str(ORAMASYS / "src")]

from nacl.bindings import crypto_sign_seed_keypair  # noqa: E402
from orama.graph.dispatch_attempts import (  # noqa: E402
    AuthorizationRefused, EventRefused, ExpectedBinding, SqliteAttemptStore,
    VerifiedDispatchGrant,
)
from orama.graph.effect_proposals import EffectScope  # noqa: E402
from phylax import dispatch_wire as W  # noqa: E402
from phylax.dispatch_permit_store import GrantFacts, SqliteDispatchPermitStore  # noqa: E402

SEED = hashlib.sha256(b"c2-part3-events-probe-key-1").digest()
KEY = "part3-probe-key-1"
PUBLIC = crypto_sign_seed_keypair(SEED)[0]
ISSUER = "issuer-probe"
APPROVAL = "approval-probe-1"
NOW = datetime(2026, 10, 19, 5, 0, 0, tzinfo=UTC)
D = {name: hashlib.sha256(name.encode()).hexdigest() for name in ("gp", "rq", "ar", "pol")}
VECTOR_FILES = ("docs/vectors/dispatch-events-v1.json", "src/tests/vectors/dispatch-events-v1.json")


class Signer:
    """Issuer signer port backed by the issuer wire module and the probe seed."""

    def active_key_id(self) -> str:
        """Return the probe's one issuer key id."""
        return KEY

    def sign_permit(self, key_id: str, body) -> str:
        """Sign a permit body with the probe seed."""
        return W.sign_permit(SEED, body)

    def sign_finalization(self, key_id: str, body) -> str:
        """Sign a finalization body with the probe seed."""
        return W.sign_finalization(SEED, body)

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign an event digest with the probe seed."""
        return W.sign_event(SEED, digest)


class Verifier:
    """Consumer verifier port: REAL Ed25519ph verification through the issuer's wire module."""

    def __init__(self, key_id: str = KEY, public: bytes = PUBLIC) -> None:
        """Pin the trusted key id and public key."""
        self.key_id, self.public = key_id, public

    def verify_permit(self, key_id, body, signature) -> bool:
        """Verify a permit signature under the pinned key."""
        return key_id == self.key_id and W.verify_permit(self.public, body, signature)

    def verify_finalization(self, key_id, body, signature) -> bool:
        """Verify a finalization signature under the pinned key."""
        return key_id == self.key_id and W.verify_finalization(self.public, body, signature)

    def verify_event(self, key_id, digest, signature) -> bool:
        """Verify an event signature under the pinned key."""
        return key_id == self.key_id and W.verify_event(self.public, digest, signature)


class Grants:
    """The issuer's injected grant facts: every grant is live (issuer admission is out of scope)."""

    def get(self, grant_id: str) -> GrantFacts:
        """Return live grant facts bound to the probe's fixed digests."""
        return GrantFacts(D["gp"], f"op-{grant_id}", D["rq"], "probe-ledger", NOW + timedelta(hours=2), False, False)


class Gates:
    """Rule 6 gate port that always passes, so every refusal comes from Rule 4."""
    def check(self, **_kwargs) -> bool:
        """Pass every gate check."""
        return True


class NoPortRevocations:
    """The legacy injected port says nothing is revoked, so every refusal below comes from the facts."""

    def revoked(self, *, grant_id: str, issuer_id: str) -> bool:
        """Report nothing revoked through the legacy port."""
        return False


SCOPE = EffectScope("probe-principal", "probe-graph", D["pol"], D["rq"], D["ar"], "probe-dest")


class World:
    """One issuer and one governed consumer, each in a private temp directory."""

    def __init__(self) -> None:
        """Create a private issuer store, a governed consumer store and real crypto ports."""
        self.root = Path(tempfile.mkdtemp(prefix="c2-part3-"))
        self.issuer = SqliteDispatchPermitStore(self.root / "issuer" / "issuer.db")
        (self.root / "consumer").mkdir(mode=0o700)
        self.consumer_path = self.root / "consumer" / "attempts.db"
        self.consumer = SqliteAttemptStore(self.consumer_path, governed=True)
        self.signer, self.verifier, self.n, self.t = Signer(), Verifier(), 0, NOW

    def tick(self) -> datetime:
        """Advance the world clock by one second and return it."""
        self.t += timedelta(seconds=1)
        return self.t

    def sync(self) -> None:
        """Deliver every issuer event the consumer has not acknowledged yet."""
        low, high = self.consumer.acked_through(ISSUER) + 1, self.issuer.current_counter()
        if low <= high:
            self.consumer.ingest_events(ISSUER, self.issuer.events(low, high), self.verifier)

    def reservations(self) -> list:
        """Return the consumer's reservation rows, read-only and sorted."""
        connection = sqlite3.connect(f"file:{self.consumer_path}?mode=ro", uri=True)
        try:
            return sorted(connection.execute("SELECT * FROM reservations").fetchall(), key=repr)
        finally:
            connection.close()

    def dispatch(self, grant_id: str | None = None, approval_ref: str | None = ""):
        """Run one full permit round; return None on success or (rule, reason, untouched).

        ``approval_ref`` is bound to the attempt at creation ("" single approval, None undeclared);
        Step 4.3 reads it from there and takes no approval argument.
        """
        self.n += 1
        grant = grant_id or f"grant-{self.n}"
        attempt, reservation = f"attempt-{self.n}", f"res-{self.n}"
        self.sync()
        req = {
            "grant_id": grant, "grant_payload_digest": D["gp"], "operation_id": f"op-{grant}",
            "request_digest": D["rq"], "artifact_digest": D["ar"], "reservation_id": reservation,
            "ledger_store_id": "probe-ledger", "configuration_policy_epoch": 1, "authority_epoch": 1,
            "consumer_acked_through": self.consumer.acked_through(ISSUER), "attempt_id": attempt,
            "requested_at": W.timestamp(self.t),
        }
        if approval_ref is None:
            # This one vector models a migrated row with an undeclared binding.
            self.consumer._create_attempt(attempt, grant, reservation)
        else:
            self.consumer.create_attempt(
                attempt, VerifiedDispatchGrant(grant, approval_ref), reservation
            )
        self.consumer.propose(f"proposal-{self.n}", SCOPE, self.t)
        self.consumer.reserve(reservation, f"proposal-{self.n}", SCOPE, self.t + timedelta(hours=1), self.t)
        self.consumer.mark_transmitted(attempt)
        permit = json.loads(self.issuer.admit(req, grants=Grants(), signer=self.signer, now=self.tick()))
        fin_req = {
            "permit_id": permit["permit_id"], "permit_digest": permit["payload_digest"],
            "attempt_id": attempt, "reservation_id": reservation, "ledger_store_id": "probe-ledger",
            "authority_epoch": 1, "consumer_acked_through": req["consumer_acked_through"],
            "requested_at": W.timestamp(self.t),
        }
        fin_bytes, envelope = self.issuer.finalize(fin_req, grants=Grants(), signer=self.signer, now=self.tick())
        before_rows = self.reservations()
        try:
            self.consumer.authorize_dispatch(
                attempt, permit, json.loads(fin_bytes), self.tick(), verifier=self.verifier,
                gates=Gates(), revocations=NoPortRevocations(), issuer_id=ISSUER,
                expected=ExpectedBinding(D["rq"], D["ar"], 1, 1, "probe-ledger"), scope=SCOPE,
            )
        except AuthorizationRefused as refusal:
            untouched = (
                self.reservations() == before_rows
                and self.consumer.outbox_row(attempt) is None
            )
            return refusal.rule, refusal.reason, untouched
        return None


results: list[dict] = []


def record(name: str, ok: bool, detail: str) -> None:
    """Record and print one scenario outcome."""
    results.append({"scenario": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + " :: " + detail)


def refuses(call) -> bool:
    """Return True when the call is refused as malformed (wire or event refusal)."""
    try:
        call()
    except (W.WireError, EventRefused):
        return True
    return False


def main() -> int:
    """Run scenarios X1-X8 and return 0 only when every scenario passes."""
    worlds: list[World] = []

    # X1 the published vectors are byte-identical in both repositories and verify for real.
    phylax_bytes, oramasys_bytes = (root.joinpath(p).read_bytes() for root, p in zip((PHYLAX, ORAMASYS), VECTOR_FILES))
    vectors = json.loads(phylax_bytes)
    w = World(); worlds.append(w)
    w.consumer.ingest_events(ISSUER, vectors["events"], Verifier(vectors["issuer_key_id"], bytes.fromhex(vectors["public_key"])))
    facts = w.consumer.authority_facts(ISSUER)
    record("X1 vectors identical, real signatures verify, facts recorded",
           phylax_bytes == oramasys_bytes and w.consumer.acked_through(ISSUER) == 4
           and len(facts["revocations"]) == 3 and len(facts["cascades"]) == 1,
           f"sha256={hashlib.sha256(phylax_bytes).hexdigest()[:16]} acked={w.consumer.acked_through(ISSUER)}")

    # X2 every shared malformed body is refused by the issuer AND by the consumer (real signature).
    misses = []
    for case in vectors["malformed"]:
        digest = hashlib.sha256(case["name"].encode()).hexdigest()
        event = {"version": 1, "kind": case["kind"], "body": case["body"], "previous_event_digest": W.GENESIS_EVENT_DIGEST,
                 "event_digest": digest, "issuer_key_id": KEY, "signature": W.sign_event(SEED, digest)}
        issuer_refused = refuses(lambda: W.event_digest(1, case["kind"], case["body"], W.GENESIS_EVENT_DIGEST))
        fresh = World(); worlds.append(fresh)
        consumer_refused = refuses(lambda: fresh.consumer.ingest_events(ISSUER, [event], fresh.verifier))
        if not (issuer_refused and consumer_refused and fresh.consumer.acked_through(ISSUER) == 0):
            misses.append(case["name"])
    record("X2 malformed bodies refused on both sides", not misses, f"{len(vectors['malformed'])} cases, misses={misses}")

    # X3 duplicate and unsorted cascades: the issuer append refuses and consumes no version.
    w = World(); worlds.append(w)
    bad = [refuses(lambda g=g: w.issuer.append_cascade(APPROVAL, g, 1, signer=w.signer))
           for g in (["grant-b", "grant-a"], ["grant-a", "grant-a"])]
    record("X3 duplicate/unsorted cascade rejected", all(bad) and w.issuer.current_counter() == 0,
           f"refused={bad} counter={w.issuer.current_counter()}")

    # X4-X6 each revocation kind refuses dispatch under Rule 4 with nothing written. The approval
    # binding is persisted on the attempt; the authorizing caller never supplies it.
    cases = (
        ("X4 grant revocation", lambda w: w.issuer.append_revocation("grant", "grant-x", signer=w.signer), "grant-x", "", "grant_revoked"),
        ("X5a approval revocation (bound on the attempt)", lambda w: w.issuer.append_revocation("approval", APPROVAL, signer=w.signer), "grant-x", APPROVAL, "approval_revoked"),
        ("X5b cascade lists the grant (single-approval binding)", lambda w: (w.issuer.append_revocation("approval", APPROVAL, signer=w.signer),
            w.issuer.append_cascade(APPROVAL, ["grant-a", "grant-x"], 1, signer=w.signer)), "grant-x", "", "cascade_listed"),
        ("X5c undeclared binding fails closed on an approval revocation", lambda w: w.issuer.append_revocation("approval", APPROVAL, signer=w.signer), "grant-x", None, "approval_undeclared"),
        ("X6 issuer revocation", lambda w: w.issuer.append_revocation("issuer", ISSUER, signer=w.signer), "grant-x", "", "issuer_revoked"),
    )
    for name, setup, grant, approval_ref, reason in cases:
        w = World(); worlds.append(w)
        setup(w)
        outcome = w.dispatch(grant, approval_ref)
        record(name, outcome == ("rule4", reason, True), f"outcome={outcome}")

    # X7 replay is idempotent: the same events twice change nothing and flag no divergence.
    w = World(); worlds.append(w)
    w.issuer.append_revocation("grant", "grant-r", signer=w.signer)
    w.issuer.append_cascade(APPROVAL, ["grant-s"], 1, signer=w.signer)
    events = w.issuer.events(1, 2)
    w.consumer.ingest_events(ISSUER, events, w.verifier)
    first = w.consumer.authority_facts(ISSUER)
    w.consumer.ingest_events(ISSUER, events, w.verifier)
    again = w.issuer.append_revocation("grant", "grant-r", signer=w.signer)
    record("X7 replay idempotent on both sides",
           first == w.consumer.authority_facts(ISSUER) and not w.consumer.is_diverged(ISSUER)
           and again == events[0] and w.issuer.current_counter() == 2,
           f"acked={w.consumer.acked_through(ISSUER)} counter={w.issuer.current_counter()}")

    # X8 a refusal preserves the reservation; an unrelated grant on the same chain still dispatches.
    w = World(); worlds.append(w)
    w.issuer.append_revocation("grant", "grant-x", signer=w.signer)
    refused = w.dispatch("grant-x")
    held = w.reservations()
    allowed = w.dispatch("grant-y")
    record("X8 refusal keeps the reservation; control dispatch consumes its own",
           refused == ("rule4", "grant_revoked", True) and allowed is None and w.reservations() != held,
           f"refused={refused} control={'authorized' if allowed is None else allowed}")

    for world in worlds:
        world.consumer.close()
        shutil.rmtree(world.root, ignore_errors=True)
    ok = all(r["ok"] for r in results)
    print(json.dumps({"probe": "c2_part3_events_probe", "ok": ok, "results": results}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
