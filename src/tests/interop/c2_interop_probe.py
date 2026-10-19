"""Interop probe: real Phylax issuer store x real Oramasys consumer, real Ed25519ph verification.

Run: python3 c2_interop_probe.py <phylax-checkout> <oramasys-checkout>   (needs only PyNaCl)
Standalone on purpose: Oramasys never imports a signature library; only this probe adapts the issuer's
verifier into the consumer's injected port. This file is byte-identical in the Phylax and Oramasys
repositories (src/tests/interop/); each repository's CI runs it against the other at a pinned
commit. Prints a JSON receipt; exit 0 only if every expectation holds.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

PHYLAX, ORAMASYS = (Path(arg).resolve() for arg in sys.argv[1:3])
sys.path[:0] = [str(PHYLAX / "src"), str(ORAMASYS / "src")]

from nacl.bindings import crypto_sign_seed_keypair  # noqa: E402
from orama.graph.dispatch_attempts import (  # noqa: E402
    AuthorizationRefused, ExpectedBinding, SqliteAttemptStore, sender_precondition,
)
from phylax import dispatch_wire as W  # noqa: E402
from phylax.dispatch_permit_store import GrantFacts, SqliteDispatchPermitStore  # noqa: E402

SEED = hashlib.sha256(b"c2-interop-probe-key-1").digest()
KEY = "probe-key-1"
PUBLIC = crypto_sign_seed_keypair(SEED)[0]
ISSUER = "issuer-probe"
NOW = datetime(2026, 10, 19, 5, 0, 0, tzinfo=UTC)
D = {name: hashlib.sha256(name.encode()).hexdigest() for name in ("gp", "rq", "ar")}


class Signer:
    """Issuer signer port backed by the frozen wire module and a fixed probe seed."""

    def active_key_id(self) -> str:
        return KEY

    def sign_permit(self, key_id: str, body) -> str:
        return W.sign_permit(SEED, body)

    def sign_finalization(self, key_id: str, body) -> str:
        return W.sign_finalization(SEED, body)

    def sign_event(self, key_id: str, digest: str) -> str:
        return W.sign_event(SEED, digest)


class Verifier:
    """Consumer verifier port: REAL Ed25519ph verification through the issuer's wire module."""

    def verify_permit(self, key_id, body, signature) -> bool:
        return key_id == KEY and W.verify_permit(PUBLIC, body, signature)

    def verify_finalization(self, key_id, body, signature) -> bool:
        return key_id == KEY and W.verify_finalization(PUBLIC, body, signature)

    def verify_event(self, key_id, digest, signature) -> bool:
        return key_id == KEY and W.verify_event(PUBLIC, digest, signature)


class Grants:
    """Signed-grant lookup port: every grant matches the probe's request digests."""

    def __init__(self) -> None:
        self.ledgers: dict[str, str] = {}

    def get(self, grant_id: str) -> GrantFacts:
        ledger = self.ledgers.get(grant_id, "probe-ledger")
        return GrantFacts(D["gp"], f"op-{grant_id}", D["rq"], ledger, NOW + timedelta(hours=2), False, False)


class Gates:
    def check(self, **_kwargs) -> bool:
        return True


class Revocations:
    def revoked(self, *, grant_id: str, issuer_id: str) -> bool:
        return False


class World:
    """One issuer database plus one consumer database, each in a private temp directory."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="c2-interop-"))
        self.issuer_path = self.root / "issuer" / "issuer.db"
        self.issuer = SqliteDispatchPermitStore(self.issuer_path)
        (self.root / "consumer").mkdir(mode=0o700)
        self.consumer = SqliteAttemptStore(self.root / "consumer" / "attempts.db")
        self.verifier, self.signer, self.grants = Verifier(), Signer(), Grants()
        self.n = 0
        self.t = NOW

    def tick(self, seconds: int = 1) -> datetime:
        self.t += timedelta(seconds=seconds)
        return self.t

    def request(self, ack: int, ledger: str = "probe-ledger") -> dict:
        self.n += 1
        if ledger != "probe-ledger":
            self.grants.ledgers[f"grant-{self.n}"] = ledger
        return {
            "grant_id": f"grant-{self.n}", "grant_payload_digest": D["gp"], "operation_id": f"op-grant-{self.n}",
            "request_digest": D["rq"], "artifact_digest": D["ar"], "reservation_id": f"res-{self.n}",
            "ledger_store_id": ledger, "configuration_policy_epoch": 1, "authority_epoch": 1,
            "consumer_acked_through": ack, "attempt_id": f"attempt-{self.n}", "requested_at": W.timestamp(self.t),
        }

    def issue(self, req: dict, fin_ack: int | None = None):
        """Issuer side: admit then finalize; return (permit dict, finalization dict, envelope)."""
        permit = json.loads(self.issuer.admit(req, grants=self.grants, signer=self.signer, now=self.tick()))
        fin_req = {
            "permit_id": permit["permit_id"], "permit_digest": permit["payload_digest"],
            "attempt_id": req["attempt_id"], "reservation_id": req["reservation_id"],
            "ledger_store_id": req["ledger_store_id"], "authority_epoch": req["authority_epoch"],
            "consumer_acked_through": req["consumer_acked_through"] if fin_ack is None else fin_ack,
            "requested_at": W.timestamp(self.t),
        }
        fin_bytes, envelope = self.issuer.finalize(fin_req, grants=self.grants, signer=self.signer, now=self.tick())
        return permit, json.loads(fin_bytes), envelope

    def authorize(self, req: dict, permit: dict, fin: dict):
        expected = ExpectedBinding(D["rq"], D["ar"], 1, 1, "probe-ledger")
        self.consumer.authorize_dispatch(
            req["attempt_id"], permit, fin, self.tick(), verifier=self.verifier, gates=Gates(),
            revocations=Revocations(), issuer_id=ISSUER, expected=expected,
        )

    def begin(self, req: dict) -> None:
        self.consumer.create_attempt(req["attempt_id"], req["grant_id"], req["reservation_id"])
        self.consumer.mark_transmitted(req["attempt_id"])


results: list[dict] = []


def record(name: str, ok: bool, detail: str) -> None:
    results.append({"scenario": name, "ok": ok, "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + " :: " + detail)


def expect_refusal(world: World, req, permit, fin, rule: str, reason: str | None = None):
    try:
        world.authorize(req, permit, fin)
    except AuthorizationRefused as error:
        return error.rule == rule and (reason is None or error.reason == reason), f"{error.rule}:{error.reason}"
    return False, "authorized (expected a refusal)"


def main() -> int:
    w = World()
    # S1 happy path: issuer produces, consumer authorizes with REAL signature verification.
    req = w.request(ack=0)
    w.begin(req)
    permit, fin, env = w.issue(req)
    w.consumer.ingest_events(ISSUER, env["events"], w.verifier)
    w.authorize(req, permit, fin)
    record("S1 issuer->consumer happy path", sender_precondition(w.consumer, req["attempt_id"]),
           f"R_p={permit['revocation_version']} R_f={fin['revocation_version']} outbox complete")

    # S2 second grant on the same issuer chain, consumer has acknowledged the first event.
    ack = w.consumer.acked_through(ISSUER)
    req2 = w.request(ack=ack)
    w.begin(req2)
    p2, f2, e2 = w.issue(req2)
    w.consumer.ingest_events(ISSUER, e2["events"], w.verifier)
    w.authorize(req2, p2, f2)
    record("S2 chained second grant", fin["revocation_version"] + 1 == f2["revocation_version"], f"R_f={f2['revocation_version']}")

    # S3 tampered permit is refused on the signature, nothing recorded.
    req3 = w.request(ack=w.consumer.acked_through(ISSUER))
    w.begin(req3)
    p3, f3, e3 = w.issue(req3)
    w.consumer.ingest_events(ISSUER, e3["events"], w.verifier)
    tampered = {**p3, "expires_at": W.timestamp(NOW + timedelta(days=1))}
    ok, detail = expect_refusal(w, req3, tampered, f3, "rule1", "permit_signature")
    record("S3 tampered permit refused (real signature)", ok, detail)

    # S4 permit replay after a recorded authorization is refused.
    ok, detail = expect_refusal(w, req, permit, fin, "rule1")
    record("S4 replay of a recorded permit refused", ok, detail)

    # S5 fence first: the consumer's fence wins over a later authorization.
    req5 = w.request(ack=w.consumer.acked_through(ISSUER))
    w.begin(req5)
    p5, f5, e5 = w.issue(req5)
    w.consumer.ingest_events(ISSUER, e5["events"], w.verifier)
    w.consumer.fence(req5["attempt_id"])
    ok, detail = expect_refusal(w, req5, p5, f5, "rule6", "attempt_fenced")
    record("S5 fenced attempt refused", ok, detail)

    # S7 a validly signed permit and finalization for ANOTHER ledger is refused by the consumer.
    req7 = w.request(ack=w.consumer.acked_through(ISSUER), ledger="other-ledger")
    w.begin(req7)
    p7, f7, e7 = w.issue(req7)
    w.consumer.ingest_events(ISSUER, e7["events"], w.verifier)
    ok, detail = expect_refusal(w, req7, p7, f7, "rule1", "permit_binding")
    record("S7 permit for another ledger refused (real signature)", ok, detail)

    # S6 THE HEADLINE CASE: a clean issuer rollback after the consumer already acknowledged later events.
    snapshot = w.root / "issuer-snapshot.db"
    shutil.copy2(w.issuer_path, snapshot)                      # issuer state at counter C
    snap_counter = w.issuer.current_counter()
    req6a = w.request(ack=w.consumer.acked_through(ISSUER))     # grant that will be LOST by the rollback
    w.begin(req6a)
    p6a, f6a, e6a = w.issue(req6a)
    w.consumer.ingest_events(ISSUER, e6a["events"], w.verifier)  # consumer acknowledges the soon-lost events
    acked_before = w.consumer.acked_through(ISSUER)
    w.issuer.close()
    for suffix in ("", "-wal", "-shm"):                         # clean restore of the older snapshot
        target = Path(str(w.issuer_path) + suffix)
        if target.exists():
            target.unlink()
    shutil.copy2(snapshot, w.issuer_path)
    w.issuer = SqliteDispatchPermitStore(w.issuer_path)
    restored = w.issuer.current_counter()
    req6 = w.request(ack=snap_counter)                           # request sent with the consumer's STALE ack
    w.begin(req6)
    p6, f6, e6 = w.issue(req6)                                   # the restored issuer finalizes: same R_f, new digest
    ok, detail = expect_refusal(w, req6, p6, f6, "rule5")
    record("S6 clean issuer rollback detected (fork)", ok and restored == snap_counter and acked_before > restored,
           f"issuer counter {acked_before}->{restored}, refusal {detail}")

    receipt = {
        "phylax_head": subprocess.run(["git", "-C", str(PHYLAX), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip(),
        "oramasys_head": subprocess.run(["git", "-C", str(ORAMASYS), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip(),
        "vector_sha256": hashlib.sha256((PHYLAX / "docs/vectors/dispatch-permit-v1.json").read_bytes()).hexdigest(),
        "results": results, "all_ok": all(item["ok"] for item in results),
    }
    print(json.dumps(receipt, indent=2))
    shutil.rmtree(w.root, ignore_errors=True)
    return 0 if receipt["all_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
