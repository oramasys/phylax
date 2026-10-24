"""Slice 2 interop probe: attested abandon, successor issuance and reservation-scope binding.

Run: python3 c2_slice2_probe.py <phylax-checkout> <oramasys-checkout>   (needs only PyNaCl)
Companion of c2_interop_probe.py (same folder, same arguments): it reuses that probe's real
Ed25519ph ports and then proves, against the real Phylax issuer store and the real Oramasys
consumer, that (A) a consumer abandon attestation is accepted by the issuer and its authenticated
outcome releases the attempt, a retry is idempotent and a successor records its predecessor, and
(B) a reservation is bound to the permit by content (operation and artifact digests).
The issuer-outcome authenticator here is a test stand-in that accepts only pairs the issuer
returned; the production authenticator is a serving prerequisite. Byte-identical in the Phylax
and Oramasys repositories; each repository's unit test pins the SHA-256 of this file.
Exit 0 only if every scenario holds.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("c2_interop_probe", HERE / "c2_interop_probe.py")
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)  # reads the same argv, sets sys.path, runs S1-S7

from orama.graph.dispatch_attempts import (  # noqa: E402
    IssuerOutcomeRefused, SqliteAttemptStore, VerifiedDispatchGrant,
)
from orama.graph.effect_proposals import EffectScope, ReservationRefused  # noqa: E402
from phylax import dispatch_wire as W  # noqa: E402
from phylax.dispatch_permit_store import GrantFacts, SqliteDispatchPermitStore  # noqa: E402

D, NOW, ISSUER = probe.D, probe.NOW, probe.ISSUER
results: list[bool] = []


def check(name: str, ok: bool, detail: str) -> None:
    """Record one scenario outcome and print it."""
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + " :: " + detail)


class ChannelAuthenticator:
    """Test stand-in: accepts only (outcome, record) pairs the issuer actually returned."""

    def __init__(self) -> None:
        """Start with no issuer responses noted."""
        self._seen: set[tuple[str, str]] = set()

    def received(self, outcome: str, record: dict) -> None:
        """Note a response obtained from the issuer."""
        self._seen.add((outcome, json.dumps(dict(record), sort_keys=True)))

    def verify(self, outcome: str, record) -> bool:
        """Return True only for a response noted by ``received``."""
        return (outcome, json.dumps(dict(record), sort_keys=True)) in self._seen


class Operator:
    """Operator port that always authorizes with a fixed reference."""

    def authorize(self, operation, *, attempt_id, grant_id):
        """Return the audit reference of the authorizing operator."""
        return "operator-ref-7"


def abandon_scenarios() -> None:
    """S8-S14: attested abandon, retry and successor, with the issuer and consumer stores."""
    world = probe.World()
    signer, grants = world.signer, world.grants
    auth = ChannelAuthenticator()
    issuer = world.issuer
    consumer = SqliteAttemptStore(world.root / "consumer" / "abandon.db", abandon_authenticator=auth)
    operator = Operator()
    req = world.request(ack=0)
    permit = json.loads(issuer.admit(req, grants=grants, signer=signer, now=NOW))
    consumer.create_attempt(
        req["attempt_id"], VerifiedDispatchGrant(req["grant_id"]), req["reservation_id"]
    )
    consumer.fence(req["attempt_id"])
    attestation = consumer.build_abandon_attestation(req["attempt_id"], permit["permit_id"], "loss", 1, NOW)
    try:
        W.validate_abandon_attestation(attestation)
        check("S8 consumer attestation passes the issuer's validator", True, "8 fields, cause=loss")
    except W.WireError as error:
        check("S8 consumer attestation passes the issuer's validator", False, str(error))
    outcome, record = issuer.abandon(attestation, operator=operator, now=NOW + timedelta(seconds=1))
    check("S9 issuer records the abandon", outcome == "abandon.recorded", outcome)
    check("S10 both sides compute the same attestation digest",
          record["attestation_digest"] == W.attestation_digest(attestation), record["attestation_digest"][:12])
    try:
        consumer.record_abandon_outcome(req["attempt_id"], outcome, record, NOW + timedelta(seconds=2))
        refused = False
    except IssuerOutcomeRefused:
        refused = True
    check("S11b outcome not received over the issuer channel is refused", refused, "fail closed")
    auth.received(outcome, record)
    consumer.record_abandon_outcome(req["attempt_id"], outcome, record, NOW + timedelta(seconds=2))
    stored = consumer.abandon_outcome(req["attempt_id"])
    check("S11 consumer records the authenticated outcome and authorizes release",
          stored is not None and stored["release_authorized"] == 1
          and consumer.get_attempt(req["attempt_id"]).state == "abandoned", "state=abandoned")
    again_outcome, again = issuer.abandon(attestation, operator=operator, now=NOW + timedelta(seconds=3))
    check("S12 an identical abandon retry returns the recorded outcome",
          again_outcome == "abandon.already_abandoned" and again == record, again_outcome)
    nxt = dict(req, attempt_id="attempt-successor", requested_at=W.timestamp(NOW + timedelta(seconds=4)))
    successor = json.loads(issuer.admit(nxt, grants=grants, signer=signer, now=NOW + timedelta(seconds=4)))
    check("S13 a new attempt is issued as a successor",
          successor["attempt_id"] == nxt["attempt_id"] and successor["permit_id"] != permit["permit_id"],
          successor["permit_id"][:14])
    row = issuer.lookup_attempt(nxt["attempt_id"], operator=operator)
    check("S14 the successor records its predecessor", row["replaces_permit_id"] == permit["permit_id"],
          "replaces_permit_id set")


SCOPE = EffectScope("principal-1", "graph-1", "a" * 64, D["rq"], D["ar"], "dest-1")


def scope_flow(world, label: str, reserved: EffectScope, presented: EffectScope):
    """Issue a real permit, reserve ``reserved``, then authorize presenting ``presented``."""
    req = world.request(ack=world.consumer.acked_through(ISSUER))
    world.consumer.create_attempt(
        req["attempt_id"], VerifiedDispatchGrant(req["grant_id"]), req["reservation_id"]
    )
    world.consumer.mark_transmitted(req["attempt_id"])
    world.consumer.propose(f"prop-{label}", reserved, world.tick())
    world.consumer.reserve(req["reservation_id"], f"prop-{label}", reserved,
                           world.t + timedelta(hours=1), world.t)
    permit, fin, env = world.issue(req)
    world.consumer.ingest_events(ISSUER, env["events"], world.verifier)
    expected = probe.ExpectedBinding(D["rq"], D["ar"], 1, 1, "probe-ledger")
    world.consumer.authorize_dispatch(
        req["attempt_id"], permit, fin, world.tick(), verifier=world.verifier, gates=probe.Gates(),
        revocations=probe.Revocations(), issuer_id=ISSUER, expected=expected, scope=presented,
    )
    return req, permit


def refusal_reason(world, label: str, reserved: EffectScope, presented: EffectScope) -> str:
    """Return the refusal reason, or a marker if the flow was wrongly authorized."""
    try:
        scope_flow(world, label, reserved, presented)
    except ReservationRefused as error:
        return error.reason
    return "AUTHORIZED (expected a refusal)"


def scope_scenarios() -> None:
    """L1-L5: the reservation scope is bound to the real signed permit by content."""
    world = probe.World()
    world.consumer = SqliteAttemptStore(world.root / "consumer" / "governed.db", governed=True)
    req, permit = scope_flow(world, "ok", SCOPE, SCOPE)
    check("L1 matching scope authorizes a real signed permit",
          world.consumer.outbox_row(req["attempt_id"]) is not None, f"request_digest={permit['request_digest'][:8]}")
    check("L2 the scope maps onto the permit's own digests",
          (SCOPE.operation_digest, SCOPE.artifact_identity) == (permit["request_digest"], permit["artifact_digest"]),
          "operation_digest==request_digest, artifact_identity==artifact_digest")
    other_op = replace(SCOPE, operation_digest="9" * 64)
    check("L3 reservation made for another operation is refused (real signature)",
          refusal_reason(world, "op", other_op, other_op) == "scope_not_bound_to_permit", "scope_not_bound_to_permit")
    other_art = replace(SCOPE, artifact_identity="8" * 64)
    check("L4 reservation made for another artifact is refused (real signature)",
          refusal_reason(world, "art", other_art, other_art) == "scope_not_bound_to_permit", "scope_not_bound_to_permit")
    check("L5 presenting a scope other than the reserved one is still refused",
          refusal_reason(world, "mix", SCOPE, other_op) == "scope_mismatch", "scope_mismatch")


abandon_scenarios()
scope_scenarios()
print(json.dumps({"all_ok": all(results)}))
sys.exit(0 if all(results) else 1)
