"""Verifier-only surface: verify, revocation freshness, close; no issuer or seed path.

One read-only store (``grant_composition.open_verification_store``) backs both the v1
adjustment verifier and the v2 effect verifier. This module references no authority
store, seed provider, P5 authority or signing key, and constructs none. Denials leave it
only as the stable public ``deny.*`` vocabulary with a correlation id; internal reasons,
grant ids, key ids and paths never appear in the public form.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Callable, Final, Mapping

from .adjustment_grant import (
    GrantRefusal,
    GrantRefusalReason,
    GrantVerificationStore,
    PhylaxGrantVerifier,
    RevocationObservation,
    VerifiedGrant,
)
from .capability_record import EffectiveCapabilities, parse_capability_record
from .effect_grant import (
    EffectGrantRefusal,
    EffectGrantVerifier,
    VerifiedEffectGrant,
)
from .grant_composition import GrantVerifierConfig, open_verification_store
from .verifier_evidence import EvidenceLog, ExportOutcome, safe_export

REVOCATION_MAX_AGE_SECONDS: Final = 60  # ADR 71
REVOCATION_FUTURE_SKEW_SECONDS: Final = 5


class PublicDenial(StrEnum):
    """The stable public denial vocabulary (CONTRACT section 3)."""

    REVOCATION_STALE = "deny.revocation_stale"
    UNKNOWN_KEY = "deny.unknown_key"
    MALFORMED_GRANT = "deny.malformed_grant"
    REVOKED_GRANT = "deny.revoked_grant"
    MISSING_CAPABILITY_RECORD = "deny.missing_capability_record"
    UNAUTHORIZED_CALLER = "deny.unauthorized_caller"
    VERIFIER_UNAVAILABLE = "deny.verifier_unavailable"


_INTERNAL_TO_PUBLIC: Final[Mapping[str, PublicDenial]] = {
    "revocation.stale": PublicDenial.REVOCATION_STALE,
    "grant.key_unknown": PublicDenial.UNKNOWN_KEY,
    "grant.malformed": PublicDenial.MALFORMED_GRANT,
    "grant.schema_unsupported": PublicDenial.MALFORMED_GRANT,
    "grant.signature_invalid": PublicDenial.MALFORMED_GRANT,
    "grant.expired": PublicDenial.MALFORMED_GRANT,
    "grant.future_dated": PublicDenial.MALFORMED_GRANT,
    "grant.revoked": PublicDenial.REVOKED_GRANT,
    "verifier.unavailable": PublicDenial.VERIFIER_UNAVAILABLE,
}


def public_denial_for(reason: object) -> PublicDenial:
    """Map an internal refusal reason (enum or string) to its public code.

    Anything outside the closed mapping fails closed as ``deny.verifier_unavailable``.
    """
    key = str(getattr(reason, "value", reason))
    return _INTERNAL_TO_PUBLIC.get(key, PublicDenial.VERIFIER_UNAVAILABLE)


class VerifierDenied(Exception):
    """A redacted denial: only the public code and a correlation id are exposed."""

    def __init__(self, code: PublicDenial) -> None:
        """Keep construction limited to the closed public vocabulary."""
        if not isinstance(code, PublicDenial):
            raise ValueError("denial code is not in the public vocabulary")
        self.code = code
        self.correlation_id = str(uuid.uuid4())
        super().__init__(code.value)

    def body(self) -> dict[str, dict[str, str]]:
        """Return the response body ``{"error": {"code", "correlation_id"}}``."""
        return {"error": {"code": self.code.value, "correlation_id": self.correlation_id}}


def check_revocation_fresh(
    observation: RevocationObservation,
    now: datetime,
    *,
    max_age_seconds: int = REVOCATION_MAX_AGE_SECONDS,
    future_skew_seconds: int = REVOCATION_FUTURE_SKEW_SECONDS,
) -> None:
    """Raise ``GrantRefusal(REVOCATION_STALE)`` unless the observation is recent enough.

    Older than ``max_age_seconds``, from the future beyond ``future_skew_seconds``, or
    carrying a naive timestamp all refuse. Exactly the maximum age is still fresh.
    """
    observed = observation.observed_at
    if (
        not isinstance(observed, datetime)
        or observed.tzinfo is None
        or not isinstance(now, datetime)
        or now.tzinfo is None
    ):
        raise GrantRefusal(GrantRefusalReason.REVOCATION_STALE)
    age = now - observed
    if age > timedelta(seconds=max_age_seconds) or age < -timedelta(seconds=future_skew_seconds):
        raise GrantRefusal(GrantRefusalReason.REVOCATION_STALE)


class VerifierSurface:
    """The only consumer-facing verifier object; it holds no issuer capability."""

    def __init__(
        self,
        *,
        store: GrantVerificationStore,
        caller_check: Callable[[Any], bool],
        verifier_id: str = "phylax-primary",
        clock: Callable[[], datetime] | None = None,
        evidence_sink: Callable[[Mapping[str, object]], object] | None = None,
        expected_binary_digest: str | None = None,
        expected_config_digest: str | None = None,
    ) -> None:
        """Bind a read-only store and a mandatory caller authorizer (no default allow)."""
        if not callable(caller_check):
            raise ValueError("caller_check is required")
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._caller_check = caller_check
        self._v1 = PhylaxGrantVerifier(store=store, verifier_id=verifier_id, clock=self._clock)
        self._v2 = EffectGrantVerifier(store=store, verifier_id=verifier_id, clock=self._clock)
        self._digests = (expected_binary_digest, expected_config_digest)
        self._sink = evidence_sink
        self._evidence = EvidenceLog()

    # -- internals -----------------------------------------------------------------

    def _now(self) -> datetime:
        """Return the surface clock, refusing a broken or naive clock as unavailable."""
        try:
            now = self._clock()
            if not isinstance(now, datetime) or now.tzinfo is None:
                raise ValueError("clock")
            return now.astimezone(UTC)
        except Exception as exc:  # noqa: BLE001
            raise GrantRefusal(GrantRefusalReason.VERIFIER_UNAVAILABLE) from exc

    def _authorize(self, caller: object) -> None:
        """Require the injected check to return exactly ``True`` for ``caller``."""
        try:
            allowed = self._caller_check(caller)
        except Exception:  # noqa: BLE001 - an unusable authorizer denies
            allowed = False
        if allowed is not True:
            raise VerifierDenied(PublicDenial.UNAUTHORIZED_CALLER)

    def _note(self, scope: str, code: str) -> None:
        """Record evidence; a failure here can never change an outcome."""
        try:
            self._evidence.record(datetime.now(UTC), scope, code)
        except Exception:  # noqa: BLE001
            pass

    def _check_observation(self, observation: RevocationObservation | None) -> None:
        """Judge a caller-supplied observation for age and for a revoked verdict."""
        if observation is None:
            return
        check_revocation_fresh(observation, self._now())
        if observation.revoked:
            raise GrantRefusal(GrantRefusalReason.GRANT_REVOKED)

    def _run(self, scope: str, action: Callable[[], Any]) -> Any:
        """Execute ``action``, converting every failure to a redacted ``VerifierDenied``."""
        try:
            result = action()
        except VerifierDenied as denied:
            self._note(scope, denied.code.value)
            raise
        except (GrantRefusal, EffectGrantRefusal) as refusal:
            code = public_denial_for(refusal.reason)
            self._note(scope, code.value)
            raise VerifierDenied(code) from None
        except Exception:  # noqa: BLE001 - unknown failure is unavailability
            self._note(scope, PublicDenial.VERIFIER_UNAVAILABLE.value)
            raise VerifierDenied(PublicDenial.VERIFIER_UNAVAILABLE) from None
        self._note(scope, "ok")
        return result

    def _recheck_freshness(
        self, observation: RevocationObservation | None, started: datetime
    ) -> None:
        """Re-judge freshness after verification so a slow read cannot outlive its proof.

        A supplied observation is judged again against the clock now. With none, the live
        durable read must have finished within the maximum age since ``started``.
        """
        now = self._now()
        if observation is not None:
            check_revocation_fresh(observation, now)
        elif now - started > timedelta(seconds=REVOCATION_MAX_AGE_SECONDS):
            raise GrantRefusal(GrantRefusalReason.REVOCATION_STALE)

    @staticmethod
    def _match_observation(observation: RevocationObservation | None, grant_id: str) -> None:
        """An observation about another grant proves nothing about this one: stale."""
        if observation is not None and observation.grant_id != grant_id:
            raise GrantRefusal(GrantRefusalReason.REVOCATION_STALE)

    # -- public surface --------------------------------------------------------------

    def capabilities(self, record: object) -> EffectiveCapabilities:
        """Return effective capability bits for ``record`` (all false when invalid)."""
        return parse_capability_record(
            record,  # type: ignore[arg-type]
            expected_binary_digest=self._digests[0],
            expected_config_digest=self._digests[1],
        )

    def verify_adjustment(
        self, wire: bytes, *, caller: object, observation: RevocationObservation | None = None
    ) -> VerifiedGrant:
        """Verify a v1 adjustment grant; an optional observation must be fresh."""

        def action() -> VerifiedGrant:
            """Run the guarded action for this scope."""
            self._authorize(caller)
            self._check_observation(observation)
            started = self._now()
            verified = self._v1.verify(wire)
            self._match_observation(observation, verified.grant_id)
            self._recheck_freshness(observation, started)
            return verified

        return self._run("adjustment", action)  # type: ignore[no-any-return]

    def verify_effect(
        self,
        wire: bytes,
        *,
        caller: object,
        capability_record: object,
        observation: RevocationObservation | None = None,
    ) -> VerifiedEffectGrant:
        """Verify a v2 effect grant; denied unless a valid record enables ``effects``.

        With no valid capability record (or an ``effects`` bit that is false) the call is
        refused before the grant is even parsed.
        """

        def action() -> VerifiedEffectGrant:
            """Run the guarded action for this scope."""
            self._authorize(caller)
            caps = self.capabilities(capability_record)
            if not (caps.valid and caps.effects):
                raise VerifierDenied(PublicDenial.MISSING_CAPABILITY_RECORD)
            self._check_observation(observation)
            started = self._now()
            verified = self._v2.verify(wire)
            self._match_observation(observation, verified.grant_id)
            self._recheck_freshness(observation, started)
            return verified

        return self._run("effect", action)  # type: ignore[no-any-return]

    def revocation_freshness(
        self, grant_id: str, *, caller: object, observation: RevocationObservation | None = None
    ) -> RevocationObservation:
        """Return a fresh revocation observation, or deny as stale / unavailable.

        Without ``observation`` the durable index is read now (v1 and v2 share the one
        store, so the path is identical). A supplied observation must be about ``grant_id`` and is judged for age.
        The observation time is taken before the read and judged after it, so a read that
        stalls past 60 s is stale.
        """

        def action() -> RevocationObservation:
            """Run the guarded action for this scope."""
            self._authorize(caller)
            if not isinstance(grant_id, str) or not grant_id.strip():
                raise GrantRefusal(GrantRefusalReason.GRANT_MALFORMED)
            if observation is not None:
                self._match_observation(observation, grant_id)
                check_revocation_fresh(observation, self._now())
                return observation
            started = self._now()
            try:
                revoked = self._store.is_revoked(grant_id)
            except (sqlite3.Error, OSError) as exc:
                raise GrantRefusal(GrantRefusalReason.VERIFIER_UNAVAILABLE) from exc
            seen = RevocationObservation(grant_id, bool(revoked), started)
            check_revocation_fresh(seen, self._now())
            return seen

        return self._run("revocation", action)  # type: ignore[no-any-return]

    def export_evidence(self, start: datetime, end: datetime) -> ExportOutcome:
        """Send a redacted window summary to the sink; failure is reported, never raised."""
        return safe_export(self._evidence, self._sink, start, end)

    @property
    def export_failures(self) -> int:
        """Return how many evidence exports have failed (monitoring only)."""
        return self._evidence.export_failures

    def close(self) -> None:
        """Release the retained read-only connection; safe to call more than once."""
        close = getattr(self._store, "close", None)
        if callable(close):
            close()


def open_verifier_surface(
    config: GrantVerifierConfig,
    *,
    caller_check: Callable[[Any], bool],
    clock: Callable[[], datetime] | None = None,
    evidence_sink: Callable[[Mapping[str, object]], object] | None = None,
    expected_binary_digest: str | None = None,
    expected_config_digest: str | None = None,
) -> VerifierSurface:
    """Open the verifier-only surface read-only; it creates, migrates and seeds nothing."""
    store = open_verification_store(config)
    try:
        return VerifierSurface(
            store=store,
            caller_check=caller_check,
            verifier_id=config.verifier_id,
            clock=clock,
            evidence_sink=evidence_sink,
            expected_binary_digest=expected_binary_digest,
            expected_config_digest=expected_config_digest,
        )
    except BaseException:
        store.close()
        raise
