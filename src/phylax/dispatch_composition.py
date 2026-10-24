"""Trusted key-custody adapter for the frozen E1/C2 dispatch signer port.

This adapter deliberately covers only the issuer-side signing port.  It does
not create grant facts, authenticate an operator, verify consumer events, or
open a serving path.  Those are separate composition boundaries.
"""

from __future__ import annotations

from collections.abc import Mapping

from .adjustment_grant import RotatingIssuerKeyring


class DispatchIssuerSigner:
    """Expose a keyring only through the frozen ``IssuerSigner`` operations.

    ``RotatingIssuerKeyring`` retains the seed and rechecks the durable active
    generation for each operation.  The adapter never returns private material
    and has no generic signing method, preserving the permit/finalization/event
    domain separation set by :mod:`phylax.dispatch_wire`.
    """

    def __init__(self, keyring: RotatingIssuerKeyring) -> None:
        """Bind this adapter to one durable issuer-key registry and custody source."""
        self._keyring = keyring

    def active_key_id(self) -> str:
        """Return the active dispatch key identifier after durable-state refresh."""
        return self._keyring.dispatch_active_key_id()

    def sign_permit(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign a dispatch permit only when ``key_id`` is the current active key."""
        return self._keyring.sign_dispatch_permit(key_id, body)

    def sign_finalization(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign a dispatch finalization only when ``key_id`` is the current active key."""
        return self._keyring.sign_dispatch_finalization(key_id, body)

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign an issuer event only when ``key_id`` is the current active key."""
        return self._keyring.sign_dispatch_event(key_id, digest)
