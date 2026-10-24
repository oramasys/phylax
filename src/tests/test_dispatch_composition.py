"""Narrow trusted-key-custody coverage for the frozen dispatch signer port."""

from __future__ import annotations

import json
from pathlib import Path

from nacl.bindings import crypto_sign_seed_keypair

import pytest

from phylax import dispatch_wire
from phylax.adjustment_grant import PhylaxGrantAuthority, RotatingIssuerKeyring
from phylax.dispatch_composition import DispatchIssuerSigner
from phylax.grant_store import SqliteGrantAuthorityStore
from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority

_SEED = b"D" * 32
_KEY_ID = "issuer-1"


class _Seeds:
    """Fixed private seed source for a narrow adapter test."""

    def load_seed(self, seed_ref: str) -> bytes:
        """Return the test seed only for the expected opaque reference."""
        if seed_ref != _KEY_ID:
            raise ValueError("unexpected seed reference")
        return _SEED


def _signer(tmp_path: Path) -> DispatchIssuerSigner:
    """Create the public authority adapter over a registry with one active key."""
    keyring = RotatingIssuerKeyring(
        key_id=_KEY_ID,
        seed_ref=_KEY_ID,
        seed_provider=_Seeds(),
        store=SqliteGrantAuthorityStore(tmp_path / "grants.sqlite3"),
    )
    authority = PhylaxGrantAuthority(
        keyring=keyring,
        p5_approval=P5ApprovalAuthority(
            signing_key=b"P" * 32,
            store=InMemoryP5ApprovalStore(),
        ),
    )
    return authority.dispatch_signer_adapter()


def _vectors() -> dict[str, object]:
    """Load the frozen dispatch bodies rather than duplicate a wire shape in this test."""
    path = Path(__file__).parents[2] / "docs" / "vectors" / "dispatch-permit-v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_dispatch_signer_uses_only_the_frozen_dispatch_domains(tmp_path: Path) -> None:
    """One custody adapter signs valid permit/finalization/event bytes in distinct domains."""
    signer = _signer(tmp_path)
    vectors = _vectors()
    permit = vectors["permit"]["body"]
    finalization = vectors["finalization"]["body"]
    event_digest = "a" * 64
    public_key, _private = crypto_sign_seed_keypair(_SEED)

    key_id = signer.active_key_id()
    permit_signature = signer.sign_permit(key_id, permit)
    finalization_signature = signer.sign_finalization(key_id, finalization)
    event_signature = signer.sign_event(key_id, event_digest)

    assert dispatch_wire.verify_permit(public_key, permit, permit_signature)
    assert dispatch_wire.verify_finalization(public_key, finalization, finalization_signature)
    assert dispatch_wire.verify_event(public_key, event_digest, event_signature)
    assert not dispatch_wire.verify_event(public_key, event_digest, permit_signature)


def test_dispatch_signer_refuses_a_stale_or_substituted_key_id(tmp_path: Path) -> None:
    """A caller cannot select a different durable key generation for a dispatch signature."""
    signer = _signer(tmp_path)
    permit = _vectors()["permit"]["body"]

    with pytest.raises(ValueError, match="not the active issuer key"):
        signer.sign_permit("other-issuer", permit)
