"""Narrow trusted-key-custody coverage for the frozen dispatch signer port."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from nacl.bindings import crypto_sign_seed_keypair

import pytest

from phylax import dispatch_wire
from phylax.adjustment_grant import PhylaxGrantAuthority, RotatingIssuerKeyring
from phylax.dispatch_composition import DispatchIssuerSigner
from phylax.grant_store import SqliteGrantAuthorityStore
from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority

_SEED = b"D" * 32
_KEY_ID = "issuer-1"
_NEXT_SEED = b"E" * 32
_NEXT_KEY_ID = "issuer-2"


class _Seeds:
    """Synthetic private seed source keyed by opaque reference."""

    def load_seed(self, seed_ref: str) -> bytes:
        """Return the synthetic seed only for a known opaque reference."""
        seeds = {_KEY_ID: _SEED, _NEXT_KEY_ID: _NEXT_SEED}
        if seed_ref not in seeds:
            raise ValueError("unexpected seed reference")
        return seeds[seed_ref]


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


def test_dispatch_signer_adopts_a_rotation_made_by_another_keyring(tmp_path: Path) -> None:
    """A stale worker refuses the retired id and signs all three domains with the new key."""
    store = SqliteGrantAuthorityStore(tmp_path / "grants.sqlite3")
    first = RotatingIssuerKeyring(
        key_id=_KEY_ID, seed_ref=_KEY_ID, seed_provider=_Seeds(), store=store
    )
    second = RotatingIssuerKeyring(
        key_id=_KEY_ID, seed_ref=_KEY_ID, seed_provider=_Seeds(), store=store
    )
    stale = DispatchIssuerSigner(second)
    assert stale.active_key_id() == _KEY_ID

    first.rotate(key_id=_NEXT_KEY_ID, seed_ref=_NEXT_KEY_ID, now=datetime.now(UTC))

    vectors = _vectors()
    permit = vectors["permit"]["body"]
    finalization = vectors["finalization"]["body"]
    digest = "a" * 64
    for refused in (
        lambda: stale.sign_permit(_KEY_ID, permit),
        lambda: stale.sign_finalization(_KEY_ID, finalization),
        lambda: stale.sign_event(_KEY_ID, digest),
    ):
        with pytest.raises(ValueError, match="not the active issuer key"):
            refused()

    public_key, _private = crypto_sign_seed_keypair(_NEXT_SEED)
    assert stale.active_key_id() == _NEXT_KEY_ID
    assert dispatch_wire.verify_permit(
        public_key, permit, stale.sign_permit(_NEXT_KEY_ID, permit)
    )
    assert dispatch_wire.verify_finalization(
        public_key, finalization, stale.sign_finalization(_NEXT_KEY_ID, finalization)
    )
    assert dispatch_wire.verify_event(public_key, digest, stale.sign_event(_NEXT_KEY_ID, digest))


def test_dispatch_signature_matches_its_key_id_when_rotation_lands_mid_call(tmp_path: Path) -> None:
    """A refresh between the id check and the seed read cannot pair an old id with a new seed.

    ``validate_key_id`` runs after the active key is captured.  The hook rotates the
    registry through a second keyring and refreshes this one there, which is exactly
    what a concurrent worker's ``ensure_current`` does.  The signature must still
    verify under the key id that was requested, never under the newly rotated key.
    """
    store = SqliteGrantAuthorityStore(tmp_path / "grants.sqlite3")
    rotating = RotatingIssuerKeyring(
        key_id=_KEY_ID, seed_ref=_KEY_ID, seed_provider=_Seeds(), store=store
    )
    worker = RotatingIssuerKeyring(
        key_id=_KEY_ID, seed_ref=_KEY_ID, seed_provider=_Seeds(), store=store
    )
    signer = DispatchIssuerSigner(worker)
    permit = _vectors()["permit"]["body"]
    real_validate = dispatch_wire.validate_key_id
    fired: list[bool] = []

    def rotate_midway(value: object) -> None:
        """Validate normally, then let another authority rotate and this one refresh once."""
        real_validate(value)
        if not fired:
            fired.append(True)
            rotating.rotate(key_id=_NEXT_KEY_ID, seed_ref=_NEXT_KEY_ID, now=datetime.now(UTC))
            worker.ensure_current()

    with mock.patch.object(dispatch_wire, "validate_key_id", rotate_midway):
        signature = signer.sign_permit(_KEY_ID, permit)

    assert fired
    old_public_key, _private = crypto_sign_seed_keypair(_SEED)
    assert dispatch_wire.verify_permit(old_public_key, permit, signature)
