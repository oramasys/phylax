"""Pinned hash verification for the C2 slice 2 cross-repository interop probe.

The SHA-256 literal is kept equal to the counterpart repository's literal;
never change the probe or either literal alone.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

EXPECTED_PROBE_SHA256 = "682129b1d1f359fa04548c75f2bb362f93648e5673bddb96390453d3b4d8d878"
PROBE_PATH = Path(__file__).resolve().parent / "interop" / "c2_slice2_probe.py"


def test_slice2_probe_exists_and_matches_pinned_sha256() -> None:
    """Verify that c2_slice2_probe.py exists and matches the pinned SHA-256 hash.

    The SHA-256 literal is kept equal to the counterpart repository's literal;
    never change the probe or either literal alone.
    """
    assert PROBE_PATH.is_file(), f"Probe file not found at {PROBE_PATH}"
    digest = hashlib.sha256(PROBE_PATH.read_bytes()).hexdigest()
    assert digest == EXPECTED_PROBE_SHA256, (
        f"Probe hash mismatch: expected {EXPECTED_PROBE_SHA256}, got {digest}"
    )
