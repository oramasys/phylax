"""Execute the CI parity gate against equal, missing and one-sided changed probe copies."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from textwrap import dedent

import pytest


ROOT = Path(__file__).resolve().parents[2]
PROBES = ("c2_interop_probe.py", "c2_slice2_probe.py")
PROBE_PIN = "src/tests/interop/oramasys-slice2-probe-pin.txt"


def step_command(name: str) -> str:
    """Read a named step's scalar or literal-block shell command, not a duplicate of its logic."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    match = re.search(
        rf"^      - name: {re.escape(name)}\n(?:        id: [^\n]+\n)?        run: ([^\n]+)"
        r"((?:\n          [^\n]*)*)",
        workflow, re.MULTILINE,
    )
    assert match is not None, f"CI step {name!r} must have an executable run command"
    return dedent(match[2]).strip() if match[1] == "|" else match[1]


@pytest.mark.parametrize("probe", PROBES)
@pytest.mark.parametrize("side", ["local", "peer"])
@pytest.mark.parametrize("change", ["none", "mutated", "missing"])
def test_ci_parity_gate_rejects_one_sided_probe_changes(tmp_path, probe, side, change) -> None:
    """Removing either comparison lets a one-sided mutation through and fails this regression."""
    copies = {}
    for name in PROBES:
        peer = "oramasys-pinned" if name == "c2_interop_probe.py" else "oramasys-probe-pinned"
        for label, root in (("local", tmp_path), ("peer", tmp_path / peer)):
            target = root / "src" / "tests" / "interop" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / "src" / "tests" / "interop" / name).read_bytes())
            copies[label, name] = target
    target = copies[side, probe]
    if change == "mutated":
        target.write_bytes(target.read_bytes() + b"\n# one-sided mutation\n")
    elif change == "missing":
        target.unlink()
    result = subprocess.run(
        ["bash", "-e", "-c", step_command("Probe copies must be byte-identical")],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == (0 if change == "none" else 1 if change == "mutated" else 2), (
        result.stdout + result.stderr
    )


@pytest.mark.parametrize("pin", [None, "", "main", "g" * 40, "a" * 39])
def test_probe_source_pin_is_validated_and_separate_from_runtime_pin(tmp_path, pin) -> None:
    """CI reads the real probe pin, rejects mutable/malformed refs, and wires only its copy checkout."""
    target = tmp_path / PROBE_PIN
    target.parent.mkdir(parents=True)
    source = (ROOT / PROBE_PIN).read_text()
    assert re.fullmatch(r"[0-9a-f]{40}\n", source)
    target.write_text(source if pin is None else pin)
    runtime_pin = "src/tests/interop/oramasys-permit-pin.txt"
    (tmp_path / runtime_pin).write_text((ROOT / runtime_pin).read_text())
    output = tmp_path / "github-output"
    result = subprocess.run(
        ["bash", "-e", "-c", step_command("Read the probe-only Oramasys commit")],
        cwd=tmp_path, env={**os.environ, "GITHUB_OUTPUT": str(output)},
        capture_output=True, text=True,
    )
    if pin is None:
        assert result.returncode == 0, result.stderr
        assert output.read_text() == f"commit={source.strip()}\n"
    else:
        assert result.returncode != 0
        assert not output.exists()
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    checkout = workflow.split("      - name: Check out the probe-only Oramasys source\n", 1)[1]
    checkout = checkout.split("      - ", 1)[0]
    assert "          ref: ${{ steps.probe-pin.outputs.commit }}\n" in checkout
    assert "          repository: oramasys/oramasys\n" in checkout
    assert "          path: oramasys-probe-pinned\n" in checkout
    assert "          persist-credentials: false\n" in checkout
