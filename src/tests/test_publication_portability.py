"""Publication and retention portability and cross-process locking regressions."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from phylax import dispatch_retention, platform_fs, revocation_publication


def test_imports_do_not_require_fcntl_after_platform_initialization() -> None:
    """Callers import when the platform implementation has no fcntl module."""
    script = """
import builtins
import sys
sys.path.insert(0, sys.argv[1])
import phylax.platform_fs
real_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name == 'fcntl':
        raise ImportError('fcntl unavailable')
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded
import phylax.dispatch_retention
import phylax.revocation_publication
"""
    src = str(Path(platform_fs.__file__).resolve().parents[1])
    result = subprocess.run([sys.executable, "-c", script, src], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("kind", ["publication", "retention"])
def test_caller_lock_excludes_other_process(tmp_path: Path, kind: str) -> None:
    """Each caller holds its sibling lock against another process until released."""
    medium = revocation_publication.DirectoryMedium(tmp_path)
    ledger = dispatch_retention.RetentionLedger(tmp_path / "ledger.db")
    context = medium._locked() if kind == "publication" else dispatch_retention._retention_lock(ledger)
    path = tmp_path / (".publish.lock" if kind == "publication" else "ledger.db.lock")
    script = """
import sys
sys.path.insert(0, sys.argv[2])
from phylax.platform_fs import locked
try:
    with locked(sys.argv[1], blocking=False):
        pass
except BlockingIOError:
    sys.exit(7)
"""
    command = [sys.executable, "-c", script, str(path), str(Path(platform_fs.__file__).resolve().parents[1])]
    with context:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert result.returncode == 7, result.stderr
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_publication_propagates_directory_flush_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed directory flush never reports an immutable rewrite as durable."""
    medium = revocation_publication.DirectoryMedium(tmp_path)
    medium.put("segment", b"data")
    def fail(path: str | Path) -> None:
        """Represent a refused platform directory flush."""
        raise platform_fs.DirectoryFsyncError("flush failed")
    monkeypatch.setattr(platform_fs, "fsync_dir", fail)
    with pytest.raises(platform_fs.DirectoryFsyncError):
        medium.put("segment", b"data")


@pytest.mark.parametrize("name", [
    r"..\outside", r"folder\outside", r"C:outside", r"C:\outside",
    r"\\server\share\outside", r"\outside", "/outside", "../outside", ".", "..",
    "state.json:stream", "", "NUL", "con", "PRN.txt", "COM1", "lpt1.log",
    "COM1.txt", "CONIN$", "CONOUT$", "state.json.", "state.json ",
])
def test_publication_rejects_windows_path_names(tmp_path: Path, name: str) -> None:
    """Publication names cannot address files through Windows path syntax."""
    medium = revocation_publication.DirectoryMedium(tmp_path)
    with pytest.raises(ValueError):
        medium.put(name, b"data")
    assert medium.get(name) is None
