"""Real-process tests for the platform locking and durability primitives."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from phylax import platform_fs as fs

_HOLDER = (
    "import sys\n"
    "from pathlib import Path\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from phylax import platform_fs as fs\n"
    "f = open(sys.argv[2], 'a+b')\n"
    "(fs.exclusive_lock if sys.argv[3] == 'x' else fs.shared_lock)(f)\n"
    "Path(sys.argv[4]).write_text('held')\n"
    "print('held', flush=True)\n"
    "sys.stdin.readline()\n"
)

_BLOCKER = (
    "import sys\n"
    "from pathlib import Path\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from phylax import platform_fs as fs\n"
    "Path(sys.argv[3]).write_text('attempting')\n"
    "with fs.locked(sys.argv[2]):\n"
    "    Path(sys.argv[3]).write_text('acquired')\n"
)


def _spawn(path: Path, exclusive: bool, *, timeout: float = 10.0) -> subprocess.Popen[str]:
    """Start a child that holds a lock until its stdin yields a line; wait with a deadline until it holds it."""
    src = str(Path(fs.__file__).resolve().parents[1])
    marker = path.parent / f"{path.stem}_{time.monotonic_ns()}.ready"
    if marker.exists():
        marker.unlink()
    child = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, src, str(path), "x" if exclusive else "s", str(marker)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker.exists():
            try:
                marker.unlink()
            except OSError:
                pass
            return child
        if child.poll() is not None:
            raise RuntimeError(f"child process exited prematurely with code {child.returncode}")
        time.sleep(0.02)
    child.kill()
    child.wait(timeout=5)
    raise TimeoutError(f"child did not acquire lock within {timeout}s deadline")


def _release(child: subprocess.Popen[str]) -> None:
    """Let the child exit cleanly."""
    assert child.stdin is not None
    try:
        child.stdin.write("\n")
        child.stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    child.wait(timeout=10)


def _try(path: Path, *, exclusive: bool) -> None:
    """Attempt a non-blocking lock on a fresh handle and release it."""
    with open(path, "a+b") as handle:
        (fs.exclusive_lock if exclusive else fs.shared_lock)(handle, blocking=False)
        fs.unlock(handle)


def test_exclusive_contention_across_processes(tmp_path: Path) -> None:
    """A child's exclusive lock blocks the parent until the child releases."""
    lock = tmp_path / "x.lock"
    child = _spawn(lock, True)
    try:
        with pytest.raises(BlockingIOError):
            _try(lock, exclusive=True)
        with pytest.raises(BlockingIOError):
            _try(lock, exclusive=False)
    finally:
        _release(child)
    _try(lock, exclusive=True)


def test_shared_locks_coexist_but_exclude_exclusive(tmp_path: Path) -> None:
    """Shared holders admit shared lockers and refuse exclusive ones."""
    lock = tmp_path / "s.lock"
    child = _spawn(lock, False)
    try:
        _try(lock, exclusive=False)
        with pytest.raises(BlockingIOError):
            _try(lock, exclusive=True)
    finally:
        _release(child)
    _try(lock, exclusive=True)


def test_lock_released_when_holder_is_killed(tmp_path: Path) -> None:
    """The kernel releases the lock when the holding process is killed."""
    lock = tmp_path / "k.lock"
    child = _spawn(lock, True)
    with pytest.raises(BlockingIOError):
        _try(lock, exclusive=True)
    child.kill()
    child.wait(timeout=10)
    deadline = time.monotonic() + 5
    while True:
        try:
            _try(lock, exclusive=True)
            break
        except BlockingIOError:
            assert time.monotonic() < deadline
            time.sleep(0.05)


def test_lock_released_on_close(tmp_path: Path) -> None:
    """Closing the handle releases the lock without an explicit unlock."""
    lock = tmp_path / "c.lock"
    first = open(lock, "a+b")
    fs.exclusive_lock(first)
    with pytest.raises(BlockingIOError):
        _try(lock, exclusive=True)
    first.close()
    _try(lock, exclusive=True)


def test_locked_context_manager_and_descriptor_target(tmp_path: Path) -> None:
    """``locked`` locks for the block only and accepts a raw descriptor."""
    lock = tmp_path / "m.lock"
    with fs.locked(lock):
        with pytest.raises(BlockingIOError):
            with fs.locked(lock, blocking=False):
                pass
    with fs.locked(lock, blocking=False):
        pass
    descriptor = os.open(lock, os.O_RDWR | getattr(os, "O_BINARY", 0))
    try:
        fs.exclusive_lock(descriptor, blocking=False)
        with pytest.raises(BlockingIOError):
            _try(lock, exclusive=True)
        fs.unlock(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.skipif(sys.platform != "win32", reason="POSIX flock converts a same-handle relock")
def test_same_handle_nonblocking_relock_raises_on_windows(tmp_path: Path) -> None:
    """Windows does not convert a held lock: a same-handle relock is refused, never granted."""
    with open(tmp_path / "r.lock", "a+b") as handle:
        fs.exclusive_lock(handle)
        with pytest.raises(BlockingIOError):
            fs.exclusive_lock(handle, blocking=False)
        fs.unlock(handle)


def test_unlock_without_lock_is_a_noop(tmp_path: Path) -> None:
    """Unlocking a handle that holds nothing does not raise."""
    with open(tmp_path / "n.lock", "a+b") as handle:
        fs.unlock(handle)


def test_fsync_dir_error_codes(tmp_path: Path) -> None:
    """A missing directory is ENOENT and a regular file is ENOTDIR (typed on Windows)."""
    import errno
    plain = tmp_path / "plain"
    plain.write_bytes(b"x")
    with pytest.raises(OSError) as missing:
        fs.fsync_dir(tmp_path / "nope")
    assert missing.value.errno == errno.ENOENT
    with pytest.raises(OSError) as notdir:
        fs.fsync_dir(plain)
    assert notdir.value.errno == errno.ENOTDIR
    if sys.platform == "win32":
        assert isinstance(missing.value, fs.DirectoryFsyncError)


def test_blocking_lock_waits_for_release(tmp_path: Path) -> None:
    """A blocking acquire returns only after the child releases."""
    lock = tmp_path / "b.lock"
    child = _spawn(lock, True)
    marker = tmp_path / "b.marker"
    src = str(Path(fs.__file__).resolve().parents[1])
    blocker = subprocess.Popen(
        [sys.executable, "-c", _BLOCKER, src, str(lock), str(marker)],
        text=True,
    )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if marker.exists():
            break
        if blocker.poll() is not None:
            pytest.fail(f"blocker exited prematurely with code {blocker.returncode}")
        time.sleep(0.02)
    else:
        blocker.kill()
        blocker.wait(timeout=5)
        _release(child)
        pytest.fail("blocker failed to start lock attempt within deadline")

    timer = threading.Timer(0.5, lambda: _release(child))
    timer.start()
    start = time.monotonic()
    try:
        blocker.wait(timeout=10)
    except subprocess.TimeoutExpired:
        blocker.kill()
        blocker.wait(timeout=5)
        pytest.fail("blocker timed out waiting for lock release")
    finally:
        timer.join(timeout=5)
        if blocker.poll() is None:
            blocker.kill()
            blocker.wait(timeout=5)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)

    elapsed = time.monotonic() - start
    assert blocker.returncode == 0
    assert elapsed >= 0.3
    assert marker.read_text().strip() == "acquired"


def test_fsync_dir_on_real_directory(tmp_path: Path) -> None:
    """Flushing a real directory succeeds; a missing one raises OSError."""
    (tmp_path / "f").write_bytes(b"x")
    fs.fsync_dir(tmp_path)
    with pytest.raises(OSError):
        fs.fsync_dir(tmp_path / "missing")


def test_replace_durably_is_atomic_for_readers(tmp_path: Path) -> None:
    """A concurrent reader only ever sees the whole old or whole new content."""
    dst = tmp_path / "state"
    old, new = b"old" * 1000, b"new" * 1000
    dst.write_bytes(old)
    stop = threading.Event()
    ready = threading.Event()
    seen: set[bytes] = set()
    successful_reads = 0

    def reader() -> None:
        """Poll the destination, tolerating transient Windows sharing errors."""
        nonlocal successful_reads
        ready.set()
        while not stop.is_set():
            try:
                data = dst.read_bytes()
                seen.add(data)
                successful_reads += 1
            except PermissionError:
                pass

    thread = threading.Thread(target=reader)
    thread.start()
    assert ready.wait(timeout=5), "reader thread did not signal ready in time"
    try:
        for index in range(50):
            tmp = tmp_path / f"t{index}"
            tmp.write_bytes(new if index % 2 == 0 else old)
            for _ in range(200):
                try:
                    fs.replace_durably(tmp, dst)
                    break
                except PermissionError:
                    time.sleep(0.01)
            else:
                raise AssertionError("replace kept failing")
    finally:
        stop.set()
        thread.join(timeout=10)
        assert not thread.is_alive(), "reader thread did not finish within deadline"
    assert successful_reads > 0, "no successful reads occurred during replacements"
    assert successful_reads >= 20, f"expected at least 20 successful reads, got {successful_reads}"
    assert seen <= {old, new}
    assert dst.read_bytes() == old
    assert not (tmp_path / "t0").exists()


def test_check_private_is_an_explicit_stub(tmp_path: Path) -> None:
    """The unimplemented ACL check raises instead of passing."""
    with pytest.raises(NotImplementedError):
        fs.check_private(tmp_path, "SECRET")



def test_replace_durably_flushes_parent_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Flushing reaches one parent when equal and both parents when cross-directory."""
    recorded: list[Path] = []

    def record_fsync_dir(path: str | os.PathLike[str]) -> None:
        """Record directory flush targets."""
        recorded.append(Path(path))

    monkeypatch.setattr(fs, "fsync_dir", record_fsync_dir)

    same_dir = tmp_path / "same"
    same_dir.mkdir()
    src_same = same_dir / "src.txt"
    dst_same = same_dir / "dst.txt"
    src_same.write_bytes(b"content-same")
    dst_same.write_bytes(b"old-same")

    del recorded[:]
    fs.replace_durably(src_same, dst_same)
    assert len(recorded) == 1
    assert recorded[0].resolve() == same_dir.resolve()

    dir_a = tmp_path / "dir_a"
    dir_b = tmp_path / "dir_b"
    dir_a.mkdir()
    dir_b.mkdir()
    src_cross = dir_a / "src.txt"
    dst_cross = dir_b / "dst.txt"
    src_cross.write_bytes(b"content-cross")
    dst_cross.write_bytes(b"old-cross")

    del recorded[:]
    fs.replace_durably(src_cross, dst_cross)
    assert len(recorded) == 2
    resolved_recorded = {p.resolve() for p in recorded}
    assert resolved_recorded == {dir_a.resolve(), dir_b.resolve()}
