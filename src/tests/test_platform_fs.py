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
    "sys.path.insert(0, sys.argv[1])\n"
    "from phylax import platform_fs as fs\n"
    "f = open(sys.argv[2], 'a+b')\n"
    "(fs.exclusive_lock if sys.argv[3] == 'x' else fs.shared_lock)(f)\n"
    "print('held', flush=True)\n"
    "sys.stdin.readline()\n"
)


def _spawn(path: Path, exclusive: bool) -> subprocess.Popen[str]:
    """Start a child that holds a lock until its stdin yields a line; wait until it holds it."""
    src = str(Path(fs.__file__).resolve().parents[1])
    child = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, src, str(path), "x" if exclusive else "s"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    assert child.stdout is not None and child.stdout.readline().strip() == "held"
    return child


def _release(child: subprocess.Popen[str]) -> None:
    """Let the child exit cleanly."""
    assert child.stdin is not None
    child.stdin.write("\n")
    child.stdin.flush()
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
    timer = threading.Timer(0.5, lambda: _release(child))
    timer.start()
    start = time.monotonic()
    with fs.locked(lock):
        assert time.monotonic() - start >= 0.3
    timer.join()


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
    seen: set[bytes] = set()

    def reader() -> None:
        """Poll the destination, tolerating transient Windows sharing errors."""
        while not stop.is_set():
            try:
                seen.add(dst.read_bytes())
            except PermissionError:
                pass

    thread = threading.Thread(target=reader)
    thread.start()
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
        thread.join()
    assert seen <= {old, new}
    assert dst.read_bytes() == old
    assert not (tmp_path / "t0").exists()


def test_check_private_is_an_explicit_stub(tmp_path: Path) -> None:
    """The unimplemented ACL check raises instead of passing."""
    with pytest.raises(NotImplementedError):
        fs.check_private(tmp_path, "SECRET")
