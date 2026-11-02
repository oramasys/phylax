"""Cross-platform file locking and durability primitives for Phylax publication and retention.

POSIX uses only the standard library (``fcntl.flock``, ``os.fsync``).  Windows requires
``pywin32``; it is imported eagerly inside the Windows branch, so a missing dependency is an
``ImportError`` at import time and the module is refused rather than degraded.  There is no
fallback, no no-op lock, and no best-effort path: every primitive either does what it says or
raises.

Lock semantics (shared by both platforms except where noted)
    * Both platforms exclude a second open file description / handle on the same file, including
      one in the same process.
    * ``blocking=False`` raises ``BlockingIOError`` when the lock is held elsewhere.
    * The lock is released by ``unlock``, by closing the file, or by the kernel when the holder
      process dies (including being killed).
    * DIFFERENCE, same handle: POSIX ``flock`` converts a lock the handle already holds; Windows
      does not.  Locking the same handle twice with ``blocking=True`` deadlocks on Windows, and
      with ``blocking=False`` raises ``BlockingIOError``.  This is deliberately not emulated;
      call sites must never relock a handle they already hold.
    * ``unlock`` on a handle holding no lock is a silent no-op on both platforms.
    * DIFFERENCE, deletion: on Windows a held lock file cannot be deleted or renamed, which is
      stronger than POSIX unlink-and-recreate.  Do not rely on removing a lock file to break a lock.
    * Convention kept by all callers: lock a sibling lock file, never the data file itself,
      because Windows byte-range locks also block reads and writes of the locked range.
    * Windows locks the whole file range with ``LockFileEx``.  This overlaps byte 0, so it
      conflicts correctly with the 1-byte ``msvcrt.locking`` lock at offset 0 used by other fleet
      tooling (orama-system ``discovery_trust``).  Same model, but ``LockFileEx`` is used here
      because it supports shared locks and true blocking waits, which ``msvcrt.locking`` lacks.

Durability caveats
    * POSIX ``fsync_dir`` makes a completed rename or create durable on mainstream filesystems.
    * On NTFS, ``FlushFileBuffers`` on a directory handle flushes that directory's metadata, but
      Microsoft does not document a directory-durability guarantee comparable to POSIX.  Opening
      a directory for flushing needs write access to it; where Windows denies that, a typed
      ``DirectoryFsyncError`` is raised instead of silently skipping.  ``replace_durably`` on
      Windows relies on ``MOVEFILE_WRITE_THROUGH`` (which returns only after the move is flushed)
      and additionally flushes parent directories via ``fsync_dir`` (once when in the same
      directory, and both parent directories when replacing across different directories).
"""

from __future__ import annotations

import errno
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, Iterator, Union

__all__ = [
    "DirectoryFsyncError",
    "check_private",
    "exclusive_lock",
    "fsync_dir",
    "locked",
    "replace_durably",
    "shared_lock",
    "unlock",
]

IS_WINDOWS = sys.platform == "win32"

LockTarget = Union[int, IO[Any]]


class DirectoryFsyncError(OSError):
    """A directory could not be flushed to stable storage; the caller must not assume durability."""


def _fileno(target: LockTarget) -> int:
    """Return the OS file descriptor for a file object or a raw descriptor."""
    if isinstance(target, int):
        return target
    return target.fileno()


if IS_WINDOWS:
    import msvcrt

    import pywintypes
    import win32con
    import win32file
    import winerror

    _ALL_BYTES = 0xFFFFFFFF
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    def _handle(target: LockTarget) -> int:
        """Return the Win32 handle behind a descriptor or file object."""
        return msvcrt.get_osfhandle(_fileno(target))

    def _lock(target: LockTarget, *, exclusive: bool, blocking: bool) -> None:
        """Lock the whole file with LockFileEx, translating contention to BlockingIOError."""
        flags = 0
        if exclusive:
            flags |= win32con.LOCKFILE_EXCLUSIVE_LOCK
        if not blocking:
            flags |= win32con.LOCKFILE_FAIL_IMMEDIATELY
        try:
            win32file.LockFileEx(
                _handle(target), flags, _ALL_BYTES, _ALL_BYTES, pywintypes.OVERLAPPED()
            )
        except pywintypes.error as error:
            if error.winerror in (winerror.ERROR_LOCK_VIOLATION, winerror.ERROR_IO_PENDING):
                raise BlockingIOError(errno.EAGAIN, "file lock is held elsewhere") from error
            raise OSError(errno.EIO, f"LockFileEx failed: {error.strerror}") from error

    def unlock(target: LockTarget) -> None:
        """Release the lock taken by ``exclusive_lock`` or ``shared_lock`` on this handle."""
        try:
            win32file.UnlockFileEx(
                _handle(target), _ALL_BYTES, _ALL_BYTES, pywintypes.OVERLAPPED()
            )
        except pywintypes.error as error:
            if error.winerror == winerror.ERROR_NOT_LOCKED:
                return
            raise OSError(errno.EIO, f"UnlockFileEx failed: {error.strerror}") from error

    def fsync_dir(path: str | os.PathLike[str]) -> None:
        """Flush a directory handle with FlushFileBuffers; raise ``DirectoryFsyncError`` on failure.

        Errors carry ENOENT (missing), ENOTDIR (a file path), EACCES (denied) or EIO.
        """
        try:
            handle = win32file.CreateFile(
                os.fspath(path),
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                _FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        except pywintypes.error as error:
            code = {
                winerror.ERROR_ACCESS_DENIED: errno.EACCES,
                winerror.ERROR_FILE_NOT_FOUND: errno.ENOENT,
                winerror.ERROR_PATH_NOT_FOUND: errno.ENOENT,
                winerror.ERROR_DIRECTORY: errno.ENOTDIR,
            }.get(error.winerror, errno.EIO)
            raise DirectoryFsyncError(
                code,
                f"cannot open directory for flush: {error.strerror}",
                os.fspath(path),
            ) from error
        try:
            if not win32file.GetFileInformationByHandle(handle)[0] & win32con.FILE_ATTRIBUTE_DIRECTORY:
                raise DirectoryFsyncError(errno.ENOTDIR, "not a directory", os.fspath(path))
            win32file.FlushFileBuffers(handle)
        except pywintypes.error as error:
            raise DirectoryFsyncError(
                errno.EIO, f"FlushFileBuffers on directory failed: {error.strerror}", os.fspath(path)
            ) from error
        finally:
            handle.Close()

    def replace_durably(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        """Atomically replace ``dst`` with ``src`` using MoveFileEx with write-through and directory fsync.

        Intra-directory replacements rely on ``MOVEFILE_WRITE_THROUGH`` to ensure moved data is flushed
        to disk and also flush the destination parent directory via ``fsync_dir``.  When ``src`` and
        ``dst`` reside in different parent directories, both parent directories are flushed.  Note that
        NTFS directory buffer flushing via ``FlushFileBuffers`` requires write access to the directory
        and does not carry POSIX-equivalent durability guarantees, but flushes cached metadata where
        permitted.
        """
        try:
            win32file.MoveFileEx(
                os.fspath(src),
                os.fspath(dst),
                win32file.MOVEFILE_REPLACE_EXISTING | win32file.MOVEFILE_WRITE_THROUGH,
            )
        except pywintypes.error as error:
            # Same exception family as os.replace so callers need no new handling.
            raise OSError(None, error.strerror, os.fspath(src), error.winerror, os.fspath(dst)) from error
        _flush_parents_after_replace(src, dst)

else:
    import fcntl

    def _lock(target: LockTarget, *, exclusive: bool, blocking: bool) -> None:
        """Take ``fcntl.flock``; contention without ``blocking`` raises BlockingIOError."""
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not blocking:
            mode |= fcntl.LOCK_NB
        fcntl.flock(_fileno(target), mode)

    def unlock(target: LockTarget) -> None:
        """Release the ``flock`` held on this open file description."""
        fcntl.flock(_fileno(target), fcntl.LOCK_UN)

    def fsync_dir(path: str | os.PathLike[str]) -> None:
        """Open the directory O_RDONLY|O_DIRECTORY and fsync it."""
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def replace_durably(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        """Atomically replace ``dst`` with ``src`` then fsync parent directories.

        When ``src`` and ``dst`` share the same parent directory, it is flushed once.
        When replacing across different parent directories, both parent directories are flushed.
        """
        os.replace(src, dst)
        _flush_parents_after_replace(src, dst)



def _flush_parents_after_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
    """Flush destination directory, and also source directory when they differ."""
    src_parent = Path(src).parent
    dst_parent = Path(dst).parent
    try:
        same_dir = src_parent.resolve() == dst_parent.resolve()
    except (OSError, RuntimeError):
        same_dir = src_parent == dst_parent
    fsync_dir(dst_parent)
    if not same_dir:
        fsync_dir(src_parent)

def exclusive_lock(target: LockTarget, *, blocking: bool = True) -> None:
    """Take an exclusive lock on a file object or descriptor; BlockingIOError if busy and non-blocking."""
    _lock(target, exclusive=True, blocking=blocking)


def shared_lock(target: LockTarget, *, blocking: bool = True) -> None:
    """Take a shared lock on a file object or descriptor; BlockingIOError if busy and non-blocking."""
    _lock(target, exclusive=False, blocking=blocking)


@contextmanager
def locked(
    path_or_target: str | os.PathLike[str] | LockTarget,
    *,
    exclusive: bool = True,
    blocking: bool = True,
) -> Iterator[IO[Any] | int]:
    """Lock a path (opened ``a+b`` and closed on exit) or an already open target for the block."""
    owned = isinstance(path_or_target, (str, os.PathLike))
    target: Any = open(path_or_target, "a+b") if owned else path_or_target
    try:
        _lock(target, exclusive=exclusive, blocking=blocking)
        try:
            yield target
        finally:
            unlock(target)
    finally:
        if owned:
            target.close()


def check_private(path: str | os.PathLike[str], file_class: str) -> None:
    """TODO: validate private-file ownership and ACLs per the H09 design table; not implemented.

    The Windows contract (protected DACL, owner SID equals token SID, class allowlist, reparse
    refusal, link count 1) needs reviewed ACL code and real tests that are out of this pass.  It
    raises rather than returning, so no caller can mistake a missing check for a passed one.
    """
    raise NotImplementedError("check_private is not implemented; see H09-SERVING-DESIGN.md section 2")
