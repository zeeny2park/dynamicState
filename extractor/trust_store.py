"""Durable Trust Store, Process Identity, and Canonical Operation Identity.

Extracted from extractor.capture_backend for modular maintainability;
all public symbols remain re-exported from extractor.capture_backend.
"""

import contextlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import threading
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Union
import uuid

if TYPE_CHECKING:
    from .capture_backend import CaptureKeyStore, CausalAttestation

class TrustConsumptionStatus(str, Enum):
    """Explicit trust consumption outcomes distinguishing all verification and durability states."""
    NEW_ACCEPTANCE = "NEW_ACCEPTANCE"
    IDEMPOTENT_RECOVERY = "IDEMPOTENT_RECOVERY"
    REPLAY_CONFLICT = "REPLAY_CONFLICT"
    REVOKED = "REVOKED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    EXPIRED = "EXPIRED"
    PERSISTENCE_FAILURE = "PERSISTENCE_FAILURE"


@dataclass
class TrustConsumptionResult:
    """Structured result of an atomic trust-consumption operation."""
    status: TrustConsumptionStatus
    reason: str
    attestation_id: str
    key_id: str = ""
    evidence_id: str = ""
    recorded_at: str = ""

    @property
    def is_accepted(self) -> bool:
        """Returns True if the credential was legitimately accepted (new or idempotent same-evidence)."""
        return self.status in (
            TrustConsumptionStatus.NEW_ACCEPTANCE,
            TrustConsumptionStatus.IDEMPOTENT_RECOVERY,
        )


class DurableCommitOutcome(Enum):
    NOT_COMMITTED = "NOT_COMMITTED"
    COMMITTED = "COMMITTED"
    ALREADY_COMMITTED = "ALREADY_COMMITTED"
    NON_DURABLE = "NON_DURABLE"
    REJECTED = "REJECTED"
    COMMIT_UNKNOWN = "COMMIT_UNKNOWN"


class DurableCommitError(RuntimeError):
    def __init__(self, message: str, outcome: DurableCommitOutcome, cause: Optional[Exception] = None):
        super().__init__(message)
        self.outcome = outcome
        self.cause = cause


# ==============================================================================
# Operation Identity, Replay Defense & Lifecycle Trust Boundaries (Unit 1)
# ==============================================================================

class InvalidOperationIdError(ValueError):
    """Raised when an operation identifier fails whitelist validation or format constraints."""
    pass


class ProcessIdentityMismatchError(ValueError):
    """Raised when target Process Identity (host, boot_id, pid, process_start_time) mismatches."""
    pass


class ProcessIdentityUnavailableError(RuntimeError):
    """Raised when target process start time or kernel boot identity cannot be reliably resolved."""
    pass


class MissingIdentityFieldError(ValueError):
    """Raised when a mandatory identity field is missing, None, or empty."""
    pass


class IdentityConflictError(ValueError):
    """Raised when incoming identity metadata conflicts with previously established valid identity."""
    pass


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal or backward operation lifecycle transition is attempted."""
    pass


class LockTimeoutError(TimeoutError):
    """Raised when acquiring the trust store mutual exclusion lock times out."""
    pass


class SecurityViolationError(RuntimeError):
    """Raised when a filesystem security constraint (permissions, ownership, symlink) is violated."""
    pass


class ConflictAuditPersistenceError(RuntimeError):
    """Raised when persisting an identity conflict audit event to durable storage fails."""
    pass


class OperationLifecycleState(str, Enum):
    """Explicit operation lifecycle states with strict validated one-way transitions."""
    CREATED = "CREATED"
    VALIDATED = "VALIDATED"
    RESERVED = "RESERVED"
    EXECUTING = "EXECUTING"
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIAL = "PARTIAL"
    ABORTED_ON_RESTART = "ABORTED_ON_RESTART"


_OPERATION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}\Z")


def validate_operation_id(operation_id: Any) -> str:
    """Validate operation ID against strict whitelist with no silent trimming.
    
    Invariant: Length 1~128, whitelist ^[a-zA-Z0-9_.:-]+$, no None/empty/whitespace/unicode.
    """
    if not isinstance(operation_id, str):
        raise InvalidOperationIdError(f"Operation ID must be str, got {type(operation_id).__name__}")
    n = len(operation_id)
    if n < 1 or n > 128:
        raise InvalidOperationIdError(f"Operation ID length must be between 1 and 128, got {n}")
    if any(c in " \t\r\n\x0b\x0c" for c in (operation_id[0], operation_id[-1])):
        raise InvalidOperationIdError("Operation ID must not contain leading or trailing whitespace (no trim)")
    if any(c.isspace() for c in operation_id):
        raise InvalidOperationIdError("Operation ID must not contain whitespace characters")
    if not _OPERATION_ID_REGEX.match(operation_id):
        raise InvalidOperationIdError(f"Operation ID '{operation_id}' contains invalid characters")
    return operation_id


@dataclass(frozen=True)
class ProcessIdentity:
    """OS-level Process Identity 4-tuple providing single source of truth for process uniqueness."""
    host_identity: str
    boot_id: str
    pid: int
    process_start_time: int

    def __post_init__(self):
        if not self.host_identity or not isinstance(self.host_identity, str):
            raise MissingIdentityFieldError("host_identity must be a non-empty string")
        if not self.boot_id or not isinstance(self.boot_id, str):
            raise MissingIdentityFieldError("boot_id must be a non-empty string")
        if self.pid is None or isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 1:
            raise MissingIdentityFieldError("pid must be an integer greater than 1")
        if (self.process_start_time is None or isinstance(self.process_start_time, bool)
                or not isinstance(self.process_start_time, int) or self.process_start_time <= 0):
            raise MissingIdentityFieldError("process_start_time must be a positive integer")

    def matches(self, other: Any) -> bool:
        if not isinstance(other, ProcessIdentity):
            return False
        return (
            self.host_identity == other.host_identity
            and self.boot_id == other.boot_id
            and int(self.pid) == int(other.pid)
            and int(self.process_start_time) == int(other.process_start_time)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_identity": self.host_identity,
            "boot_id": self.boot_id,
            "pid": self.pid,
            "process_start_time": self.process_start_time,
        }


def _normalize_canonical_value(val: Any) -> Any:
    """Recursively sort dictionary keys and normalize iterables for canonical serialization."""
    if isinstance(val, dict):
        return {str(k): _normalize_canonical_value(v) for k, v in sorted(val.items(), key=lambda item: str(item[0]))}
    elif isinstance(val, (list, tuple)):
        return [_normalize_canonical_value(x) for x in val]
    return val


@dataclass(frozen=True)
class CanonicalOperationIdentity:
    """Complete Canonical Operation Identity for Replay Defense and auditability."""
    operation_id: str
    operation_kind: str
    process_identity: ProcessIdentity
    build_id: str
    session_identity: str
    request_scope: str
    normalized_parameters: Dict[str, Any]
    schema_version: str = "1.0"

    def __post_init__(self):
        if not self.operation_id:
            raise MissingIdentityFieldError("operation_id is required")
        validate_operation_id(self.operation_id)
        if not self.operation_kind:
            raise MissingIdentityFieldError("operation_kind is required")
        if not self.process_identity or not isinstance(self.process_identity, ProcessIdentity):
            raise MissingIdentityFieldError("process_identity must be a valid ProcessIdentity")
        if not self.build_id:
            raise MissingIdentityFieldError("build_id is required")
        if not self.session_identity:
            raise MissingIdentityFieldError("session_identity is required")
        if not self.request_scope:
            raise MissingIdentityFieldError("request_scope is required")
        if self.normalized_parameters is None or not isinstance(self.normalized_parameters, dict):
            raise MissingIdentityFieldError("normalized_parameters must be a dict")
        # Validate that all dictionary keys, numbers, and types strictly comply with RFC 8785 JCS
        from .canonical_json import rfc8785_canonical_json
        try:
            rfc8785_canonical_json(self.to_dict())
        except (ValueError, TypeError) as e:
            raise ValueError(f"CanonicalOperationIdentity violates RFC 8785 canonical constraints: {e}") from e

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation_kind": self.operation_kind,
            "process_identity": self.process_identity.to_dict(),
            "build_id": self.build_id,
            "session_identity": self.session_identity,
            "request_scope": self.request_scope,
            "normalized_parameters": self.normalized_parameters,
            "schema_version": self.schema_version,
        }

    def to_canonical_json(self) -> str:
        """Deterministic RFC 8785-compliant JSON representation using extractor.canonical_json."""
        from .canonical_json import rfc8785_canonical_str
        return rfc8785_canonical_str(self.to_dict())

    def digest(self) -> str:
        """Generate SHA-256 hex digest of the RFC 8785 canonical JSON representation."""
        from .canonical_json import rfc8785_canonical_json
        return hashlib.sha256(rfc8785_canonical_json(self.to_dict())).hexdigest()


def build_canonical_replay_identity(
    operation_id: str,
    operation_kind: str,
    process_identity: ProcessIdentity,
    build_id: str,
    session_identity: str,
    request_scope: str,
    parameters: Optional[Dict[str, Any]] = None,
    schema_version: str = "1.0",
) -> CanonicalOperationIdentity:
    """Build normalized, key-sorted CanonicalOperationIdentity compliant with RFC 8785."""
    norm_params = _normalize_canonical_value(parameters or {})
    if not isinstance(norm_params, dict):
        norm_params = {}
    return CanonicalOperationIdentity(
        operation_id=validate_operation_id(operation_id),
        operation_kind=str(operation_kind),
        process_identity=process_identity,
        build_id=str(build_id),
        session_identity=str(session_identity),
        request_scope=str(request_scope),
        normalized_parameters=norm_params,
        schema_version=str(schema_version),
    )


_CURRENT_BOOT_ID_CACHE: Optional[str] = None
_CURRENT_MACHINE_ID_CACHE: Optional[str] = None


def resolve_current_boot_id() -> str:
    """Resolve OS kernel boot ID with caching. Fails closed if unavailable."""
    global _CURRENT_BOOT_ID_CACHE
    if _CURRENT_BOOT_ID_CACHE:
        return _CURRENT_BOOT_ID_CACHE
    try:
        if os.path.exists("/proc/sys/kernel/random/boot_id"):
            with open("/proc/sys/kernel/random/boot_id", "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    _CURRENT_BOOT_ID_CACHE = content
                    return _CURRENT_BOOT_ID_CACHE
    except Exception as e:
        raise ProcessIdentityUnavailableError(f"Failed to read kernel boot_id from /proc: {e}") from e
    raise ProcessIdentityUnavailableError("Kernel boot_id is missing or unavailable on this system")


def resolve_machine_id() -> str:
    """Resolve host machine ID from systemd or dbus files, fallback to hostname."""
    global _CURRENT_MACHINE_ID_CACHE
    if _CURRENT_MACHINE_ID_CACHE:
        return _CURRENT_MACHINE_ID_CACHE
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        _CURRENT_MACHINE_ID_CACHE = content
                        return _CURRENT_MACHINE_ID_CACHE
        except Exception:
            pass
    _CURRENT_MACHINE_ID_CACHE = socket.gethostname() or "localhost"
    return _CURRENT_MACHINE_ID_CACHE


def resolve_process_start_time(pid: int) -> int:
    """Extract starttime (field 22, clock ticks since boot) from /proc/<pid>/stat.
    
    Fails closed with ProcessIdentityUnavailableError if process not found or unreadable.
    """
    stat_path = f"/proc/{pid}/stat"
    try:
        with open(stat_path, "r", encoding="utf-8") as f:
            content = f.read()
        rparen = content.rfind(")")
        if rparen != -1:
            rest = content[rparen + 1:].strip().split()
            # rest[0] is state (field 3), rest[19] is starttime (field 22)
            if len(rest) >= 20:
                return int(rest[19])
    except Exception as e:
        raise ProcessIdentityUnavailableError(f"Cannot resolve process start time for PID {pid}: {e}") from e
    raise ProcessIdentityUnavailableError(f"Cannot parse starttime from {stat_path}")


class DurableTrustStore:
    """Persistent durable trust store for causal verifier keys, revocations, and anti-replay state.

    POSIX / Linux Platform Assumptions:
    1. Atomic File Replacement: Relies on POSIX rename(2) semantics via os.replace(), ensuring that
       the temporary write file is atomically swapped into place without exposure of partial content.
    2. Cross-Process Mutual Exclusion: Relies on fcntl.flock(LOCK_EX) on a dedicated '<store_path>.lock' file.
       On Linux local filesystems (ext4, XFS, tmpfs, Btrfs), this provides rigorous kernel-managed
       advisory file table locking across independent operating system processes.
    3. Durability Guarantees: Calls os.fsync(fd) prior to rename to ensure file payload is committed to
       underlying non-volatile block storage. Calls os.fsync(dir_fd) on the parent directory following rename
       to ensure directory entry updates persist across sudden power loss or kernel panic.
    4. Access Control & Permission Boundaries: Files are created with mode 0600 and directories with 0700,
       restricting read and write authority strictly to the owning UID under Linux DAC (Discretionary Access Control).
    5. Fail-Closed Invariant: Any corrupted store file, invalid schema, truncated JSON, or unpropagated
       persistence error immediately raises RuntimeError and aborts trust acceptance.
    """

    def __init__(self, store_path: Optional[str] = None):
        self.store_path = store_path or os.environ.get("DYNAMICSTATE_TRUST_STORE_PATH")
        self._lock = threading.RLock()
        self._lock_depth: int = 0
        self._lock_fd: Optional[int] = None
        self.keys: Dict[str, str] = {}
        self.active_key_id: str = "default"
        self.revoked_keys: Dict[str, Dict[str, Any]] = {}
        self.used_attestation_ids: Set[str] = set()
        self.used_attestations: Dict[str, Dict[str, Any]] = {}
        self.used_operation_ids: Dict[str, Dict[str, Any]] = {}
        self.identity_conflict_events: List[Dict[str, Any]] = []
        self._startup_reconciled: bool = False
        if self.store_path and os.path.exists(self.store_path):
            self.load()

    @property
    def is_durable(self) -> bool:
        """Return True only when backed by a concrete persistent store_path."""
        return bool(self.store_path and str(self.store_path).strip())

    @contextlib.contextmanager
    def _file_lock(self, timeout: float = 5.0):
        """Cross-process and cross-thread re-entrant mutual exclusion context with 5.0s timeout."""
        with self._lock:
            if not self.store_path:
                yield
                return

            lock_path = self.store_path + ".lock"
            if self._lock_depth == 0:
                dir_name = os.path.dirname(os.path.abspath(lock_path))
                if os.path.exists(dir_name):
                    self._verify_parent_dir_security(dir_name)
                else:
                    os.makedirs(dir_name, mode=0o700, exist_ok=True)
                flags = os.O_RDWR | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(lock_path, flags, 0o600)
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode):
                        raise SecurityViolationError(f"Lock file '{lock_path}' is not a regular file")
                    if hasattr(os, "getuid") and st.st_uid != os.getuid():
                        raise SecurityViolationError(f"Lock file '{lock_path}' owned by UID {st.st_uid}, expected {os.getuid()}")
                    if st.st_nlink > 1:
                        raise SecurityViolationError(
                            f"Lock file '{lock_path}' has hard links (nlink={st.st_nlink}), rejecting due to hard-link replacement risk"
                        )
                    if (st.st_mode & 0o077) != 0:
                        try:
                            os.fchmod(fd, 0o600)
                        except OSError as fe:
                            raise SecurityViolationError(f"Lock file permissions broader than 0600: {fe}") from fe

                    t_start = time.perf_counter()
                    backoff = 0.001
                    locked = False
                    while time.perf_counter() - t_start < timeout:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            locked = True
                            break
                        except (BlockingIOError, OSError) as e:
                            if e.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                                time.sleep(backoff)
                                backoff = min(backoff * 1.5, 0.05)
                            else:
                                raise
                    if not locked:
                        raise LockTimeoutError(
                            f"Durable trust store lock acquisition timed out after {timeout}s on '{lock_path}'"
                        )
                    self._lock_fd = fd
                except BaseException:
                    os.close(fd)
                    raise
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0 and self._lock_fd is not None:
                    fd = self._lock_fd
                    self._lock_fd = None
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def _verify_parent_dir_security(self, dir_name: str) -> None:
        """Verify parent directory and all ancestors: no symlinks, correct ownership, safe permissions."""
        curr = os.path.abspath(dir_name)
        while curr and curr != "/":
            if os.path.islink(curr):
                raise SecurityViolationError(f"Trust store ancestor is a symlink: '{curr}'")
            if os.path.exists(curr):
                dst = os.lstat(curr)
                if stat.S_ISLNK(dst.st_mode):
                    raise SecurityViolationError(f"Trust store ancestor is a symlink: '{curr}'")
            parent = os.path.dirname(curr)
            if parent == curr:
                break
            curr = parent

        if os.path.exists(dir_name):
            dst = os.lstat(dir_name)
            if stat.S_ISLNK(dst.st_mode):
                raise SecurityViolationError(f"Trust store parent directory is a symlink: '{dir_name}'")
            if hasattr(os, "getuid") and dst.st_uid != os.getuid():
                raise SecurityViolationError(f"Trust store parent directory owned by UID {dst.st_uid}, expected {os.getuid()}")
            dir_mode = stat.S_IMODE(dst.st_mode)
            is_sticky = bool(dst.st_mode & stat.S_ISVTX)
            if (dir_mode & 0o002) != 0 and not is_sticky:
                raise SecurityViolationError(
                    f"Trust store parent directory '{dir_name}' has unsafe world-writable permissions (mode={oct(dir_mode)})"
                )
            if (dir_mode & 0o020) != 0 and not is_sticky:
                raise SecurityViolationError(
                    f"Trust store parent directory '{dir_name}' has unsafe group-writable permissions (mode={oct(dir_mode)})"
                )

    def _verify_path_security(self, path: str, operation: str = "access") -> None:
        """Verify filesystem security constraints: no symlinks, correct ownership, secure permissions."""
        if not path:
            return
        prep = "to" if operation == "save" else "from"
        if os.path.islink(path) or (not os.path.exists(path) and os.path.lexists(path)):
            raise SecurityViolationError(f"Refusing to {operation} trust store {prep} symlink: '{path}'")

        abs_path = os.path.abspath(path)
        dir_name = os.path.dirname(abs_path)
        self._verify_parent_dir_security(dir_name)

        if os.path.lexists(path):
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                raise SecurityViolationError(f"Refusing to {operation} trust store {prep} symlink: '{path}'")
            if not stat.S_ISREG(st.st_mode):
                raise SecurityViolationError(f"Trust store path is not a regular file: '{path}'")
            if st.st_nlink > 1:
                raise SecurityViolationError(
                    f"Trust store file '{path}' has hard links (nlink={st.st_nlink}), rejecting due to hard-link replacement risk"
                )
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                raise SecurityViolationError(f"Trust store file owned by UID {st.st_uid}, expected {os.getuid()}")
            # Ensure permissions are not broader than 0600
            current_mode = stat.S_IMODE(st.st_mode)
            if (current_mode & 0o077) != 0:
                try:
                    os.chmod(path, 0o600)
                except OSError as e:
                    raise SecurityViolationError(f"Failed to secure trust store permissions to 0600: {e}") from e

    def _cleanup_stale_temp_files(self, max_age_seconds: Optional[float] = None) -> None:
        """Scan and remove abandoned .trust_tmp_* files in trust store directory under exclusive lock."""
        if not self.store_path:
            return
        dir_name = os.path.dirname(os.path.abspath(self.store_path))
        if not os.path.exists(dir_name) or os.path.islink(dir_name):
            return
        now = time.time()
        try:
            for fname in os.listdir(dir_name):
                if fname.startswith(".trust_tmp_"):
                    fpath = os.path.join(dir_name, fname)
                    try:
                        if not os.path.islink(fpath) and os.path.isfile(fpath):
                            # Try to acquire non-blocking lock to verify no active writer is holding it
                            try:
                                check_fd = os.open(fpath, os.O_RDWR)
                                try:
                                    fcntl.flock(check_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                    # We have exclusive lock on temp file, so no active writer is holding it
                                    if max_age_seconds is not None:
                                        st = os.stat(fpath)
                                        if now - st.st_mtime < max_age_seconds:
                                            continue
                                    os.remove(fpath)
                                except (BlockingIOError, OSError) as lock_err:
                                    if getattr(lock_err, "errno", None) in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                                        # Active writer holds the lock: NEVER delete!
                                        continue
                                    raise
                                finally:
                                    os.close(check_fd)
                            except OSError:
                                pass
                    except OSError:
                        pass
        except OSError:
            pass

    def load(self, reconcile_crashes: Optional[bool] = None) -> None:
        """Load state from persistent trust store file. Fails closed if corrupted."""
        with self._lock:
            if not self.store_path or not os.path.exists(self.store_path):
                return
            if os.path.islink(self.store_path):
                raise SecurityViolationError(f"Refusing to load trust store from symlink: '{self.store_path}'")
            self._verify_path_security(self.store_path, operation="load")
            self._cleanup_stale_temp_files()
            try:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(self.store_path, flags)
                except OSError as open_err:
                    if getattr(open_err, "errno", None) in (errno.ELOOP, errno.EMLINK):
                        raise SecurityViolationError(f"Refusing to load trust store from symlink: '{self.store_path}'") from open_err
                    raise
                try:
                    st = os.fstat(fd)
                    if stat.S_ISLNK(st.st_mode):
                        raise SecurityViolationError(f"Refusing to load trust store from symlink: '{self.store_path}'")
                    if not stat.S_ISREG(st.st_mode):
                        raise SecurityViolationError(f"Trust store path is not a regular file: '{self.store_path}'")
                    if st.st_nlink > 1:
                        raise SecurityViolationError(
                            f"Trust store file '{self.store_path}' has hard links (nlink={st.st_nlink}), rejecting due to hard-link replacement risk"
                        )
                    if hasattr(os, "getuid") and st.st_uid != os.getuid():
                        raise SecurityViolationError(f"Trust store file owned by UID {st.st_uid}, expected {os.getuid()}")
                    with os.fdopen(fd, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                except BaseException:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise
                if not content:
                    return
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise ValueError("Trust store payload must be a JSON dictionary")

                # Strict schema and nested type validation
                if "schema_version" in data:
                    schema_ver = data["schema_version"]
                    if not isinstance(schema_ver, str) or schema_ver not in ("1.0.0", "1.1.0"):
                        raise ValueError(f"Unsupported or invalid trust store schema_version: {schema_ver!r}")

                if "updated_at" in data:
                    up_at = data["updated_at"]
                    if not isinstance(up_at, str):
                        raise ValueError(f"Invalid updated_at in trust store: {up_at!r}")
                    try:
                        datetime.fromisoformat(up_at.replace("Z", "+00:00"))
                    except Exception as iso_err:
                        raise ValueError(f"Invalid updated_at ISO 8601 timestamp in trust store: {up_at!r}") from iso_err

                if "keys" in data:
                    if not isinstance(data["keys"], dict):
                        raise ValueError("Trust store 'keys' field must be a dictionary")
                    for k, v in data["keys"].items():
                        if not isinstance(k, str) or not isinstance(v, str) or not k:
                            raise ValueError(f"Invalid key entry in trust store: {k!r}")

                if "revoked_keys" in data:
                    if not isinstance(data["revoked_keys"], dict):
                        raise ValueError("Trust store 'revoked_keys' field must be a dictionary")
                    for k, v in data["revoked_keys"].items():
                        if not isinstance(k, str) or not isinstance(v, dict):
                            raise ValueError(f"Invalid revoked_keys entry: {k!r}")
                        if "revoked_at" not in v or not isinstance(v["revoked_at"], str):
                            raise ValueError(f"revoked_keys entry '{k}' missing valid 'revoked_at'")
                        try:
                            datetime.fromisoformat(v["revoked_at"].replace("Z", "+00:00"))
                        except Exception as iso_err:
                            raise ValueError(f"revoked_keys entry '{k}' has invalid revoked_at timestamp") from iso_err

                if "used_attestation_ids" in data:
                    if not isinstance(data["used_attestation_ids"], (list, set)):
                        raise ValueError("Trust store 'used_attestation_ids' must be a list or set")
                    for aid in data["used_attestation_ids"]:
                        if not isinstance(aid, str) or not aid:
                            raise ValueError(f"Invalid used_attestation_id: {aid!r}")

                if "used_attestations" in data:
                    if not isinstance(data["used_attestations"], dict):
                        raise ValueError("Trust store 'used_attestations' must be a dictionary")
                    for aid, rec in data["used_attestations"].items():
                        if not isinstance(aid, str) or not isinstance(rec, dict) or not aid:
                            raise ValueError(f"Invalid used_attestations entry: {aid!r}")
                        if "evidence_id" not in rec or not isinstance(rec["evidence_id"], str) or not rec["evidence_id"]:
                            raise ValueError(f"used_attestations entry '{aid}' missing valid 'evidence_id'")
                        if "session_id" in rec and (not isinstance(rec["session_id"], str) or not rec["session_id"]):
                            raise ValueError(f"used_attestations entry '{aid}' has invalid session_id")
                        if "operation_id" in rec and (not isinstance(rec["operation_id"], str) or not rec["operation_id"].strip()):
                            raise ValueError(f"used_attestations entry '{aid}' has invalid operation_id")
                        if "pid" in rec:
                            p = rec["pid"]
                            if isinstance(p, bool) or not isinstance(p, int) or p < 0:
                                raise ValueError(f"used_attestations entry '{aid}' has invalid pid: {p!r}")
                        if "recorded_at" in rec:
                            r_at = rec["recorded_at"]
                            if not isinstance(r_at, str):
                                raise ValueError(f"used_attestations entry '{aid}' has non-string recorded_at")
                            try:
                                datetime.fromisoformat(r_at.replace("Z", "+00:00"))
                            except Exception as iso_err:
                                raise ValueError(f"used_attestations entry '{aid}' invalid recorded_at timestamp: {r_at!r}") from iso_err

                if "used_operation_ids" in data:
                    if not isinstance(data["used_operation_ids"], dict):
                        raise ValueError("Trust store 'used_operation_ids' must be a dictionary")
                    for op_id, op_rec in data["used_operation_ids"].items():
                        if not isinstance(op_id, str) or not isinstance(op_rec, dict) or not op_id:
                            raise ValueError(f"Invalid used_operation_ids entry: {op_id!r}")
                        if "session_id" not in op_rec or not isinstance(op_rec["session_id"], str) or not op_rec["session_id"]:
                            raise ValueError(f"used_operation_ids entry '{op_id}' missing valid 'session_id'")
                        if "pid" not in op_rec or isinstance(op_rec["pid"], bool) or not isinstance(op_rec["pid"], int) or op_rec["pid"] < 0:
                            raise ValueError(f"used_operation_ids entry '{op_id}' missing valid 'pid'")
                        if "recorded_at" in op_rec:
                            r_at = op_rec["recorded_at"]
                            if not isinstance(r_at, str):
                                raise ValueError(f"used_operation_ids entry '{op_id}' has non-string recorded_at")
                            try:
                                datetime.fromisoformat(r_at.replace("Z", "+00:00"))
                            except Exception as iso_err:
                                raise ValueError(f"used_operation_ids entry '{op_id}' invalid recorded_at timestamp: {r_at!r}") from iso_err
                        if "evidence_ids" in op_rec:
                            eids = op_rec["evidence_ids"]
                            if not isinstance(eids, list):
                                raise ValueError(f"used_operation_ids entry '{op_id}' evidence_ids must be a list")
                            if len(eids) != len(set(eids)):
                                raise ValueError(f"used_operation_ids entry '{op_id}' contains duplicate evidence_ids")
                            for eid in eids:
                                if not isinstance(eid, str) or not eid:
                                    raise ValueError(f"used_operation_ids entry '{op_id}' contains invalid evidence_id: {eid!r}")
                        for str_field in ("receipt_id", "process_identity", "executable_identity", "build_id", "target_host", "observation_digest", "operation_type"):
                            if str_field in op_rec and not isinstance(op_rec[str_field], str):
                                raise ValueError(f"used_operation_ids entry '{op_id}' has invalid non-string '{str_field}'")

                if "identity_conflict_events" in data and isinstance(data["identity_conflict_events"], list):
                    self.identity_conflict_events = list(data["identity_conflict_events"])

                self.keys = {str(k): str(v) for k, v in data.get("keys", {}).items()}
                self.active_key_id = str(data.get("active_key_id", "default"))
                self.revoked_keys = dict(data.get("revoked_keys", {}))
                self.used_attestation_ids = set(data.get("used_attestation_ids", []))
                self.used_attestations = dict(data.get("used_attestations", {}))
                # Sync used_attestation_ids with used_attestations
                for aid in self.used_attestations.keys():
                    self.used_attestation_ids.add(aid)
                self.used_operation_ids = dict(data.get("used_operation_ids", {}))
                # Eager Crash Recovery: reconcile uncommitted operations (RESERVED / EXECUTING) to ABORTED_ON_RESTART
                should_reconcile = reconcile_crashes if reconcile_crashes is not None else (not self._startup_reconciled)
                if should_reconcile:
                    reconciled_count = 0
                    now_iso = datetime.now(timezone.utc).isoformat()
                    for op_id, op_rec in self.used_operation_ids.items():
                        curr_st = op_rec.get("state")
                        if curr_st in (OperationLifecycleState.RESERVED.value, OperationLifecycleState.EXECUTING.value):
                            op_rec["state"] = OperationLifecycleState.ABORTED_ON_RESTART.value
                            op_rec["aborted_at"] = now_iso
                            op_rec["abort_reason"] = "Process terminated abnormally before completion (crash recovery reconciliation)"
                            reconciled_count += 1
                    self._startup_reconciled = True
                    if reconciled_count > 0:
                        self.save()
            except Exception as e:
                raise RuntimeError(f"Durable trust store at '{self.store_path}' is corrupted or unreadable: {e}") from e

    def get_identity_conflict_events(self) -> List[Dict[str, Any]]:
        """Retrieve persisted identity conflict events for security audit."""
        with self._file_lock():
            self.load()
            return list(getattr(self, "identity_conflict_events", []))

    def reconcile_from_disk(self) -> None:
        """Reconcile in-memory state from disk under lock after indeterminate commit outcome."""
        with self._file_lock():
            self.load()

    def save(self) -> DurableCommitOutcome:
        """Atomically persist trust store state to disk with strict commit outcome semantics."""
        with self._file_lock():
            if not self.store_path:
                return DurableCommitOutcome.NON_DURABLE
            self._verify_path_security(self.store_path, operation="save")
            payload = {
                "schema_version": "1.1.0",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "active_key_id": self.active_key_id,
                "keys": self.keys,
                "revoked_keys": self.revoked_keys,
                "used_attestation_ids": sorted(list(self.used_attestation_ids)),
                "used_attestations": getattr(self, "used_attestations", {}),
                "used_operation_ids": self.used_operation_ids,
                "identity_conflict_events": getattr(self, "identity_conflict_events", []),
            }
            dir_name = os.path.dirname(os.path.abspath(self.store_path))
            os.makedirs(dir_name, mode=0o700, exist_ok=True)
            tmp_path = os.path.join(dir_name, f".trust_tmp_{uuid.uuid4().hex[:12]}")
            commit_point_reached = False
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(tmp_path, flags, 0o600)
                except OSError as open_err:
                    if getattr(open_err, "errno", None) in (errno.ELOOP, errno.EMLINK):
                        raise SecurityViolationError(f"Refusing to save trust store to symlink: '{tmp_path}'") from open_err
                    raise
                try:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except (BlockingIOError, OSError) as flock_err:
                        raise SecurityViolationError(f"Failed to acquire exclusive lock on temporary trust store '{tmp_path}': {flock_err}") from flock_err
                    # Apply and verify 0600 mode directly on open FD to prevent TOCTOU pathname races
                    try:
                        os.fchmod(fd, 0o600)
                        os.chmod(tmp_path, 0o600)
                    except OSError as ce:
                        raise RuntimeError(f"Failed to apply 0600 mode on temporary trust store: {ce}") from ce
                    st = os.fstat(fd)
                    if stat.S_ISLNK(st.st_mode):
                        raise SecurityViolationError(f"Refusing to save trust store to symlink: '{tmp_path}'")
                    if st.st_nlink > 1:
                        raise SecurityViolationError(
                            f"Temporary trust store file '{tmp_path}' has hard links (nlink={st.st_nlink})"
                        )
                    if (stat.S_IMODE(st.st_mode) & 0o077) != 0:
                        raise RuntimeError(f"Failed to verify 0600 mode on temporary trust store: got {oct(st.st_mode)}")
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump(payload, f, indent=2)
                        f.flush()
                        # fsync temporary file data and metadata after permission changes
                        os.fsync(f.fileno())
                except BaseException:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise

                # EXACT DURABLE COMMIT POINT: Atomic replacement under existing file lock
                os.replace(tmp_path, self.store_path)
                commit_point_reached = True

                # Parent directory fsync after replacement to commit directory entry to non-volatile storage
                dir_flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    dir_flags |= os.O_DIRECTORY
                dir_fd = os.open(dir_name, dir_flags)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)

                return DurableCommitOutcome.COMMITTED
            except Exception as e:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                if commit_point_reached:
                    raise DurableCommitError(
                        f"Trust store commit outcome uncertain: atomic replace completed but parent directory fsync failed: {e}",
                        outcome=DurableCommitOutcome.COMMIT_UNKNOWN,
                        cause=e,
                    ) from e
                else:
                    raise DurableCommitError(
                        f"Failed to persist durable trust store to '{self.store_path}': {e}",
                        outcome=DurableCommitOutcome.NOT_COMMITTED,
                        cause=e,
                    ) from e

    def register_key(self, key_id: str, secret: str, is_active: bool = False) -> None:
        with self._file_lock():
            self.load()
            kid = str(key_id)
            if not kid or not secret:
                raise ValueError("key_id and secret must be non-empty strings")
            if kid in self.revoked_keys:
                raise ValueError(f"Cannot register key '{kid}': key is permanently revoked")
            orig_keys = dict(self.keys)
            orig_active = self.active_key_id
            self.keys[kid] = str(secret)
            if is_active or len(self.keys) == 1:
                self.active_key_id = kid
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                self.keys = orig_keys
                self.active_key_id = orig_active
                raise
            except Exception:
                self.keys = orig_keys
                self.active_key_id = orig_active
                raise

    def rotate_key(self, new_key_id: str, new_secret: str) -> None:
        self.register_key(new_key_id, new_secret, is_active=True)

    def revoke_key(self, key_id: str, reason: str = "revoked") -> None:
        with self._file_lock():
            self.load()
            kid = str(key_id)
            orig_rev = dict(self.revoked_keys)
            orig_active = self.active_key_id
            self.revoked_keys[kid] = {
                "revoked_at": datetime.now(timezone.utc).isoformat(),
                "reason": str(reason),
            }
            if self.active_key_id == kid:
                available = [k for k in self.keys.keys() if k not in self.revoked_keys]
                self.active_key_id = available[0] if available else ""
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                self.revoked_keys = orig_rev
                self.active_key_id = orig_active
                raise
            except Exception:
                self.revoked_keys = orig_rev
                self.active_key_id = orig_active
                raise

    def is_revoked(self, key_id: str) -> bool:
        with self._file_lock():
            self.load()
            return str(key_id) in self.revoked_keys

    def record_used_attestation(self, attestation_id: str) -> None:
        with self._file_lock():
            self.load()
            att_id = str(attestation_id)
            if att_id in self.used_attestation_ids:
                raise ValueError(f"Replay of causal attestation ID '{att_id}' rejected")
            orig_set = set(self.used_attestation_ids)
            self.used_attestation_ids.add(att_id)
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                self.used_attestation_ids = orig_set
                raise
            except Exception:
                self.used_attestation_ids = orig_set
                raise

    def is_attestation_used(self, attestation_id: str) -> bool:
        with self._file_lock():
            self.load()
            return str(attestation_id) in self.used_attestation_ids

    def consume_attestation(
        self,
        attestation: "CausalAttestation",
        evidence_id: str,
        session_id: Optional[str] = None,
        expected_pid: Optional[int] = None,
        expected_process_identity: Optional[str] = None,
        expected_executable_identity: Optional[str] = None,
        expected_build_id: Optional[str] = None,
        expected_target_host: Optional[str] = None,
        secret: Optional[str] = None,
        key_store: Optional["CaptureKeyStore"] = None,
        current_time_ns: Optional[int] = None,
        operation_id: Optional[str] = None,
        require_operation_id: bool = True,
    ) -> TrustConsumptionResult:
        """Atomic trust-consumption contract eliminating check-then-record race conditions."""
        arg_op_id = str(operation_id).strip() if (operation_id is not None and str(operation_id).strip()) else None
        att_op_raw = getattr(attestation, "operation_id", None)
        att_op_id = str(att_op_raw).strip() if (att_op_raw is not None and str(att_op_raw).strip()) else None
        if arg_op_id is not None:
            validate_operation_id(arg_op_id)
        if att_op_id is not None:
            validate_operation_id(att_op_id)
        if arg_op_id is not None and att_op_id is not None and arg_op_id != att_op_id:
            return TrustConsumptionResult(
                status=TrustConsumptionStatus.IDENTITY_MISMATCH,
                reason=f"OPERATION_ID_MISMATCH: Expected operation '{arg_op_id}', attestation has '{att_op_id}'",
                attestation_id=str(getattr(attestation, "attestation_id", "")),
                key_id=str(getattr(attestation, "key_id", "")),
                evidence_id=str(evidence_id),
            )
        eff_op_id = arg_op_id or att_op_id
        if require_operation_id:
            if eff_op_id is None or not str(eff_op_id).strip():
                raise MissingIdentityFieldError("operation_id is mandatory for durable attestation consumption")
            validate_operation_id(str(eff_op_id))
        with self._file_lock():
            self.load()
            att_id = str(attestation.attestation_id)
            kid = str(attestation.key_id)

            # 1. Revocation check
            if kid in self.revoked_keys or attestation.revoked:
                return TrustConsumptionResult(
                    status=TrustConsumptionStatus.REVOKED,
                    reason=f"Attestation key '{kid}' or attestation itself is revoked",
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=str(evidence_id),
                )

            # 2. Signature verification & identity validation (explicitly binding canonical operation_id)
            ok_v, err_v = attestation.verify(
                secret=secret,
                key_store=key_store,
                current_time_ns=current_time_ns,
                expected_session_id=session_id,
                expected_pid=expected_pid,
                expected_operation_id=eff_op_id,
                expected_process_identity=expected_process_identity,
                expected_executable_identity=expected_executable_identity,
                expected_build_id=expected_build_id,
                expected_target_host=expected_target_host,
                trust_store=self,
            )
            if not ok_v:
                if "KEY_REVOKED" in err_v:
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.REVOKED,
                        reason=err_v,
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )
                if "EXPIRED_ATTESTATION" in err_v:
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.EXPIRED,
                        reason=err_v,
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )
                if any(m in err_v for m in ("MISMATCH", "MISSING_", "INVALID_TARGET_PID", "CROSS_SESSION")):
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.IDENTITY_MISMATCH,
                        reason=err_v,
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )
                return TrustConsumptionResult(
                    status=TrustConsumptionStatus.INVALID_SIGNATURE,
                    reason=err_v,
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=str(evidence_id),
                )

            # 3. Anti-replay reservation / idempotent check
            if not hasattr(self, "used_attestations"):
                self.used_attestations: Dict[str, Dict[str, Any]] = {}

            if att_id in self.used_attestation_ids:
                bound_info = self.used_attestations.get(att_id)
                if bound_info:
                    bound_eid = bound_info.get("evidence_id")
                    bound_sess = bound_info.get("session_id")
                    bound_pid = bound_info.get("pid")
                    bound_op = bound_info.get("operation_id")
                    op_matches = (
                        (bound_op is None and eff_op_id is None)
                        or (bound_op is not None and eff_op_id is not None and str(bound_op) == str(eff_op_id))
                        or (bound_op is None and not require_operation_id)
                    )
                    # Exact original committed evidence + canonical operation_id recovery
                    if (
                        bound_eid == str(evidence_id)
                        and (not session_id or bound_sess == str(session_id))
                        and (expected_pid is None or int(bound_pid) == int(expected_pid))
                        and op_matches
                    ):
                        return TrustConsumptionResult(
                            status=TrustConsumptionStatus.IDEMPOTENT_RECOVERY,
                            reason="Idempotent re-verification of same evidence record and canonical operation_id",
                            attestation_id=att_id,
                            key_id=kid,
                            evidence_id=str(evidence_id),
                            recorded_at=bound_info.get("recorded_at", ""),
                        )
                    else:
                        return TrustConsumptionResult(
                            status=TrustConsumptionStatus.REPLAY_CONFLICT,
                            reason=(
                                f"Attestation ID '{att_id}' already consumed by evidence '{bound_eid}' "
                                f"(session={bound_sess}, pid={bound_pid}, operation_id={bound_op})"
                            ),
                            attestation_id=att_id,
                            key_id=kid,
                            evidence_id=str(evidence_id),
                        )
                else:
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.REPLAY_CONFLICT,
                        reason=f"Attestation ID '{att_id}' already recorded as used in trust store",
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )

            # 4. Atomic durable consumption
            now_iso = datetime.now(timezone.utc).isoformat()
            orig_used_set = set(self.used_attestation_ids)
            orig_used_dict = dict(self.used_attestations)

            self.used_attestation_ids.add(att_id)
            att_rec = {
                "evidence_id": str(evidence_id),
                "session_id": str(session_id or attestation.session_id),
                "pid": int(expected_pid or attestation.target_identity.get("pid", 0)),
                "recorded_at": now_iso,
            }
            if eff_op_id is not None:
                att_rec["operation_id"] = str(eff_op_id)
            self.used_attestations[att_id] = att_rec

            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.PERSISTENCE_FAILURE,
                        reason=f"Commit outcome uncertain during atomic trust consumption: {dce}",
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )
                self.used_attestation_ids = orig_used_set
                self.used_attestations = orig_used_dict
                return TrustConsumptionResult(
                    status=TrustConsumptionStatus.PERSISTENCE_FAILURE,
                    reason=f"Persistence failure during atomic trust consumption: {dce}",
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=str(evidence_id),
                )
            except Exception as e:
                self.used_attestation_ids = orig_used_set
                self.used_attestations = orig_used_dict
                return TrustConsumptionResult(
                    status=TrustConsumptionStatus.PERSISTENCE_FAILURE,
                    reason=f"Persistence failure during atomic trust consumption: {e}",
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=str(evidence_id),
                )

            return TrustConsumptionResult(
                status=TrustConsumptionStatus.NEW_ACCEPTANCE,
                reason="Successfully verified and consumed attestation",
                attestation_id=att_id,
                key_id=kid,
                evidence_id=str(evidence_id),
                recorded_at=now_iso,
            )

    def reconcile_attestations_atomic(
        self,
        items: List[Dict[str, Any]],
    ) -> List[TrustConsumptionResult]:
        """Atomically validate and reconcile a batch of attestations under one lock and one save.

        If ANY item fails validation or replay checks, NO durable TrustStore mutation occurs.
        """
        if not items:
            return []
        with self._file_lock():
            self.load()
            if not hasattr(self, "used_attestations"):
                self.used_attestations: Dict[str, Dict[str, Any]] = {}

            orig_used_set = set(self.used_attestation_ids)
            orig_used_dict = {k: dict(v) for k, v in self.used_attestations.items()}
            pending_set = set(orig_used_set)
            pending_dict = {k: dict(v) for k, v in orig_used_dict.items()}
            results: List[TrustConsumptionResult] = []
            now_iso = datetime.now(timezone.utc).isoformat()
            needs_save = False

            for item in items:
                attestation = item["attestation"]
                evidence_id = str(item["evidence_id"])
                session_id = item.get("session_id")
                expected_pid = item.get("expected_pid")
                expected_process_identity = item.get("expected_process_identity")
                expected_executable_identity = item.get("expected_executable_identity")
                expected_build_id = item.get("expected_build_id")
                expected_target_host = item.get("expected_target_host")
                operation_id = item.get("operation_id")
                require_operation_id = item.get("require_operation_id", True)

                arg_op_id = str(operation_id).strip() if (operation_id is not None and str(operation_id).strip()) else None
                att_op_raw = getattr(attestation, "operation_id", None)
                att_op_id = str(att_op_raw).strip() if (att_op_raw is not None and str(att_op_raw).strip()) else None
                att_id = str(attestation.attestation_id)
                kid = str(attestation.key_id)

                if arg_op_id is not None and att_op_id is not None and arg_op_id != att_op_id:
                    raise ValueError(
                        f"CausalAttestation rejected for record '{evidence_id}': [IDENTITY_MISMATCH] "
                        f"OPERATION_ID_MISMATCH: Expected operation '{arg_op_id}', attestation has '{att_op_id}'"
                    )
                eff_op_id = arg_op_id or att_op_id
                if require_operation_id:
                    if eff_op_id is None or not str(eff_op_id).strip():
                        raise MissingIdentityFieldError("operation_id is mandatory for durable attestation consumption")
                    validate_operation_id(str(eff_op_id))
                elif eff_op_id is not None:
                    validate_operation_id(str(eff_op_id))

                if kid in self.revoked_keys or attestation.revoked:
                    raise ValueError(
                        f"CausalAttestation rejected for record '{evidence_id}': [REVOKED] "
                        f"Attestation key '{kid}' or attestation itself is revoked"
                    )

                ok_v, err_v = attestation.verify(
                    expected_session_id=session_id,
                    expected_pid=expected_pid,
                    expected_operation_id=eff_op_id,
                    expected_process_identity=expected_process_identity,
                    expected_executable_identity=expected_executable_identity,
                    expected_build_id=expected_build_id,
                    expected_target_host=expected_target_host,
                    trust_store=self,
                )
                if not ok_v:
                    raise ValueError(f"CausalAttestation rejected for record '{evidence_id}': {err_v}")

                if att_id in pending_set:
                    bound_info = pending_dict.get(att_id)
                    if bound_info:
                        bound_eid = bound_info.get("evidence_id")
                        bound_sess = bound_info.get("session_id")
                        bound_pid = bound_info.get("pid")
                        bound_op = bound_info.get("operation_id")
                        op_matches = (
                            (bound_op is None and eff_op_id is None)
                            or (bound_op is not None and eff_op_id is not None and str(bound_op) == str(eff_op_id))
                            or (bound_op is None and not require_operation_id)
                        )
                        if (
                            bound_eid == evidence_id
                            and (not session_id or bound_sess == str(session_id))
                            and (expected_pid is None or int(bound_pid) == int(expected_pid))
                            and op_matches
                        ):
                            results.append(TrustConsumptionResult(
                                status=TrustConsumptionStatus.IDEMPOTENT_RECOVERY,
                                reason="Idempotent re-verification of same evidence record and canonical operation_id",
                                attestation_id=att_id,
                                key_id=kid,
                                evidence_id=evidence_id,
                                recorded_at=bound_info.get("recorded_at", ""),
                            ))
                            continue
                    raise ValueError(
                        f"Replay of causal attestation ID '{att_id}' rejected on record '{evidence_id}': [REPLAY_CONFLICT]"
                    )

                pending_set.add(att_id)
                att_rec = {
                    "evidence_id": evidence_id,
                    "session_id": str(session_id or attestation.session_id),
                    "pid": int(expected_pid or attestation.target_identity.get("pid", 0)),
                    "recorded_at": now_iso,
                }
                if eff_op_id is not None:
                    att_rec["operation_id"] = str(eff_op_id)
                pending_dict[att_id] = att_rec
                needs_save = True
                results.append(TrustConsumptionResult(
                    status=TrustConsumptionStatus.NEW_ACCEPTANCE,
                    reason="Successfully verified and consumed attestation",
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=evidence_id,
                    recorded_at=now_iso,
                ))

            if needs_save:
                self.used_attestation_ids = pending_set
                self.used_attestations = pending_dict
                try:
                    self.save()
                except DurableCommitError as dce:
                    if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                        self.reconcile_from_disk()
                    else:
                        self.used_attestation_ids = orig_used_set
                        self.used_attestations = orig_used_dict
                    raise RuntimeError(f"Persistence failure during atomic trust reconciliation: {dce}") from dce
                except Exception as e:
                    self.used_attestation_ids = orig_used_set
                    self.used_attestations = orig_used_dict
                    raise RuntimeError(f"Persistence failure during atomic trust reconciliation: {e}") from e

            return results

    def record_used_operation(
        self,
        op_id: str,
        session_id: str,
        pid: int,
        metadata: Optional[Dict[str, Any]] = None,
        allow_idempotent: bool = False,
        require_canonical_replay_identity: bool = False,
        require_lifecycle_enforcement: bool = False,
    ) -> None:
        oid = validate_operation_id(op_id)
        with self._file_lock():
            self.load()

            # Canonical Replay Identity & Digest Verification
            # Compatibility journal entries may remain non-replay records only when they carry
            # no capture/lifecycle authority. Capture and lifecycle operations require JCS
            # identity even if a caller forgets the explicit option.
            requires_canon = (
                require_canonical_replay_identity
                or getattr(self, "require_canonical_replay_identity", False)
                or (metadata is not None and bool(metadata.get("require_canonical_replay_identity")))
                or require_lifecycle_enforcement
                or (metadata is not None and (
                    bool(metadata.get("require_lifecycle_enforcement"))
                    or bool(metadata.get("require_lifecycle_persistence"))
                    or metadata.get("operation_type") in ("diagnostic", "probe")
                ))
            )
            has_canon_ident = bool(metadata and "canonical_identity" in metadata)
            has_canon_dig = bool(metadata and "canonical_digest" in metadata)

            if requires_canon and not (has_canon_ident and has_canon_dig):
                if not has_canon_ident and not has_canon_dig:
                    raise MissingIdentityFieldError(
                        f"Both 'canonical_identity' and 'canonical_digest' are required for operation '{oid}'"
                    )
                raise MissingIdentityFieldError(
                    f"Both 'canonical_identity' and 'canonical_digest' must be provided together for operation '{oid}'"
                )

            if has_canon_ident or has_canon_dig:
                if not (has_canon_ident and has_canon_dig):
                    raise MissingIdentityFieldError(
                        f"Both 'canonical_identity' and 'canonical_digest' must be provided together for operation '{oid}'"
                    )
                c_ident_raw = metadata["canonical_identity"]
                c_dig_supplied = str(metadata["canonical_digest"])
                if isinstance(c_ident_raw, CanonicalOperationIdentity):
                    c_ident_obj = c_ident_raw
                elif isinstance(c_ident_raw, dict):
                    p_ident_raw = c_ident_raw.get("process_identity")
                    if not isinstance(p_ident_raw, dict):
                        raise MissingIdentityFieldError("canonical_identity missing valid process_identity dict")
                    proc_id = ProcessIdentity(
                        host_identity=str(p_ident_raw.get("host_identity", "")),
                        boot_id=str(p_ident_raw.get("boot_id", "")),
                        pid=int(p_ident_raw.get("pid", 0)),
                        process_start_time=int(p_ident_raw.get("process_start_time", 0)),
                    )
                    c_ident_obj = CanonicalOperationIdentity(
                        operation_id=str(c_ident_raw.get("operation_id", "")),
                        operation_kind=str(c_ident_raw.get("operation_kind", "")),
                        process_identity=proc_id,
                        build_id=str(c_ident_raw.get("build_id", "")),
                        session_identity=str(c_ident_raw.get("session_identity", "")),
                        request_scope=str(c_ident_raw.get("request_scope", "")),
                        normalized_parameters=c_ident_raw.get("normalized_parameters", {}),
                        schema_version=str(c_ident_raw.get("schema_version", "1.0")),
                    )
                else:
                    raise MissingIdentityFieldError("canonical_identity must be a dict or CanonicalOperationIdentity")

                # Verify caller-provided digest against recomputed RFC 8785 digest
                recomputed_dig = c_ident_obj.digest()
                if not hmac.compare_digest(c_dig_supplied, recomputed_dig):
                    raise SecurityViolationError(
                        f"Caller-provided canonical_digest '{c_dig_supplied}' does not match recomputed RFC 8785 digest '{recomputed_dig}' for operation '{oid}'"
                    )

                # Compare canonical identity fields against actual method arguments
                if c_ident_obj.operation_id != oid:
                    raise SecurityViolationError(
                        f"Canonical identity operation_id '{c_ident_obj.operation_id}' does not match op_id '{oid}'"
                    )
                if c_ident_obj.session_identity != str(session_id):
                    raise SecurityViolationError(
                        f"Canonical identity session_identity '{c_ident_obj.session_identity}' does not match session_id '{session_id}'"
                    )
                if int(c_ident_obj.process_identity.pid) != int(pid):
                    raise SecurityViolationError(
                        f"Canonical identity pid '{c_ident_obj.process_identity.pid}' does not match pid '{pid}'"
                    )
                if metadata:
                    m_host = metadata.get("target_host") or metadata.get("host_identity")
                    if m_host and str(m_host) != str(c_ident_obj.process_identity.host_identity):
                        raise SecurityViolationError(
                            f"Canonical identity host '{c_ident_obj.process_identity.host_identity}' does not match metadata '{m_host}'"
                        )
                    m_boot = metadata.get("boot_id")
                    if m_boot and str(m_boot) != str(c_ident_obj.process_identity.boot_id):
                        raise SecurityViolationError(
                            f"Canonical identity boot_id '{c_ident_obj.process_identity.boot_id}' does not match metadata '{m_boot}'"
                        )
                    m_start = metadata.get("process_start_time")
                    if m_start is not None and int(m_start) != int(c_ident_obj.process_identity.process_start_time):
                        raise SecurityViolationError(
                            f"Canonical identity process_start_time '{c_ident_obj.process_identity.process_start_time}' does not match metadata '{m_start}'"
                        )
                    m_bid = metadata.get("build_id")
                    if m_bid and str(m_bid) != str(c_ident_obj.build_id):
                        raise SecurityViolationError(
                            f"Canonical identity build_id '{c_ident_obj.build_id}' does not match metadata '{m_bid}'"
                        )

            if oid in self.used_operation_ids:
                prev = self.used_operation_ids[oid]
                prev_st = prev.get("state")
                if prev_st in (
                    OperationLifecycleState.CREATED.value,
                    OperationLifecycleState.VALIDATED.value,
                    OperationLifecycleState.RESERVED.value,
                    OperationLifecycleState.FAILED.value,
                    OperationLifecycleState.CANCELLED.value,
                    OperationLifecycleState.ABORTED_ON_RESTART.value,
                ):
                    raise InvalidStateTransitionError(
                        f"Operation '{oid}' is currently in state {prev_st} and cannot be directly marked COMMITTED; must transition through EXECUTING"
                    )
                if prev.get("session_id") != str(session_id):
                    raise ValueError(f"Receipt replay across sessions rejected for operation '{oid}'")
                if prev.get("pid") is not None and int(prev["pid"]) != int(pid):
                    raise ValueError(f"Receipt replay across PIDs rejected for operation '{oid}'")

                # Replay protection across boot sessions
                p_boot = prev.get("boot_id")
                m_boot = metadata.get("boot_id") if metadata else None
                if p_boot and m_boot and str(p_boot) != str(m_boot):
                    raise ValueError(f"Receipt replay across boot sessions rejected for operation '{oid}': boot_id mismatch ({p_boot} vs {m_boot})")

                # PID reuse defense across process start times
                p_start = prev.get("process_start_time")
                m_start = metadata.get("process_start_time") if metadata else None
                if p_start is not None and m_start is not None and int(p_start) != int(m_start):
                    raise ValueError(f"Receipt replay across process start times (PID reuse) rejected for operation '{oid}': start time mismatch ({p_start} vs {m_start})")

                # Replay protection across hosts
                p_host = prev.get("host_identity") or prev.get("target_host")
                m_host = (metadata.get("host_identity") or metadata.get("target_host")) if metadata else None
                if p_host and m_host and str(p_host) != str(m_host):
                    raise ValueError(f"Receipt replay across hosts rejected for operation '{oid}': target_host mismatch ({p_host} vs {m_host})")

                if metadata:
                    p_canon = prev.get("canonical_digest")
                    m_canon = metadata.get("canonical_digest")
                    if p_canon and m_canon and str(p_canon) != str(m_canon):
                        conflict_event = {
                            "operation_id": oid,
                            "field_name": "canonical_digest",
                            "existing_value": str(p_canon),
                            "attempted_value": str(m_canon),
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                        if not hasattr(self, "identity_conflict_events"):
                            self.identity_conflict_events = []
                        self.identity_conflict_events.append(conflict_event)
                        try:
                            self.save()
                        except Exception as save_err:
                            self.identity_conflict_events.pop()
                            raise ConflictAuditPersistenceError(
                                f"Failed to persist identity conflict audit event for operation '{oid}': {save_err}"
                            ) from save_err
                        raise IdentityConflictError(
                            f"Conflicting canonical identity digest for operation '{oid}': {p_canon} vs {m_canon}"
                        )

                    for id_field in (
                        "build_id",
                        "process_identity",
                        "executable_identity",
                        "target_host",
                        "host_identity",
                        "receipt_id",
                        "observation_digest",
                        "operation_type",
                    ):
                        p_val = prev.get(id_field)
                        m_val = metadata.get(id_field)
                        if p_val is not None and p_val != "" and m_val is not None and m_val != "" and str(p_val) != str(m_val):
                            conflict_event = {
                                "operation_id": oid,
                                "field_name": id_field,
                                "existing_value": str(p_val),
                                "attempted_value": str(m_val),
                                "detected_at": datetime.now(timezone.utc).isoformat(),
                            }
                            if not hasattr(self, "identity_conflict_events"):
                                self.identity_conflict_events = []
                            self.identity_conflict_events.append(conflict_event)
                            try:
                                self.save()
                            except Exception as save_err:
                                self.identity_conflict_events.pop()
                                raise ConflictAuditPersistenceError(
                                    f"Failed to persist identity conflict audit event for operation '{oid}': {save_err}"
                                ) from save_err
                            raise IdentityConflictError(
                                f"Conflicting target identity or metadata '{id_field}' for operation '{oid}': {p_val} vs {m_val}"
                            )

                    # Multi-evidence operation derivation checks
                    incoming_eid = metadata.get("evidence_id")
                    bound_eid = prev.get("evidence_id")
                    bound_eids = list(prev.get("evidence_ids", []))
                    if bound_eid and bound_eid not in bound_eids:
                        bound_eids.insert(0, bound_eid)

                    if incoming_eid and bound_eid and incoming_eid != bound_eid:
                        derived_from = metadata.get("derived_from")
                        parent_eids = metadata.get("parent_evidence_ids")
                        d_list = [derived_from] if isinstance(derived_from, str) else list(derived_from or [])
                        p_list = [parent_eids] if isinstance(parent_eids, str) else list(parent_eids or [])
                        has_derivation = any(d in bound_eids for d in d_list) or any(p in bound_eids for p in p_list)
                        if not has_derivation:
                            raise ValueError(
                                f"Operation '{oid}' is already bound to primary evidence '{bound_eid}'. "
                                f"Secondary evidence '{incoming_eid}' requires verifiable derivation from primary observation."
                            )

                if prev_st == OperationLifecycleState.EXECUTING.value:
                    # Valid lifecycle progression: transition from EXECUTING to COMMITTED
                    orig_prev = dict(prev)
                    prev["state"] = OperationLifecycleState.COMMITTED.value
                    prev["committed_at"] = datetime.now(timezone.utc).isoformat()
                    if metadata:
                        for k, v in metadata.items():
                            if v is not None and v != "":
                                prev[k] = v
                    if metadata and metadata.get("evidence_id"):
                        e_list = prev.setdefault("evidence_ids", [])
                        if metadata["evidence_id"] not in e_list:
                            e_list.append(metadata["evidence_id"])
                    try:
                        self.save()
                    except DurableCommitError as dce:
                        if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                            self.reconcile_from_disk()
                            raise
                        prev.clear()
                        prev.update(orig_prev)
                        raise
                    except Exception:
                        prev.clear()
                        prev.update(orig_prev)
                        raise
                    return

                if allow_idempotent:
                    if metadata:
                        orig_prev = dict(prev)
                        orig_eids = list(prev.get("evidence_ids", []))
                        for k, v in metadata.items():
                            # Monotonicity: never overwrite established non-empty values with None/empty
                            if v is None or v == "":
                                continue
                            if k == "evidence_id" and "evidence_id" in prev and prev["evidence_id"] != v:
                                continue
                            if k == "state" and prev.get("state") == OperationLifecycleState.COMMITTED.value:
                                continue
                            prev[k] = v
                        if metadata.get("evidence_id"):
                            e_list = prev.setdefault("evidence_ids", [])
                            if metadata["evidence_id"] not in e_list:
                                e_list.append(metadata["evidence_id"])
                        try:
                            self.save()
                        except DurableCommitError as dce:
                            if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                                self.reconcile_from_disk()
                                raise
                            prev.clear()
                            prev.update(orig_prev)
                            if orig_eids:
                                prev["evidence_ids"] = orig_eids
                            else:
                                prev.pop("evidence_ids", None)
                            raise
                        except Exception:
                            prev.clear()
                            prev.update(orig_prev)
                            if orig_eids:
                                prev["evidence_ids"] = orig_eids
                            else:
                                prev.pop("evidence_ids", None)
                            raise
                    return
                raise ValueError(f"Operation ID '{oid}' is already committed and single-use")

            enforce_lifecycle = (
                require_lifecycle_enforcement
                or getattr(self, "enforce_lifecycle", False)
                or (metadata is not None and (bool(metadata.get("require_lifecycle_enforcement")) or bool(metadata.get("require_lifecycle_persistence"))))
            )
            if enforce_lifecycle:
                raise InvalidStateTransitionError(
                    f"Direct creation of operation '{oid}' in COMMITTED state rejected; "
                    f"lifecycle must progress CREATED -> VALIDATED -> RESERVED -> EXECUTING -> COMMITTED"
                )

            rec = {
                "session_id": str(session_id),
                "pid": int(pid),
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "state": OperationLifecycleState.COMMITTED.value,
            }
            if metadata:
                for k, v in metadata.items():
                    if v is not None and v != "":
                        rec[k] = v
            if metadata and metadata.get("evidence_id"):
                rec["evidence_ids"] = [metadata["evidence_id"]]

            orig_ops = dict(self.used_operation_ids)
            self.used_operation_ids[oid] = rec
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                self.used_operation_ids = orig_ops
                raise
            except Exception:
                self.used_operation_ids = orig_ops
                raise

    def get_operation_lifecycle_state(self, op_id: str) -> Optional[OperationLifecycleState]:
        """Get the current lifecycle state of an operation, if recorded."""
        oid = validate_operation_id(op_id)
        with self._file_lock():
            self.load()
            rec = self.used_operation_ids.get(oid)
            if not rec:
                return None
            st = rec.get("state")
            if not st:
                return None
            try:
                return OperationLifecycleState(st)
            except ValueError:
                return None

    def get_operation_record(self, op_id: str) -> Optional[Dict[str, Any]]:
        """Return a detached copy of a durable operation record for receipt/evidence binding."""
        oid = validate_operation_id(op_id)
        with self._file_lock():
            self.load()
            rec = self.used_operation_ids.get(oid)
            return dict(rec) if isinstance(rec, dict) else None

    def transition_operation_lifecycle(
        self,
        op_id: str,
        session_id: str,
        pid: int,
        target_state: OperationLifecycleState,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Enforce strict validated one-way transitions on operation lifecycle."""
        oid = validate_operation_id(op_id)
        with self._file_lock():
            self.load()
            if oid not in self.used_operation_ids:
                if target_state != OperationLifecycleState.CREATED:
                    raise InvalidStateTransitionError(
                        f"Initial operation state must be CREATED, got {target_state.value}"
                    )
                rec = {
                    "session_id": str(session_id),
                    "pid": int(pid),
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                    "state": target_state.value,
                }
                if metadata:
                    for k, v in metadata.items():
                        if v is not None and v != "":
                            rec[k] = v
                orig_ops = dict(self.used_operation_ids)
                self.used_operation_ids[oid] = rec
                try:
                    self.save()
                except Exception:
                    self.used_operation_ids = orig_ops
                    raise
                return

            rec = self.used_operation_ids[oid]
            # Bind lifecycle identity: reject cross-session or cross-PID transitions
            prev_sess = rec.get("session_id")
            prev_pid = rec.get("pid")
            if prev_sess is not None and str(prev_sess) != str(session_id):
                conflict_event = {
                    "operation_id": oid,
                    "field_name": "session_id",
                    "existing_value": str(prev_sess),
                    "attempted_value": str(session_id),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                }
                if not hasattr(self, "identity_conflict_events"):
                    self.identity_conflict_events = []
                self.identity_conflict_events.append(conflict_event)
                try:
                    self.save()
                except Exception as save_err:
                    self.identity_conflict_events.pop()
                    raise ConflictAuditPersistenceError(
                        f"Failed to persist identity conflict audit event for operation '{oid}': {save_err}"
                    ) from save_err
                raise IdentityConflictError(
                    f"Cross-session lifecycle transition rejected for operation '{oid}': {prev_sess} vs {session_id}"
                )
            if prev_pid is not None and int(prev_pid) != int(pid):
                conflict_event = {
                    "operation_id": oid,
                    "field_name": "pid",
                    "existing_value": str(prev_pid),
                    "attempted_value": str(pid),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                }
                if not hasattr(self, "identity_conflict_events"):
                    self.identity_conflict_events = []
                self.identity_conflict_events.append(conflict_event)
                try:
                    self.save()
                except Exception as save_err:
                    self.identity_conflict_events.pop()
                    raise ConflictAuditPersistenceError(
                        f"Failed to persist identity conflict audit event for operation '{oid}': {save_err}"
                    ) from save_err
                raise IdentityConflictError(
                    f"Cross-PID lifecycle transition rejected for operation '{oid}': {prev_pid} vs {pid}"
                )

            curr_state_val = rec.get("state", OperationLifecycleState.CREATED.value)
            try:
                curr_state = OperationLifecycleState(curr_state_val)
            except ValueError:
                curr_state = OperationLifecycleState.CREATED

            # COMMITTED is strictly terminal
            if curr_state == OperationLifecycleState.COMMITTED:
                raise InvalidStateTransitionError(
                    f"Operation '{oid}' is already COMMITTED (terminal) and cannot transition to {target_state.value}"
                )

            # Terminal states cannot transition
            terminal_states = (
                OperationLifecycleState.REJECTED,
                OperationLifecycleState.FAILED,
                OperationLifecycleState.CANCELLED,
                OperationLifecycleState.ABORTED_ON_RESTART,
            )
            if curr_state in terminal_states:
                raise InvalidStateTransitionError(
                    f"Operation '{oid}' is in terminal state {curr_state.value} and cannot transition to {target_state.value}"
                )

            # Valid transitions mapping
            valid_next = {
                OperationLifecycleState.CREATED: (
                    OperationLifecycleState.VALIDATED,
                    OperationLifecycleState.REJECTED,
                ),
                OperationLifecycleState.VALIDATED: (
                    OperationLifecycleState.RESERVED,
                    OperationLifecycleState.REJECTED,
                    OperationLifecycleState.FAILED,
                ),
                OperationLifecycleState.RESERVED: (
                    OperationLifecycleState.EXECUTING,
                    OperationLifecycleState.FAILED,
                    OperationLifecycleState.ABORTED_ON_RESTART,
                ),
                OperationLifecycleState.EXECUTING: (
                    OperationLifecycleState.COMMITTED,
                    OperationLifecycleState.FAILED,
                    OperationLifecycleState.CANCELLED,
                    OperationLifecycleState.PARTIAL,
                    OperationLifecycleState.ABORTED_ON_RESTART,
                ),
            }

            allowed = valid_next.get(curr_state, ())
            if target_state not in allowed:
                raise InvalidStateTransitionError(
                    f"Invalid state transition for operation '{oid}': {curr_state.value} -> {target_state.value}. Allowed: {[s.value for s in allowed]}"
                )

            orig_ops = dict(self.used_operation_ids)
            rec["state"] = target_state.value
            rec["updated_at"] = datetime.now(timezone.utc).isoformat()
            if metadata:
                for k, v in metadata.items():
                    if v is not None and v != "":
                        rec[k] = v
            try:
                self.save()
            except Exception:
                self.used_operation_ids = orig_ops
                raise

    def bind_operation_receipt(self, op_id: str, receipt_id: str) -> None:
        """Atomically bind an issued receipt ID to a committed operation in trust store."""
        oid = validate_operation_id(op_id)
        with self._file_lock():
            self.load()
            rid = str(receipt_id)
            if oid not in self.used_operation_ids:
                raise ValueError(f"Operation '{oid}' not recorded in trust store")
            rec = self.used_operation_ids[oid]
            bound_rcpt = rec.get("receipt_id")
            if bound_rcpt and bound_rcpt != rid:
                raise ValueError(f"Operation '{oid}' is already bound to receipt '{bound_rcpt}', cannot bind to '{rid}'")
            orig_rcpt = bound_rcpt
            rec["receipt_id"] = rid
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                if orig_rcpt is None:
                    rec.pop("receipt_id", None)
                else:
                    rec["receipt_id"] = orig_rcpt
                raise
            except Exception:
                if orig_rcpt is None:
                    rec.pop("receipt_id", None)
                else:
                    rec["receipt_id"] = orig_rcpt
                raise

    def bind_operation_evidence(
        self,
        op_id: str,
        evidence_id: str,
        derived_from: Optional[Union[str, List[str]]] = None,
        parent_evidence_ids: Optional[List[str]] = None,
        parent_evidence_digest: Optional[str] = None,
    ) -> None:
        """Atomically bind an evidence ID to a committed operation in trust store."""
        oid = validate_operation_id(op_id)
        with self._file_lock():
            self.load()
            eid = str(evidence_id)
            if oid not in self.used_operation_ids:
                raise ValueError(f"Operation '{oid}' not recorded in trust store")
            rec = self.used_operation_ids[oid]
            eids = rec.setdefault("evidence_ids", [])
            if not eids and "evidence_id" in rec and rec["evidence_id"]:
                eids.append(rec["evidence_id"])
            if eid not in eids:
                if len(eids) > 0:
                    d_list = [derived_from] if isinstance(derived_from, str) else list(derived_from or [])
                    p_list = [parent_evidence_ids] if isinstance(parent_evidence_ids, str) else list(parent_evidence_ids or [])
                    has_valid_derivation = any(d in eids for d in d_list) or any(p in eids for p in p_list)
                    if not has_valid_derivation:
                        raise ValueError(
                            f"Multi-evidence operation '{oid}' rejected: secondary evidence '{eid}' lacks "
                            f"verifiable derivation from primary observation '{eids[0]}'."
                        )
                orig_eids = list(eids)
                eids.append(eid)
                if parent_evidence_digest:
                    pdigs = rec.setdefault("parent_digests", {})
                    pdigs[eid] = str(parent_evidence_digest)
                try:
                    self.save()
                except DurableCommitError as dce:
                    if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                        self.reconcile_from_disk()
                        raise
                    rec["evidence_ids"] = orig_eids
                    raise
                except Exception:
                    rec["evidence_ids"] = orig_eids
                    raise
            else:
                # Idempotent re-bind: ensure parent_evidence_digest does not conflict
                if parent_evidence_digest and "parent_digests" in rec and eid in rec["parent_digests"]:
                    existing_digest = rec["parent_digests"][eid]
                    if str(existing_digest) != str(parent_evidence_digest):
                        raise ValueError(
                            f"Conflicting parent digest for evidence '{eid}' under operation '{oid}': "
                            f"existing='{existing_digest}', provided='{parent_evidence_digest}'"
                        )

    def is_operation_used(self, op_id: str) -> bool:
        oid = validate_operation_id(op_id)
        with self._file_lock():
            self.load()
            return oid in self.used_operation_ids

    def resolve_key(self, key_id: str) -> str:
        with self._file_lock():
            self.load()
            kid = str(key_id)
            if kid in self.revoked_keys:
                raise ValueError(f"Key '{kid}' is revoked")
            if kid in self.keys:
                return self.keys[kid]
            raise KeyError(f"Key '{kid}' not found in trust store")


_DEFAULT_TRUST_STORE: Optional[DurableTrustStore] = None


def get_default_trust_store() -> Optional[DurableTrustStore]:
    global _DEFAULT_TRUST_STORE
    if _DEFAULT_TRUST_STORE is None:
        ts_env = os.environ.get("DYNAMICSTATE_TRUST_STORE_PATH")
        if ts_env:
            _DEFAULT_TRUST_STORE = DurableTrustStore(ts_env)
    return _DEFAULT_TRUST_STORE


def set_default_trust_store(ts: Optional[DurableTrustStore]) -> None:
    global _DEFAULT_TRUST_STORE
    _DEFAULT_TRUST_STORE = ts


