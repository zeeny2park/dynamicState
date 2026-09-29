# dynamicState — GDB Compatibility & Verification Matrix

## 1. Overview & Verification Taxonomy

Embedded and server development environments utilize a wide span of GDB releases—from legacy LTS releases (GDB 9.2 on Ubuntu 20.04 or Yocto Dunfell) to cutting-edge debuggers (GDB 14/15 on modern Linux distributions).

To prevent overclaiming and maintain strict technical honesty, dynamicState categorizes its compatibility claims under four rigorous verification levels:

| Verification Level | Definition |
| :--- | :--- |
| **DESIGN** | Feature is designed according to GDB Python API documentation and specifications. |
| **MOCK / UNIT VERIFIED** | Validated via Python unit test suite against mock GDB modules and synthesized failure modes. |
| **REAL GDB 9.2 VERIFIED** | Executed and asserted against genuine GNU gdb 9.2 binary (`Ubuntu 9.2-0ubuntu1~20.04.2`) in containerized integration test suite (`tests/integration_gdb92.py`). |
| **REAL TARGET VALIDATED** | Executed against real running Linux target processes with live memory extraction. |

---

## 2. GDB Version Compatibility Matrix

| GDB Version | Status / Verification Level | `Frame.level()` Handling | Version Parsing (`get_gdb_version`) | Stack & Object Traversal | External Debug Image |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **GDB < 9.0** | **UNSUPPORTED** | N/A | Returns `status="RESOLVED"`, marks incompatible | Unsupported | Unsupported |
| **GDB 9.2** | **REAL GDB 9.2 VERIFIED** | Missing; falls back to caller depth without `AttributeError` | `(9, 2, "9.2")`, `supports_frame_level()=False` | Verified (live frames, structs, pointers) | Verified (`.gnu_debuglink`, Build ID) |
| **GDB 10.x** | **UNIT TESTED** | Missing; falls back to caller depth | `(10, x, ...)`, `supports_frame_level()=False` | Designed & Unit Tested | Designed & Unit Tested |
| **GDB 11.x** | **UNIT TESTED** | Supported natively by GDB | `(11, x, ...)`, `supports_frame_level()=True` | Designed & Unit Tested | Designed & Unit Tested |
| **GDB 12 - 14** | **UNIT TESTED** | Supported natively | `(12..14, x, ...)`, `supports_frame_level()=True` | Designed & Unit Tested | Designed & Unit Tested |
| **GDB 15.1** | **REAL TARGET VALIDATED** | Supported natively | `(15, 1, "15.1")`, `supports_frame_level()=True` | Verified natively on Ubuntu 24.04 (host) | Verified natively |
| **Unknown / None** | **UNIT TESTED** | Conservative fallback | `status="UNKNOWN"`, `major=None`, `minor=None` | Safe degradation | Conservative |

---

## 3. Key Compatibility Mechanisms in `extractor/gdb_compat.py`

### 3.1. Elimination of Silent Version Fallback
Previous implementations silently defaulted missing GDB modules to `(9, 2, "9.2")`.
Under dynamicState's **Uncertainty-First** principle, unknown GDB environments return:
```python
GdbVersion(major=None, minor=None, raw="UNKNOWN", status="UNKNOWN")
```
No assumptions or guessed version numbers are ever injected.

### 3.2. `Frame.level()` Graceful Degradation
`gdb.Frame.level()` was only introduced in GDB 11.0. In GDB 9.2 and 10.x, invoking `frame.level()` raises:
```
AttributeError: 'gdb.Frame' object has no attribute 'level'
```
`get_frame_level(frame, fallback_level)` intercepts this condition:
```python
def get_frame_level(frame: Any, fallback_level: int = 0) -> int:
    if frame is None:
        return fallback_level
    if hasattr(frame, "level") and callable(getattr(frame, "level")):
        try:
            return int(frame.level())
        except Exception:
            pass
    return fallback_level
```
In `extractor/execution.py`, `current_level` is tracked during `.older()` traversal, guaranteeing accurate frame indices across all GDB versions.

---

## 4. Reproducing Real GDB 9.2 Verification

To execute the genuine GDB 9.2 verification test suite:

```bash
# 1. Build the GDB 9.2 verification container (Ubuntu 20.04 LTS)
docker build -t dynamicstate-gdb92:latest docker/gdb92

# 2. Run the integration test suite
docker run --rm -v $(pwd):/workspace dynamicstate-gdb92:latest python3 tests/integration_gdb92.py --direct
```

Expected output:
```
=== GDB 9.2 Verification Environment ===
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.2) 9.2
Python 3.8.10
=== Running dynamicState GDB 9.2 Integration Tests ===
_run_native_gdb92_verification (__main__.RealGdb92IntegrationTests)
Execute the real GDB 9.2 test scenario natively. ... REAL_GDB_9_2_VERIFICATION_PASS
ok
```
