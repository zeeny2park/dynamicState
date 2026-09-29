"""Address-independent deterministic semantic state hashing for Phase 4.

The semantic state hash captures the execution call stack structure and the
reachable semantic object graph while strictly excluding transient, process-local,
or environment-dependent details:
- Raw heap, stack, or global memory addresses (ASLR-independent)
- Thread IDs and process PIDs
- Timestamps and performance metrics
- Host filesystem paths in memory maps
- Physical storage classification (heap/stack/global): excluded to guarantee
  pure semantic state equivalence regardless of whether an object was allocated
  on the stack or heap across runs or restarts.
"""

from collections import deque
import hashlib
from typing import Any, Dict, List, Set, Tuple


def _canonicalize_object_graph(data: Dict[str, Any]) -> Tuple[Tuple[Any, ...], ...]:
    """Build an address-independent canonical representation of the object graph.

    Assigns topological canonical IDs (C_0, C_1, ...) to objects in deterministic
    traversal order starting from sorted semantic roots.
    Pointer references are represented by relative canonical target IDs ('self',
    'ref:C_1', 'null'), preventing recursion loops on cyclic graphs.
    """
    persistent = data.get("persistent") or {}
    INTERNAL_SYNC_SUBSTRINGS = (
        "_condvar_cleanup_buffer",
        "_pthread_cleanup_buffer",
        "pthread_cond",
        "pthread_mutex",
        "pthread_rwlock",
        "pthread_barrier",
        "__pthread_cond_s",
        "__pthread_mutex_s",
        "condition_variable",
        "std::mutex",
        "std::__mutex_base",
        "thread::id",
    )
    SCHEDULER_METADATA_FIELDS = {
        "wseq", "__wseq", "__futex", "__owner", "__cur_writer",
        "__lock", "__arg", "__canceltype", "__routine",
        "__g1_orig_size", "__g1_start", "__g_refs", "__g_signals",
        "__g_size", "__wrefs", "__align", "__data", "__size",
        "__id", "_M_thread", "_M_id", "__native_handle"
    }

    raw_objects = []
    for obj in (persistent.get("objects", []) or []):
        t = str(obj.get("type", ""))
        if any(sub in t for sub in INTERNAL_SYNC_SUBSTRINGS):
            continue
        fnames = {f.get("name") for f in obj.get("fields", [])}
        if fnames and fnames.issubset(SCHEDULER_METADATA_FIELDS):
            continue
        raw_objects.append(obj)

    raw_roots = [
        root for root in (persistent.get("roots", []) or [])
        if not any(sub in str(root.get("type", "")) for sub in INTERNAL_SYNC_SUBSTRINGS)
        and not any(str(root.get("function", "")).startswith(p) for p in ("__pthread", "___pthread", "__GI___", "clone"))
    ]

    obj_by_id: Dict[str, Dict[str, Any]] = {
        obj.get("object_id"): obj for obj in raw_objects if obj.get("object_id")
    }

    # 1. Determine canonical ordering of objects from roots
    canonical_id_map: Dict[str, str] = {}
    visited_order: List[str] = []
    visited_set: Set[str] = set()

    # Sort roots deterministically by (source, name, type)
    sorted_roots = sorted(
        raw_roots,
        key=lambda r: (str(r.get("source", "")), str(r.get("name", "")), str(r.get("type", "")))
    )

    queue: deque = deque()
    for root in sorted_roots:
        target_ref = root.get("object_ref")
        if target_ref and target_ref in obj_by_id and target_ref not in visited_set:
            visited_set.add(target_ref)
            visited_order.append(target_ref)
            queue.append(target_ref)

    # Breadth-first traversal of object graph
    while queue:
        curr_id = queue.popleft()
        curr_obj = obj_by_id.get(curr_id, {})
        for f in sorted(curr_obj.get("fields", []), key=lambda x: str(x.get("name", ""))):
            fname = str(f.get("name", ""))
            if fname in SCHEDULER_METADATA_FIELDS:
                continue
            ref = f.get("object_ref")
            if ref and ref in obj_by_id and ref not in visited_set:
                visited_set.add(ref)
                visited_order.append(ref)
                queue.append(ref)

    # Any unreferenced objects (if present) appended in deterministic type/content order
    remaining = [oid for oid in obj_by_id if oid not in visited_set]
    remaining.sort(key=lambda oid: (
        str(obj_by_id[oid].get("type", "")),
        str([(f.get("name"), str(f.get("value"))) for f in obj_by_id[oid].get("fields", []) if str(f.get("name", "")) not in SCHEDULER_METADATA_FIELDS])
    ))
    for oid in remaining:
        visited_order.append(oid)

    for idx, oid in enumerate(visited_order):
        canonical_id_map[oid] = "C_{}".format(idx)

    # 2. Build canonical object descriptors (excluding physical memory storage layout)
    canonical_objects: List[Tuple[Any, ...]] = []
    for oid in visited_order:
        obj = obj_by_id[oid]
        cid = canonical_id_map[oid]
        obj_type = str(obj.get("type", ""))

        fields_repr: List[Tuple[str, Any, Any]] = []
        for f in sorted(obj.get("fields", []), key=lambda x: str(x.get("name", ""))):
            fname = str(f.get("name", ""))
            if fname in SCHEDULER_METADATA_FIELDS:
                continue
            ftype = str(f.get("type", ""))
            avail = f.get("availability")
            obj_ref = f.get("object_ref")
            val = f.get("value")

            if obj_ref:
                if obj_ref == oid:
                    semantic_val = "self"
                elif obj_ref in canonical_id_map:
                    semantic_val = "ref:{}".format(canonical_id_map[obj_ref])
                else:
                    semantic_val = "ref:unknown"
            elif ftype.endswith("*") or "pointer" in ftype.lower():
                if val in ("0x0", "null", "nullptr", None, 0):
                    semantic_val = "null"
                else:
                    semantic_val = "non_null_pointer"
            elif isinstance(val, str) and (val.startswith("@0x") or (val.startswith("0x") and len(val) >= 6)):
                if val in ("0x0", "@0x0"):
                    semantic_val = "null"
                else:
                    semantic_val = "non_null_pointer"
            else:
                semantic_val = val

            fields_repr.append((fname, semantic_val, avail))

        canonical_objects.append((cid, obj_type, tuple(fields_repr)))

    return tuple(canonical_objects)


def compute_state_hash(snapshot: Any) -> str:
    """Compute an address-independent deterministic 16-hex semantic state hash.

    Excludes raw memory addresses, thread IDs, process PIDs, timestamps,
    physical storage classifications, memory map file paths, and internal OS
    thread scheduling metadata.
    """
    data = snapshot.to_dict() if hasattr(snapshot, "to_dict") else snapshot
    canonical: List[Any] = []

    # 1. Execution context: thread call stack semantic functions (no thread_id / no PC)
    threads = (data.get("execution") or {}).get("threads", [])
    threads_canonical = []
    internal_prefixes = (
        "__pthread", "___pthread", "__GI_", "__GI___", "clone",
        "__futex", "futex", "__syscall", "syscall", "start_thread", "thread_start"
    )
    for thread in threads:
        frames = thread.get("frames", [])
        filtered_funcs = tuple(
            str(frame.get("function")) for frame in frames
            if frame.get("function") and not any(str(frame.get("function") or "").startswith(p) for p in internal_prefixes)
        )
        threads_canonical.append((len(filtered_funcs), filtered_funcs))
    threads_canonical.sort()
    canonical.append(("execution", tuple(threads_canonical)))

    # 2. Persistent Object Graph canonicalization
    canonical_graph = _canonicalize_object_graph(data)
    canonical.append(("objects", canonical_graph))

    canonical_bytes = repr(canonical).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()[:16]
