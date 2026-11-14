"""Validated decoding of C++ standard-library containers that own heap memory (roadmap stage 3).

The default diagnosis names the variable that owns growing heap blocks by a typed path.  For a C++ container that
path runs through the library's private members (``g_registry._M_impl._M_start[*]``,
``g_sessions._M_t._M_impl._M_header._M_parent([*]._M_right)*...``).  This module

* recognises the container types of GNU libstdc++ (C++11 ABI) from DWARF: ``std::vector``, ``std::string``,
  ``std::map`` / ``multimap`` / ``set`` / ``multiset``, ``std::unordered_map`` / ``unordered_set`` (and multi),
  ``std::deque``, ``std::list``, ``std::shared_ptr`` / ``weak_ptr``, ``std::unique_ptr``.  The layout is taken from the
  DWARF member names and offsets (``_M_start``, ``_M_node_count``, ``_M_element_count`` ...), never from fixed offsets:
  a type whose members are not found (libc++, the pre-C++11 ``std::string`` ABI, a user type that happens to be
  called ``vector``) is reported as "not decodable" with the reason, and the raw behaviour stays;
* rewrites a reachability path through those private members to the container (``g_registry[*]``: a block
  reached through an element, ``g_registry``: the container's own storage);
* decodes one container instance (header plus at most a few small reads) through a caller-supplied reader (the
  heap analysis's budgeted reader, or the target adapter of the web exploration) and validates it before anything is
  presented: begin <= end <= capacity, element-size divisibility, every pointer inside a mapped writable region and
  the storage block size of the heap walk, the tree / list / hash-chain back links of the first node, the deque map
  holding its own iterators' buffers, the control block's counts against the owner's existence.  Any failed check
  makes the result ``decoded: false`` with the reason; no value of a failed decode is reported.

No target access happens at import; the module reads only through the ``ContainerMemory`` it is given.
"""

import re
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

_STRUCT_TAGS = ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type")
_PTR_TAGS = ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type")

K_VECTOR = "std::vector"
K_STRING = "std::string"
K_MAP = "std::map"
K_MULTIMAP = "std::multimap"
K_SET = "std::set"
K_MULTISET = "std::multiset"
K_UMAP = "std::unordered_map"
K_UMULTIMAP = "std::unordered_multimap"
K_USET = "std::unordered_set"
K_UMULTISET = "std::unordered_multiset"
K_DEQUE = "std::deque"
K_LIST = "std::list"
K_SHARED = "std::shared_ptr"
K_WEAK = "std::weak_ptr"
K_UNIQUE = "std::unique_ptr"

TREE_KINDS = (K_MAP, K_MULTIMAP, K_SET, K_MULTISET)
HASH_KINDS = (K_UMAP, K_UMULTIMAP, K_USET, K_UMULTISET)
SMART_KINDS = (K_SHARED, K_WEAK, K_UNIQUE)

# template name (namespace std stripped) -> (kind, number of template arguments shown)
_NAME_KINDS: Tuple[Tuple[str, str, int], ...] = (
    ("vector<", K_VECTOR, 1), ("multimap<", K_MULTIMAP, 2), ("map<", K_MAP, 2), ("multiset<", K_MULTISET, 1),
    ("set<", K_SET, 1), ("unordered_multimap<", K_UMULTIMAP, 2), ("unordered_map<", K_UMAP, 2),
    ("unordered_multiset<", K_UMULTISET, 1), ("unordered_set<", K_USET, 1), ("deque<", K_DEQUE, 1),
    ("list<", K_LIST, 1), ("shared_ptr<", K_SHARED, 1), ("weak_ptr<", K_WEAK, 1), ("unique_ptr<", K_UNIQUE, 1),
)

# Plausibility limits (independent of the mapping checks, which are the main bound)
MAX_ELEMENTS = 1 << 32
MAX_REFCOUNT = 1 << 24
DEQUE_BUF_BYTES = 512               # libstdc++ _GLIBCXX_DEQUE_BUF_SIZE
MAX_ATTEMPTS = 6                    # reads of a container whose header changed while it was being validated


def _strip_ns(name: str) -> str:
    s = (name or "").strip()
    for pfx in ("const ", "volatile "):
        if s.startswith(pfx):
            s = s[len(pfx):]
    for pfx in ("struct ", "class "):
        if s.startswith(pfx):
            s = s[len(pfx):]
    for pfx in ("std::__cxx11::", "std::"):
        if s.startswith(pfx):
            s = s[len(pfx):]
    return s


def template_args(name: str) -> List[str]:
    """Top-level template arguments of ``name`` (``map<long, std::pair<int, int> >`` -> ['long', 'std::pair<...>'])."""
    i = name.find("<")
    if i < 0 or not name.rstrip().endswith(">"):
        return []
    body = name[i + 1:name.rstrip().rfind(">")]
    out, depth, cur = [], 0, []
    for ch in body:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _short(t: str) -> str:
    """Readable element type: std:: kept, the __cxx11 inline namespace and trailing spaces in '> >' dropped."""
    return re.sub(r"\s+>", ">", (t or "").replace("std::__cxx11::", "std::")).strip()


@dataclass
class ContainerLayout:
    """Layout of one container type, from DWARF member names (offsets relative to the container object)."""
    kind: str
    type_name: str                       # readable, e.g. std::vector<Record*>
    byte_size: int
    off: Dict[str, int] = field(default_factory=dict)
    elem_size: int = 0
    elem_type: Optional[str] = None
    pointee_type: Optional[str] = None
    # shared_ptr control block (_Sp_counted_base) member offsets
    cb_use: Optional[int] = None
    cb_weak: Optional[int] = None
    unsupported: Optional[str] = None    # recognised by name, layout not decodable (reason)

    def to_dict(self) -> Dict[str, Any]:
        d = {"kind": self.kind, "type": self.type_name}
        if self.elem_type:
            d["element_type"] = self.elem_type
        if self.unsupported:
            d["unsupported"] = self.unsupported
        return d


class _Types:
    """DWARF helpers over one ``DwarfIndex``."""

    def __init__(self, idx: Any, pointer_size: int = 8):
        self.idx = idx
        self.ps = pointer_size

    def canon(self, off: Optional[int]):
        return self.idx.resolve_canonical_type(off) if off is not None else None

    def size(self, off: Optional[int]) -> int:
        t = self.canon(off)
        if t is None:
            return 0
        if t.tag in _PTR_TAGS:
            return self.ps
        if t.tag == "DW_TAG_array_type" and not t.byte_size and t.array_count:
            return int(t.array_count) * self.size(t.target_type_offset)
        return int(t.byte_size or 0)

    def name(self, off: Optional[int]) -> str:
        t = self.canon(off)
        if t is None:
            return "?"
        if t.tag in _PTR_TAGS:
            return self.name(t.target_type_offset) + "*"
        try:
            return self.idx.get_type_name(off) or t.name or "?"
        except Exception:  # noqa: BLE001
            return t.name or "?"

    def find(self, t: Any, wanted: str, base: int = 0, depth: int = 0,
             pred: Optional[Callable[[Optional[int]], bool]] = None) -> Optional[Tuple[int, Optional[int]]]:
        """(offset, member type) of the first member called ``wanted`` in ``t`` (whose type satisfies ``pred``): its
        own members, base classes, and named struct members (so ``_M_impl._M_start`` is found from the vector)."""
        if t is None or depth > 8:
            return None
        for m in t.members:
            if m.name == wanted and (pred is None or pred(m.type_offset)):
                return base + int(m.offset or 0), m.type_offset
        for b in getattr(t, "base_classes", []) or []:
            hit = self.find(self.canon(b.type_offset), wanted, base + int(b.offset or 0), depth + 1, pred)
            if hit:
                return hit
        for m in t.members:
            mt = self.canon(m.type_offset)
            if mt is not None and mt.tag in _STRUCT_TAGS:
                hit = self.find(mt, wanted, base + int(m.offset or 0), depth + 1, pred)
                if hit:
                    return hit
        return None

    def is_pointer(self, off: Optional[int]) -> bool:
        t = self.canon(off)
        return t is not None and t.tag in _PTR_TAGS

    def member(self, t: Any, name: str) -> Optional[Tuple[int, Optional[int]]]:
        """Direct member or member of a base class (not descending into named members)."""
        if t is None:
            return None
        for m in t.members:
            if m.name == name:
                return int(m.offset or 0), m.type_offset
        for b in getattr(t, "base_classes", []) or []:
            hit = self.member(self.canon(b.type_offset), name)
            if hit:
                return int(b.offset or 0) + hit[0], hit[1]
        return None


def _kind_of(type_name: str) -> Optional[Tuple[str, int]]:
    n = _strip_ns(type_name)
    if n.startswith("basic_string<"):
        return K_STRING, 0
    for pfx, kind, nargs in _NAME_KINDS:
        if n.startswith(pfx):
            return kind, nargs
    return None


def classify(idx: Any, type_off: Optional[int]) -> Optional[ContainerLayout]:
    """Layout of the container type at ``type_off`` (typedefs/const resolved); None when it is not a container.

    A layout with ``unsupported`` set is a container by name whose libstdc++ members were not found."""
    cache = getattr(idx, "_cpp_container_layouts", None)
    if cache is None:
        cache = {}
        try:
            setattr(idx, "_cpp_container_layouts", cache)
        except (AttributeError, TypeError):
            pass
    if type_off in cache:
        return cache[type_off]
    out = _classify(idx, type_off)
    cache[type_off] = out
    return out


def _classify(idx: Any, type_off: Optional[int]) -> Optional[ContainerLayout]:
    ty = _Types(idx, int(getattr(idx, "pointer_size", 0) or 8))
    t = ty.canon(type_off)
    if t is None or t.tag not in _STRUCT_TAGS or not t.name:
        return None
    hit = _kind_of(t.name)
    if hit is None:
        return None
    kind, nargs = hit
    args = template_args(t.name)
    if kind == K_STRING:
        shown = "std::string" if (args and args[0] == "char") else "std::basic_string<%s>" % (args[0] if args else "?")
    else:
        shown = "%s<%s>" % (kind, ", ".join(_short(a) for a in args[:nargs]))
    lay = ContainerLayout(kind=kind, type_name=shown, byte_size=int(t.byte_size or 0))
    if "__1::" in t.name or "__1::" in t.name.replace(" ", ""):
        lay.unsupported = "libc++ layout (only GNU libstdc++ is decoded)"
        return lay
    ps = ty.ps

    def need(*names: str, within: Any = None, base: int = 0) -> Optional[Dict[str, Tuple[int, Optional[int]]]]:
        got = {}
        for n in names:
            h = ty.find(within if within is not None else t, n)
            if h is None:
                return None
            got[n] = (base + h[0], h[1])
        return got

    def ptr_target(toff: Optional[int]) -> Optional[int]:
        pt = ty.canon(toff)
        return pt.target_type_offset if pt is not None and pt.tag in _PTR_TAGS else None

    if kind == K_VECTOR:
        if args and args[0] == "bool":
            lay.unsupported = "std::vector<bool> is a bit vector (not decoded)"
            return lay
        g = need("_M_start", "_M_finish", "_M_end_of_storage")
        if g is None or lay.byte_size != 3 * ps:
            lay.unsupported = "std::vector members _M_start/_M_finish/_M_end_of_storage not found (not libstdc++?)"
            return lay
        et = ptr_target(g["_M_start"][1])
        lay.elem_size = ty.size(et) if et is not None else 0
        lay.elem_type = _short(args[0]) if args else ty.name(et)
        if lay.elem_size <= 0:
            lay.unsupported = "element size of %s unknown" % shown
            return lay
        lay.off = {k: v[0] for k, v in g.items()}
        return lay
    if kind == K_STRING:
        g = need("_M_p", "_M_string_length", "_M_local_buf")
        if g is None or lay.byte_size != 4 * ps:
            lay.unsupported = ("std::string members _M_p/_M_string_length/_M_local_buf not found (old copy-on-write ABI "
                               "or not libstdc++)")
            return lay
        cap = ty.find(t, "_M_allocated_capacity")
        if cap is None or cap[0] != g["_M_local_buf"][0] or not args or args[0] != "char":
            lay.unsupported = "only std::string (char, C++11 ABI) is decoded"
            return lay
        lay.off = {k: v[0] for k, v in g.items()}
        lay.off["_M_allocated_capacity"] = cap[0]
        lay.elem_size = 1
        lay.elem_type = "char"
        return lay
    if kind in TREE_KINDS:
        g = need("_M_header", "_M_node_count")
        if g is None:
            lay.unsupported = "red-black tree members _M_header/_M_node_count not found (not libstdc++?)"
            return lay
        hdr = ty.canon(g["_M_header"][1])
        links = {n: ty.member(hdr, n) for n in ("_M_parent", "_M_left", "_M_right")}
        if hdr is None or any(v is None for v in links.values()):
            lay.unsupported = "red-black tree node links not found"
            return lay
        lay.off = {"_M_header": g["_M_header"][0], "_M_node_count": g["_M_node_count"][0]}
        lay.off.update({"node" + n: v[0] for n, v in links.items()})
        lay.off["node_size"] = int(hdr.byte_size or 0)
        lay.elem_type = ", ".join(_short(a) for a in args[:nargs])
        return lay
    if kind in HASH_KINDS:
        g = need("_M_buckets", "_M_bucket_count", "_M_before_begin", "_M_element_count", "_M_single_bucket")
        if g is None:
            lay.unsupported = "hash table members _M_buckets/_M_element_count not found (not libstdc++?)"
            return lay
        nxt = ty.member(ty.canon(g["_M_before_begin"][1]), "_M_nxt")
        if nxt is None:
            lay.unsupported = "hash table node link _M_nxt not found"
            return lay
        lay.off = {k: v[0] for k, v in g.items()}
        lay.off["node_nxt"] = nxt[0]
        mlf = ty.find(t, "_M_max_load_factor")
        if mlf is not None:
            lay.off["_M_max_load_factor"] = mlf[0]
        lay.elem_type = ", ".join(_short(a) for a in args[:nargs])
        return lay
    if kind == K_DEQUE:
        g = need("_M_map", "_M_map_size", "_M_start", "_M_finish")
        if g is None:
            lay.unsupported = "std::deque members _M_map/_M_start/_M_finish not found (not libstdc++?)"
            return lay
        it = ty.canon(g["_M_start"][1])
        its = {n: ty.member(it, n) for n in ("_M_cur", "_M_first", "_M_last", "_M_node")}
        if it is None or any(v is None for v in its.values()):
            lay.unsupported = "std::deque iterator members not found"
            return lay
        et = ptr_target(its["_M_cur"][1])
        lay.elem_size = ty.size(et) if et is not None else 0
        lay.elem_type = _short(args[0]) if args else ty.name(et)
        if lay.elem_size <= 0:
            lay.unsupported = "element size of %s unknown" % shown
            return lay
        lay.off = {"_M_map": g["_M_map"][0], "_M_map_size": g["_M_map_size"][0], "_M_start": g["_M_start"][0],
                   "_M_finish": g["_M_finish"][0]}
        lay.off.update({"it" + n: v[0] for n, v in its.items()})
        return lay
    if kind == K_LIST:
        g = need("_M_node")
        hdr = ty.canon(g["_M_node"][1]) if g else None
        links = {n: ty.member(hdr, n) for n in ("_M_next", "_M_prev", "_M_size")} if hdr is not None else {}
        if g is None or not links or any(v is None for v in links.values()):
            lay.unsupported = "std::list members _M_node/_M_next/_M_size not found (old ABI without a stored size?)"
            return lay
        lay.off = {"_M_node": g["_M_node"][0]}
        lay.off.update({"node" + n: v[0] for n, v in links.items()})
        lay.elem_type = _short(args[0]) if args else None
        return lay
    if kind in (K_SHARED, K_WEAK):
        g = need("_M_ptr", "_M_pi")
        if g is None or lay.byte_size != 2 * ps:
            lay.unsupported = "%s members _M_ptr/_M_refcount._M_pi not found (not libstdc++?)" % kind
            return lay
        cb = ty.canon(ptr_target(g["_M_pi"][1]))
        use, weak = ty.member(cb, "_M_use_count"), ty.member(cb, "_M_weak_count")
        if cb is None or use is None or weak is None or ty.size(use[1]) != 4 or ty.size(weak[1]) != 4:
            lay.unsupported = "control block counts _M_use_count/_M_weak_count not found"
            return lay
        lay.off = {k: v[0] for k, v in g.items()}
        lay.cb_use, lay.cb_weak = use[0], weak[0]
        lay.pointee_type = _short(args[0]) if args else ty.name(ptr_target(g["_M_ptr"][1]))
        return lay
    if kind == K_UNIQUE:
        hp = ty.find(t, "_M_head_impl", pred=ty.is_pointer)
        if hp is None:
            lay.unsupported = "std::unique_ptr pointer member _M_head_impl not found (not libstdc++?)"
            return lay
        lay.off = {"_M_head_impl": hp[0]}
        lay.pointee_type = _short(args[0]) if args else None
        return lay
    return None


# ------------------------------------------------------------------------------------------------- path rewriting
# (internal path prefix, replacement, keep the rest of the path).  Matched after the container's own path.
_INTERNAL_PATHS: Dict[str, Tuple[Tuple[str, str, bool], ...]] = {
    K_VECTOR: (("._M_impl._M_start[", "[*]", True), ("._M_impl._M_start(", "[*]", False),
               ("._M_impl._M_start", "", False),
               ("._M_impl._M_finish", "", False), ("._M_impl._M_end_of_storage", "", False)),
    K_STRING: (("._M_dataplus._M_p", "", False),),
    K_DEQUE: (("._M_impl._M_map", "", False), ("._M_impl._M_start", "", False), ("._M_impl._M_finish", "", False)),
    K_LIST: (("._M_impl._M_node", "[*]", False),),
    K_SHARED: (("._M_ptr", "", True), ("._M_refcount._M_pi", "", False)),
    K_WEAK: (("._M_ptr", "", True), ("._M_refcount._M_pi", "", False)),
    K_UNIQUE: (("._M_t._M_t._M_head_impl", "", True), ("._M_t._M_head_impl", "", True)),
}
for _k in TREE_KINDS:
    _INTERNAL_PATHS[_k] = (("._M_t._M_impl._M_header", "[*]", False),)
for _k in HASH_KINDS:
    _INTERNAL_PATHS[_k] = (("._M_h._M_buckets[", "[*]", False), ("._M_h._M_buckets", "", False),
                           ("._M_h._M_before_begin", "[*]", False), ("._M_h._M_single_bucket", "[*]", False))

def rewrite_internal(kind: str, rest: str) -> Optional[str]:
    """``rest`` = the path after the container's own path.  Returns the replacement suffix, or None when ``rest`` does
    not go through the container's private members."""
    for pfx, repl, keep in _INTERNAL_PATHS.get(kind, ()):
        if rest.startswith(pfx):
            tail = rest[len(pfx):]
            if pfx.endswith("["):                      # the element index: drop it (the replacement is "[*]")
                j = tail.find("]")
                tail = tail[j + 1:] if j >= 0 else ""
            if tail and tail[0] not in ".-[(":
                continue                                # a longer member name that merely starts like the prefix
            return repl + (tail if keep else "")
    return None


@dataclass
class ContainerRef:
    """A container found on a variable path: ``path`` (e.g. ``g_state.items``), its layout and runtime address."""
    path: str
    layout: ContainerLayout
    address: Optional[int]
    module: Optional[str] = None


class ContainerPaths:
    """Resolves variable paths of the reachability analysis to the C++ container they run through (cached).

    ``modules`` are the analysis modules: ``(name, DwarfIndex, load bias, is_dyn)``."""

    def __init__(self, modules: Sequence[Tuple[str, Any, int, bool]]):
        self.modules = list(modules)
        self._cache: Dict[Tuple[Optional[str], str], Optional[Tuple[ContainerRef, str]]] = {}

    def _var(self, mi: int, name: str) -> Optional[Any]:
        idx = self.modules[mi][1]
        table = getattr(idx, "_cpp_container_vars", None)
        if table is None:
            by: Dict[str, Dict[int, Any]] = {}
            for v in list(idx.global_variables) + list(idx.static_variables):
                if v.name and v.link_time_address is not None and not v.is_declaration:
                    by.setdefault(v.name, {})[v.link_time_address] = v
            # two statics of the same name in different files: a path naming only the root does not say which one
            table = {n: (next(iter(h.values())) if len(h) == 1 else None) for n, h in by.items()}
            try:
                setattr(idx, "_cpp_container_vars", table)
            except (AttributeError, TypeError):
                pass
        return table.get(name)

    def resolve(self, module: Optional[str], path: str) -> Optional[Tuple[ContainerRef, str]]:
        """(container, rewritten path) for ``path`` (``root.member...``) when it runs through a container's private
        members; None otherwise.  ``module`` is the root's module name (None: the main executable)."""
        key = (module, path)
        if key in self._cache:
            return self._cache[key]
        out = self._resolve(module, path)
        self._cache[key] = out
        return out

    def _module_index(self, module: Optional[str]) -> Optional[int]:
        for mi, m in enumerate(self.modules):
            if module is None or m[0] == module:
                return mi
        return None

    def _resolve(self, module: Optional[str], path: str) -> Optional[Tuple[ContainerRef, str]]:
        m = re.match(r"^([A-Za-z_]\w*)", path or "")
        mi = self._module_index(module)
        if not m or mi is None:
            return None
        name, idx, bias, is_dyn = self.modules[mi]
        var = self._var(mi, m.group(1))
        if var is None:
            return None
        ty = _Types(idx, int(getattr(idx, "pointer_size", 0) or 8))
        toff = var.type_offset
        off = 0
        pos = len(m.group(1))
        while True:
            lay = classify(idx, toff)
            if lay is not None:
                rest = path[pos:]
                if lay.unsupported:
                    return None
                repl = rewrite_internal(lay.kind, rest)
                if repl is None:
                    return None
                base = (bias + var.link_time_address) if is_dyn else var.link_time_address
                ref = ContainerRef(path=path[:pos], layout=lay, address=base + off, module=name)
                return ref, path[:pos] + repl
            mm = re.match(r"^\.([A-Za-z_]\w*)", path[pos:])
            if not mm:
                return None
            t = ty.canon(toff)
            if t is None or t.tag not in _STRUCT_TAGS:
                return None
            hit = ty.member(t, mm.group(1))
            if hit is None:
                return None
            off += hit[0]
            toff = hit[1]
            pos += len(mm.group(0))

    def at_variable(self, module: Optional[str], var_path: str) -> Optional[ContainerRef]:
        """The container AT ``var_path`` (``g_registry`` / ``g_state.items``), or None."""
        mi = self._module_index(module)
        m = re.match(r"^([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*)*)$", var_path or "")
        if mi is None or not m:
            return None
        name, idx, bias, is_dyn = self.modules[mi]
        var = self._var(mi, m.group(1))
        if var is None:
            return None
        ty = _Types(idx, int(getattr(idx, "pointer_size", 0) or 8))
        toff, off = var.type_offset, 0
        for mem in [x for x in m.group(2).split(".") if x]:
            hit = ty.member(ty.canon(toff), mem)
            if hit is None:
                return None
            off += hit[0]
            toff = hit[1]
        lay = classify(idx, toff)
        if lay is None:
            return None
        base = (bias + var.link_time_address) if is_dyn else var.link_time_address
        return ContainerRef(path=var_path, layout=lay, address=base + off, module=name)


# ------------------------------------------------------------------------------------------------- target memory
class ContainerMemory:
    """What a decode may read: ``read_ranges`` (list of (addr, n) -> list of bytes|None), the mappings
    (``/proc/<pid>/maps`` rows as the adapters return them) and, when a heap walk is at hand, its chunk table."""

    def __init__(self, read_ranges: Callable[[List[Tuple[int, int]]], List[Optional[bytes]]],
                 mappings: Sequence[Dict[str, Any]], chunks: Any = None, max_bytes: int = 64 * 1024,
                 refresh_maps: Optional[Callable[[], Sequence[Dict[str, Any]]]] = None):
        self._read_ranges = read_ranges
        self._refresh = refresh_maps
        self._set_maps(mappings)
        self.chunks = chunks
        self.bytes_left = int(max_bytes)
        self.bytes_read = 0
        self.last_header: Optional[bytes] = None
        self.next_header: Optional[bytes] = None
        self.cur_address = 0
        self.moved = False

    def _set_maps(self, mappings: Sequence[Dict[str, Any]]) -> None:
        self.maps: List[Tuple[int, int, str, str]] = []
        for m in mappings or []:
            try:
                s = m.get("start_int")
                e = m.get("end_int")
                s = int(str(m.get("start")), 16) if s is None else int(s)
                e = int(str(m.get("end")), 16) if e is None else int(e)
            except (TypeError, ValueError):
                continue
            self.maps.append((s, e, str(m.get("permissions") or m.get("perms") or ""),
                              str(m.get("pathname") or m.get("path") or "")))
        self.maps.sort()

    @classmethod
    def from_analysis(cls, analysis: Any, max_bytes: int = 64 * 1024) -> "ContainerMemory":
        rd = analysis.reader
        # the mappings of the walk are as old as the walk: a heap that grew since (an arena heap extended by
        # mprotect, a new mmapped block) is re-read once, through the same adapter, before a decode is rejected
        return cls(rd.read_ranges, analysis.walk.mappings, analysis.walk.chunks, max_bytes=max_bytes,
                   refresh_maps=lambda: rd.adapter.get_proc_maps(rd.pid) or [])

    @classmethod
    def from_adapter(cls, adapter: Any, pid: int, mappings: Optional[Sequence[Dict[str, Any]]] = None,
                     max_bytes: int = 64 * 1024) -> "ContainerMemory":
        def rr(ranges: List[Tuple[int, int]]) -> List[Optional[bytes]]:
            res = adapter.read_memory_batch(int(pid), [(int(a), int(n)) for a, n in ranges])
            return [(r[0] if r and r[0] and len(r[0]) == n else None) for r, (_a, n) in zip(res, ranges)]
        if mappings is None:
            mappings = adapter.get_proc_maps(int(pid)) or []
        return cls(rr, mappings, None, max_bytes=max_bytes)

    def read(self, addr: int, n: int) -> Optional[bytes]:
        return self.read_many([(addr, n)])[0]

    def read_many(self, ranges: List[Tuple[int, int]]) -> List[Optional[bytes]]:
        total = sum(int(n) for _a, n in ranges)
        if total > self.bytes_left:
            raise _Reject("read budget of the container decode exhausted")
        self.bytes_left -= total
        try:
            out = self._read_ranges([(int(a), int(n)) for a, n in ranges])
        except Exception as exc:  # noqa: BLE001 - budget exhaustion of the walk reader, adapter errors
            raise _Reject("read failed: %s" % exc)
        res = []
        for d, (_a, n) in zip(out, ranges):
            if d is not None and len(d) >= n:
                self.bytes_read += n
                res.append(bytes(d[:n]))
            else:
                res.append(None)
        return res

    def mapping(self, addr: int) -> Optional[Tuple[int, int, str, str]]:
        import bisect
        i = bisect.bisect_right(self.maps, (addr, 1 << 65, "", "")) - 1
        if i >= 0 and self.maps[i][0] <= addr < self.maps[i][1]:
            return self.maps[i]
        return None

    def writable_range(self, addr: int, nbytes: int) -> bool:
        """``[addr, addr + nbytes)`` lies in one readable, writable mapping (the mappings are re-read once when they
        predate the container)."""
        m = self.mapping(addr)
        ok = m is not None and "r" in m[2] and "w" in m[2] and addr + max(0, nbytes) <= m[1]
        if not ok and self._refresh is not None:
            refresh, self._refresh = self._refresh, None
            try:
                self._set_maps(refresh())
            except Exception:  # noqa: BLE001
                return False
            return self.writable_range(addr, nbytes)
        return ok

    def writable_total(self) -> int:
        return sum(e - s for s, e, p, _ in self.maps if "w" in p)

    def block(self, addr: int) -> Optional[Tuple[int, int, bool]]:
        """(user address, usable size, in use) of the heap-walk chunk holding ``addr``; None without a walk or when
        the address is in no chunk the walk saw."""
        ct = self.chunks
        if ct is None:
            return None
        try:
            ci = ct.find_containing(addr)
            if ci is None:
                return None
            from .heap_walker import IN_USE_STATES
            return ct.addrs[ci] + 16, ct.usable_size(ci), ct.states[ci] in IN_USE_STATES
        except Exception:  # noqa: BLE001
            return None


class _Reject(Exception):
    pass




def _u(buf: bytes, off: int, size: int = 8) -> int:
    return struct.unpack_from("<Q" if size == 8 else "<I", buf, off)[0]


def _i32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<i", buf, off)[0]


def decode(layout: ContainerLayout, address: int, mem: ContainerMemory) -> Dict[str, Any]:
    """Validated decode of the container at ``address``.  Always returns a dict with ``decoded`` (bool), ``kind`` and
    ``type``; with ``decoded`` false, ``reason`` says which check failed and no value is given."""
    base = {"kind": layout.kind, "type": layout.type_name, "address": "0x%x" % address}
    if layout.unsupported:
        return dict(base, decoded=False, reason=layout.unsupported)
    fn = _DECODERS.get(layout.kind)
    if fn is None:
        return dict(base, decoded=False, reason="no decoder for %s" % layout.kind)
    out = None
    mem.next_header = None
    for attempt in range(MAX_ATTEMPTS):
        mem.cur_address = address
        mem.moved = False
        try:
            out = fn(layout, address, mem)
            break
        except _Reject as exc:
            # The target keeps running: when the header changed between its read and the reads of the nodes it points
            # to, a failed check may be that change; start again from the header read together with those nodes.
            if mem.moved and attempt + 1 < MAX_ATTEMPTS:
                time.sleep(0.001 * (attempt + 1))
                continue
            return dict(base, decoded=False, reason=str(exc) + (" (the container changed while it was read)"
                                                                if mem.moved else ""))
        except (struct.error, IndexError, TypeError, ValueError) as exc:
            return dict(base, decoded=False, reason="malformed header: %s" % exc)
    if out is None:
        return dict(base, decoded=False, reason="the container kept changing while it was read (%d attempts)"
                    % MAX_ATTEMPTS)
    d = dict(base)
    d.update(out)
    d["decoded"] = True
    return d


def _header(layout: ContainerLayout, address: int, mem: ContainerMemory) -> bytes:
    n = max(layout.byte_size, max(layout.off.values()) + 8 if layout.off else 8)
    if not mem.writable_range(address, n):
        raise _Reject("the container object at 0x%x is not in a writable mapping" % address)
    b, mem.next_header = mem.next_header, None
    if b is None or len(b) != n:
        b = mem.read(address, n)
    if b is None:
        raise _Reject("could not read the container header at 0x%x" % address)
    mem.last_header = b
    return b


def _linked(mem: ContainerMemory, ranges: List[Tuple[int, int]]) -> List[Optional[bytes]]:
    """Read memory the header points to together with the header again (one batch).  When the header changed, the
    nodes may belong to a later state of the container: ``mem.moved`` is set and a failed check is retried from the
    new header (``decode``)."""
    h = mem.last_header
    out = mem.read_many(list(ranges) + [(mem.cur_address, len(h))])
    if out[-1] is not None and out[-1] != h:
        mem.next_header = out[-1]
        mem.moved = True
    return out[:-1]


def _storage_check(mem: ContainerMemory, ptr: int, nbytes: int, what: str, checks: List[str]) -> Optional[Dict[str, Any]]:
    """The block holding ``nbytes`` at ``ptr``: one writable mapping, and when the heap walk saw an in-use chunk
    there, the chunk starts at ``ptr`` and is large enough."""
    if not mem.writable_range(ptr, nbytes):
        raise _Reject("%s 0x%x..+%d is not inside one writable mapping" % (what, ptr, nbytes))
    checks.append("%s inside one writable mapping" % what)
    blk = mem.block(ptr)
    if blk is None:
        return None
    user, usable, in_use = blk
    if not in_use:
        # allocated after the walk read that part of the heap (or freed since): not checkable against this walk
        return None
    if user != ptr:
        raise _Reject("%s 0x%x does not start a heap block (block starts at 0x%x)" % (what, ptr, user))
    if nbytes > usable:
        raise _Reject("%s needs %d bytes but its heap block holds %d" % (what, nbytes, usable))
    checks.append("%s fits its heap block" % what)
    return {"block": "0x%x" % user, "block_usable": usable}


def _vector(lay: ContainerLayout, a: int, mem: ContainerMemory) -> Dict[str, Any]:
    h = _header(lay, a, mem)
    b, e, c = _u(h, lay.off["_M_start"]), _u(h, lay.off["_M_finish"]), _u(h, lay.off["_M_end_of_storage"])
    checks: List[str] = []
    if b == 0 and e == 0 and c == 0:
        return {"size": 0, "capacity": 0, "element_type": lay.elem_type, "element_size": lay.elem_size,
                "checks": ["empty (no storage)"]}
    if not (0 < b <= e <= c):
        raise _Reject("begin <= end <= capacity violated (begin 0x%x, end 0x%x, capacity end 0x%x)" % (b, e, c))
    checks.append("begin <= end <= capacity")
    es = lay.elem_size
    if (e - b) % es or (c - b) % es:
        raise _Reject("storage length not a multiple of the element size %d" % es)
    checks.append("lengths are multiples of sizeof(%s) = %d" % (lay.elem_type, es))
    out = {"size": (e - b) // es, "capacity": (c - b) // es, "element_type": lay.elem_type, "element_size": es,
           "storage": "0x%x" % b, "storage_bytes": c - b}
    if c > b:
        blk = _storage_check(mem, b, c - b, "storage", checks)
        if blk:
            out.update(blk)
    out["checks"] = checks
    return out


def _string(lay: ContainerLayout, a: int, mem: ContainerMemory) -> Dict[str, Any]:
    h = _header(lay, a, mem)
    p, n = _u(h, lay.off["_M_p"]), _u(h, lay.off["_M_string_length"])
    local = a + lay.off["_M_local_buf"]
    sso_cap = 15
    checks: List[str] = []
    if p == local:
        if n > sso_cap:
            raise _Reject("short-string length %d exceeds the inline capacity %d" % (n, sso_cap))
        checks.append("inline (short string) length <= %d" % sso_cap)
        txt = h[lay.off["_M_local_buf"]:lay.off["_M_local_buf"] + n]
        return {"size": n, "capacity": sso_cap, "inline": True, "checks": checks,
                "preview": txt.decode("utf-8", "replace")}
    cap = _u(h, lay.off["_M_allocated_capacity"])
    if not (n <= cap and cap > sso_cap):
        raise _Reject("length %d > capacity %d, or a heap string with capacity <= %d" % (n, cap, sso_cap))
    checks.append("length <= capacity")
    out = {"size": n, "capacity": cap, "inline": False, "storage": "0x%x" % p}
    blk = _storage_check(mem, p, cap + 1, "character storage", checks)
    if blk:
        out.update(blk)
    pv = mem.read(p, min(n, 48)) if n else b""
    if pv is not None:
        out["preview"] = pv.decode("utf-8", "replace")
    out["checks"] = checks
    return out


def _tree(lay: ContainerLayout, a: int, mem: ContainerMemory) -> Dict[str, Any]:
    h = _header(lay, a, mem)
    ho = lay.off["_M_header"]
    H = a + ho
    par = _u(h, ho + lay.off["node_M_parent"])
    left = _u(h, ho + lay.off["node_M_left"])
    right = _u(h, ho + lay.off["node_M_right"])
    n = _u(h, lay.off["_M_node_count"])
    checks: List[str] = []
    if n == 0:
        if not (par == 0 and left == H and right == H):
            raise _Reject("empty tree whose header does not point to itself")
        return {"size": 0, "element_type": lay.elem_type, "checks": ["empty: header links point to itself"]}
    if par == 0 or n > min(MAX_ELEMENTS, mem.writable_total() // max(32, lay.off.get("node_size") or 32)):
        raise _Reject("node count %d with root 0x%x is implausible" % (n, par))
    ns = max(32, int(lay.off.get("node_size") or 32))
    for p, what in ((par, "root node"), (left, "leftmost node"), (right, "rightmost node")):
        if not mem.writable_range(p, ns):
            raise _Reject("%s 0x%x is not in a writable mapping" % (what, p))
    root, lm, rm = _linked(mem, [(par, ns), (left, ns), (right, ns)])
    if root is None or lm is None or rm is None:
        raise _Reject("could not read the root / leftmost / rightmost node")
    if _u(root, lay.off["node_M_parent"]) != H:
        raise _Reject("the root node's parent is not the tree header")
    outer = [(n_, c_) for n_, c_ in ((left, _u(lm, lay.off["node_M_left"])), (right, _u(rm, lay.off["node_M_right"])))
             if c_ != 0]
    if outer:
        # an element being added at that end while the tree was read: the new child must link back to the node
        if not all(mem.writable_range(c_, ns) for _n, c_ in outer):
            raise _Reject("leftmost / rightmost node has an outer child outside writable memory")
        kids = _linked(mem, [(c_, ns) for _n, c_ in outer])
        if any(k is None or _u(k, lay.off["node_M_parent"]) != n_ for k, (n_, _c) in zip(kids, outer)):
            mem.moved = True
            raise _Reject("leftmost / rightmost node has an outer child that does not link back to it")
        checks.append("a node added at an end while the tree was read links back to its parent")
    else:
        checks.append("leftmost / rightmost nodes are leaves on their outer side")
    checks += ["root node links back to the header", "node count bounded by writable memory"]
    return {"size": n, "element_type": lay.elem_type, "checks": checks}


def _hash(lay: ContainerLayout, a: int, mem: ContainerMemory) -> Dict[str, Any]:
    h = _header(lay, a, mem)
    bk, nb = _u(h, lay.off["_M_buckets"]), _u(h, lay.off["_M_bucket_count"])
    nxt = _u(h, lay.off["_M_before_begin"] + lay.off["node_nxt"])
    n = _u(h, lay.off["_M_element_count"])
    single = a + lay.off["_M_single_bucket"]
    checks: List[str] = []
    if nb < 1 or nb > MAX_ELEMENTS:
        raise _Reject("bucket count %d is implausible" % nb)
    if (n == 0) != (nxt == 0):
        raise _Reject("element count %d disagrees with the first-node link 0x%x" % (n, nxt))
    checks.append("element count agrees with the first-node link")
    if "_M_max_load_factor" in lay.off:
        mlf = struct.unpack_from("<f", h, lay.off["_M_max_load_factor"])[0]
        if not (0.0 < mlf < 1e6):
            raise _Reject("max load factor %r is implausible" % mlf)
        if n > nb * mlf * 2 + 2:
            raise _Reject("%d elements in %d buckets exceeds the load factor %.2f" % (n, nb, mlf))
        checks.append("elements within the load factor of the buckets")
    out: Dict[str, Any] = {"size": n, "buckets": nb, "element_type": lay.elem_type}
    if nb == 1:
        if bk != single:
            raise _Reject("one bucket that is not the inline single bucket")
        checks.append("single inline bucket")
    else:
        blk = _storage_check(mem, bk, nb * 8, "bucket array", checks)
        if blk:
            out.update(blk)
    if n:
        if not mem.writable_range(nxt, 8):
            raise _Reject("first node 0x%x is not in a writable mapping" % nxt)
        first = _linked(mem, [(nxt, 8)])[0]
        if first is None:
            raise _Reject("could not read the first node")
        f = _u(first, 0)
        if f != 0 and not mem.writable_range(f, 8):
            raise _Reject("the first node's next link 0x%x points outside writable memory" % f)
        if n == 1 and f != 0:
            raise _Reject("one element, but the first node links to another")
        checks.append("first node readable, its link plausible")
    out["checks"] = checks
    return out


def _deque(lay: ContainerLayout, a: int, mem: ContainerMemory) -> Dict[str, Any]:
    h = _header(lay, a, mem)
    o = lay.off
    mp, msz = _u(h, o["_M_map"]), _u(h, o["_M_map_size"])
    it = {}
    for side in ("_M_start", "_M_finish"):
        it[side] = {k: _u(h, o[side] + o["it" + k]) for k in ("_M_cur", "_M_first", "_M_last", "_M_node")}
    es = lay.elem_size
    buf_elems = DEQUE_BUF_BYTES // es if es < DEQUE_BUF_BYTES else 1
    checks: List[str] = []
    if mp == 0 and msz == 0 and all(v == 0 for s in it.values() for v in s.values()):
        return {"size": 0, "element_type": lay.elem_type, "checks": ["moved-from / unallocated deque"]}
    if mp == 0 or not (1 <= msz <= MAX_ELEMENTS):
        raise _Reject("map 0x%x of %d entries is implausible" % (mp, msz))
    s, f = it["_M_start"], it["_M_finish"]
    for name, x in (("start", s), ("finish", f)):
        if not (x["_M_first"] <= x["_M_cur"] <= x["_M_last"]):
            raise _Reject("%s iterator outside its buffer" % name)
        if x["_M_last"] - x["_M_first"] != buf_elems * es:
            raise _Reject("%s buffer is %d bytes, libstdc++ uses %d" % (name, x["_M_last"] - x["_M_first"], buf_elems * es))
        if not (mp <= x["_M_node"] < mp + msz * 8) or (x["_M_node"] - mp) % 8:
            raise _Reject("%s iterator's map slot is outside the map" % name)
    if s["_M_node"] > f["_M_node"] or (s["_M_node"] == f["_M_node"] and s["_M_cur"] > f["_M_cur"]):
        raise _Reject("start after finish")
    checks += ["iterators inside their %d-element buffers" % buf_elems, "iterator map slots inside the map",
               "start before finish"]
    blk = _storage_check(mem, mp, msz * 8, "map", checks)
    nodes = (f["_M_node"] - s["_M_node"]) // 8
    words = _linked(mem, [(s["_M_node"], (nodes + 1) * 8)])[0] if nodes < 4096 else None
    if words is not None:
        if _u(words, 0) != s["_M_first"] or _u(words, nodes * 8) != f["_M_first"]:
            raise _Reject("the map slots do not hold the iterators' buffers")
        checks.append("map slots hold the iterators' buffers")
    size = buf_elems * (nodes - 1) + (f["_M_cur"] - f["_M_first"]) // es + (s["_M_last"] - s["_M_cur"]) // es
    out = {"size": size, "buffers": nodes + 1, "element_type": lay.elem_type, "element_size": es, "checks": checks}
    if blk:
        out.update(blk)
    return out


def _list(lay: ContainerLayout, a: int, mem: ContainerMemory) -> Dict[str, Any]:
    h = _header(lay, a, mem)
    H = a + lay.off["_M_node"]
    ho = lay.off["_M_node"]
    nx, pv = _u(h, ho + lay.off["node_M_next"]), _u(h, ho + lay.off["node_M_prev"])
    n = _u(h, ho + lay.off["node_M_size"])
    if n == 0:
        if not (nx == H and pv == H):
            raise _Reject("empty list whose sentinel does not point to itself")
        return {"size": 0, "element_type": lay.elem_type, "checks": ["empty: sentinel points to itself"]}
    if n > min(MAX_ELEMENTS, mem.writable_total() // 24):
        raise _Reject("list size %d is implausible" % n)
    for p in (nx, pv):
        if not mem.writable_range(p, 16):
            raise _Reject("list node 0x%x is not in a writable mapping" % p)
    first, last = _linked(mem, [(nx, 16), (pv, 16)])
    if first is None or last is None:
        raise _Reject("could not read the first / last node")
    if _u(first, lay.off["node_M_prev"]) != H or _u(last, lay.off["node_M_next"]) != H:
        raise _Reject("first / last node does not link back to the sentinel")
    return {"size": n, "element_type": lay.elem_type,
            "checks": ["first and last nodes link back to the sentinel", "size bounded by writable memory"]}


def _pointee(mem: ContainerMemory, p: int, typ: Optional[str]) -> Dict[str, Any]:
    d: Dict[str, Any] = {"address": "0x%x" % p, "type": typ}
    m = mem.mapping(p)
    if m is None:
        raise _Reject("pointee 0x%x is not mapped" % p)
    blk = mem.block(p)
    if blk is not None and blk[2]:
        d["block"] = "0x%x" % blk[0]
        d["block_usable"] = blk[1]
        d["offset_in_block"] = p - blk[0]
    return d


def _smart(lay: ContainerLayout, a: int, mem: ContainerMemory) -> Dict[str, Any]:
    h = _header(lay, a, mem)
    checks: List[str] = []
    if lay.kind == K_UNIQUE:
        p = _u(h, lay.off["_M_head_impl"])
        if p == 0:
            return {"null": True, "pointee_type": lay.pointee_type, "checks": ["null"]}
        out = {"null": False, "pointee": _pointee(mem, p, lay.pointee_type), "pointee_type": lay.pointee_type}
        out["checks"] = ["pointee mapped"]
        return out
    p, pi = _u(h, lay.off["_M_ptr"]), _u(h, lay.off["_M_pi"])
    if pi == 0:
        if p != 0 and lay.kind == K_WEAK:
            raise _Reject("weak_ptr with a pointer but no control block")
        return {"null": p == 0, "use_count": 0, "weak_count": 0, "pointee_type": lay.pointee_type,
                "checks": ["no control block"]}
    if not mem.writable_range(pi, max(lay.cb_use, lay.cb_weak) + 4):
        raise _Reject("control block 0x%x is not in a writable mapping" % pi)
    cb = _linked(mem, [(pi, max(lay.cb_use, lay.cb_weak) + 4)])[0]
    if cb is None:
        raise _Reject("could not read the control block")
    use, weak = _i32(cb, lay.cb_use), _i32(cb, lay.cb_weak)
    if not (0 <= use <= MAX_REFCOUNT and 0 <= weak <= MAX_REFCOUNT):
        raise _Reject("control block counts use=%d weak=%d are implausible" % (use, weak))
    if lay.kind == K_SHARED and (use < 1 or weak < 1):
        raise _Reject("a live shared_ptr needs use >= 1 and weak >= 1 (use=%d weak=%d)" % (use, weak))
    if lay.kind == K_WEAK and weak < 1:
        raise _Reject("a live weak_ptr needs weak >= 1 (weak=%d)" % weak)
    if use > 0 and weak < 1:
        raise _Reject("use > 0 needs weak >= 1")
    vp = _u(cb, 0)
    vm = mem.mapping(vp)
    if vm is None or not vm[3] or vm[3].startswith("["):
        raise _Reject("control block's virtual table pointer 0x%x is not in a loaded module" % vp)
    checks += ["control block counts plausible", "control block has a module virtual table"]
    out: Dict[str, Any] = {"null": p == 0, "use_count": use,
                           # libstdc++ keeps one extra weak reference while use_count > 0
                           "weak_count": weak - (1 if use > 0 else 0), "control_block": "0x%x" % pi,
                           "pointee_type": lay.pointee_type, "expired": use == 0}
    if p and use > 0:
        out["pointee"] = _pointee(mem, p, lay.pointee_type)
        checks.append("pointee mapped")
    out["checks"] = checks
    return out


_DECODERS: Dict[str, Callable[[ContainerLayout, int, ContainerMemory], Dict[str, Any]]] = {
    K_VECTOR: _vector, K_STRING: _string, K_DEQUE: _deque, K_LIST: _list,
    K_SHARED: _smart, K_WEAK: _smart, K_UNIQUE: _smart,
}
for _k in TREE_KINDS:
    _DECODERS[_k] = _tree
for _k in HASH_KINDS:
    _DECODERS[_k] = _hash


# ------------------------------------------------------------------------------------------------- summaries
def summary(dec: Dict[str, Any]) -> Dict[str, Any]:
    """The reader-facing part of a decode (what the finding / report shows); no raw pointers except the pointee."""
    keys = ("kind", "type", "decoded", "reason", "size", "capacity", "buckets", "element_type", "inline",
            "use_count", "weak_count", "expired", "null", "pointee_type", "storage_bytes")
    out = {k: dec[k] for k in keys if k in dec}
    if isinstance(dec.get("pointee"), dict):
        out["pointee"] = {k: v for k, v in dec["pointee"].items() if k in ("address", "type", "block_usable")}
    if dec.get("checks"):
        out["checks"] = list(dec["checks"])
    return out


def text(dec: Dict[str, Any]) -> str:
    """One English line: ``std::vector<Record*>: 4,732 elements (capacity 8,192)``."""
    t = dec.get("type") or dec.get("kind")
    if not dec.get("decoded"):
        return "%s: not decoded (%s)" % (t, dec.get("reason"))
    k = dec.get("kind")
    if k in SMART_KINDS:
        if dec.get("null"):
            return "%s: null" % t
        s = "%s: points to %s" % (t, (dec.get("pointee") or {}).get("address", "?"))
        if k != K_UNIQUE:
            s += ", use_count %s, weak references %s" % (dec.get("use_count"), dec.get("weak_count"))
        return s
    unit = "characters" if k == K_STRING else "elements"
    s = "%s: %s %s" % (t, format(int(dec.get("size") or 0), ","), unit)
    if dec.get("capacity") is not None:
        s += " (capacity %s)" % format(int(dec["capacity"]), ",")
    return s
