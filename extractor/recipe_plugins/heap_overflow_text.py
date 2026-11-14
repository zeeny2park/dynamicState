"""Plain-language summary of a heap buffer overflow (presentation only; no recipe, no collector, no verdict rule).

The overflow itself is found by the heap integrity check (``extractor.heap_integrity``): it reports a damaged chunk
header (or top chunk) behind a buffer and, from the reverse reference map, the buffer that ends right before it and
how many bytes the damage reaches past that buffer's usable end.  Its finding category is the broad
``MEMORY_CORRUPTION``, so this file registers the summary sentences for that category through the presentation
registry and renders them only when the report carries such an overflow record; any other memory-corruption finding
keeps the generic summary (the registered text then returns no line).

Every number and name comes from the defect record.  What the tool saw (the damaged bytes, their extent, the buffer
and the block behind it) and what it infers (that one write that ran past the buffer's end made it; which code did
it is never observed) are kept in separate sentences.  A value that is absent is left out of its sentence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..diagnostic_recipes import CATEGORY_MEMORY_CORRUPTION

_KIND_HEADER = "chunk_header_damaged"
_KIND_TOP = "top_chunk_damaged"

# key -> (English, Korean)
_TXT: Dict[str, Any] = {
    "buf": ("{name} is a heap buffer with {n} usable bytes.", "{name}은(는) 사용 가능 크기가 {n}바이트인 힙 버퍼입니다."),
    "buf_nosize": ("{name} is a heap buffer.", "{name}은(는) 힙 버퍼입니다."),
    "anon": ("A heap buffer{size} has damaged memory right behind its end{past}.",
             "{size}힙 버퍼의 끝 바로 뒤 메모리가 손상되어 있습니다{past}."),
    "anon_size": (" with {n} usable bytes", "사용 가능 크기가 {n}바이트인 "),
    "anon_past": (": the damage reaches {k} bytes past its last usable byte",
                  ": 손상은 마지막 사용 가능 바이트에서 {k}바이트 뒤까지 이어집니다"),
    "past": (" The memory right behind its end is damaged: the damage reaches {k} bytes past its last usable byte.",
             " 끝 바로 뒤의 메모리가 손상되어 있습니다. 손상은 마지막 사용 가능 바이트에서 {k}바이트 뒤까지 이어집니다."),
    "past_nonum": (" The memory right behind its end is damaged (how far it reaches was not measured).",
                   " 끝 바로 뒤의 메모리가 손상되어 있습니다 (어디까지 이어지는지는 측정하지 못했습니다)."),
    "hdr": ("The header of the next heap block{who} is overwritten{val}.",
            "다음 힙 블록{who}의 헤더가 덮어쓰였습니다{val}."),
    "hdr_who": (", which belongs to {v},", "({v}의 것)"),
    "hdr_val": (": its size field reads {x}, which is not a valid block size",
                ": size 필드가 {x}로 읽히며 이는 올바른 블록 크기가 아닙니다"),
    "top": ("The header of the top of the heap (the unallocated space behind the last block) is overwritten{val}.",
            "힙의 맨 끝(마지막 블록 뒤의 미할당 영역) 헤더가 덮어쓰였습니다{val}."),
    "stable": ("The damage read the same in {n} re-reads, so it is not a torn read of a value that was changing.",
               "{n}번 다시 읽어도 손상된 값이 같아서, 변하는 중인 값을 잘못 읽은 것이 아닙니다."),
    "infer_pat": ("Inferred, not seen: the bytes behind the buffer repeat the value {p} that also fills the end of "
                  "the buffer, so a single write that ran past the buffer's end is the most likely cause.",
                  "추정(직접 관측한 것은 아님): 버퍼 뒤의 바이트가 버퍼 끝을 채운 값 {p}을(를) 그대로 반복하고 있어, "
                  "버퍼 끝을 넘어선 쓰기 한 번이 원인일 가능성이 가장 높습니다."),
    "infer": ("Inferred, not seen: the damage lies directly behind {name}, so a write that ran past the end of "
              "{name} is the most likely cause.",
              "추정(직접 관측한 것은 아님): 손상이 {name} 바로 뒤에 있으므로 {name}의 끝을 넘어선 쓰기가 원인일 "
              "가능성이 가장 높습니다."),
    "infer_anon": ("Inferred, not seen: the damage lies directly behind this buffer, so a write that ran past its "
                   "end is the most likely cause.",
                   "추정(직접 관측한 것은 아님): 손상이 이 버퍼 바로 뒤에 있으므로 버퍼 끝을 넘어선 쓰기가 원인일 "
                   "가능성이 가장 높습니다."),
    "writer": ("Which code wrote these bytes, and when, was not observed (the process was read without stopping "
               "it). Start from the code that writes into {name}.",
               "어느 코드가 언제 이 바이트를 썼는지는 관측되지 않았습니다(프로세스를 멈추지 않고 읽음). "
               "{name}에 쓰는 코드부터 확인하세요."),
    "writer_anon": ("Which code wrote these bytes, and when, was not observed (the process was read without "
                    "stopping it).",
                    "어느 코드가 언제 이 바이트를 썼는지는 관측되지 않았습니다(프로세스를 멈추지 않고 읽음)."),
}


def _code(x: Any) -> str:
    return "`" + str(x).replace("`", "'") + "`"


def _int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def overflow_defect(report: Optional[Dict[str, Any]], finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The first header / top-chunk defect of the report that names the buffer in front of it and its damage."""
    from ..report_visuals import _heap_defects
    for d in _heap_defects(report, finding):
        if d.get("kind") in (_KIND_HEADER, _KIND_TOP):
            return d
    return None


def overflow_sentences(i: int, d: Dict[str, Any]) -> List[str]:
    """The sentences for one overflow defect in language ``i`` (0 en, 1 ko); values absent from ``d`` are left out."""
    buf = d.get("overflowing_buffer") or {}
    dmg = d.get("damage") or {}
    victim = d.get("victim") if isinstance(d.get("victim"), dict) else {}
    details = d.get("details") if isinstance(d.get("details"), dict) else {}
    name = buf.get("variable_path") or buf.get("variable")
    usable, past = _int(buf.get("usable_size")), _int(dmg.get("bytes_past_usable_end"))
    out: List[str] = []
    # observed: the buffer and how far the damage behind it reaches
    has_past = past is not None and past > 0
    if name:
        head = (_TXT["buf"][i].format(name=_code(name), n=usable) if usable is not None
                else _TXT["buf_nosize"][i].format(name=_code(name)))
        out.append(head + (_TXT["past"][i].format(k=past) if has_past else _TXT["past_nonum"][i]))
    else:
        out.append(_TXT["anon"][i].format(
            size=_TXT["anon_size"][i].format(n=usable) if usable is not None else "",
            past=_TXT["anon_past"][i].format(k=past) if has_past else ""))
    # observed: the header of the block behind it
    size_field = details.get("observed_size_field")
    val = _TXT["hdr_val"][i].format(x=_code(size_field)) if size_field else ""
    if d.get("kind") == _KIND_TOP or str(victim.get("state")) == "top":
        out.append(_TXT["top"][i].format(val=val))
    else:
        vname = victim.get("variable_path") or victim.get("variable")
        who = _TXT["hdr_who"][i].format(v=_code(vname)) if vname else ""
        out.append(_TXT["hdr"][i].format(who=who, val=val))
    n = _int(d.get("stable_rereads"))
    if d.get("stable") and n:
        out.append(_TXT["stable"][i].format(n=n))
    # inferred: what made it
    m = re.search(r"repeated byte (0x[0-9a-fA-F]{1,2})", str(dmg.get("pattern") or ""))
    if m and dmg.get("continues_buffer_content"):
        out.append(_TXT["infer_pat"][i].format(p=_code(m.group(1))))
    elif name:
        out.append(_TXT["infer"][i].format(name=_code(name)))
    else:
        out.append(_TXT["infer_anon"][i])
    out.append(_TXT["writer"][i].format(name=_code(name)) if name else _TXT["writer_anon"][i])
    return out


def overflow_finding_text(ctx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    d = overflow_defect(report, finding)
    return {"lines": overflow_sentences(ctx.i, d) if d else []}


def _register_presentation() -> None:
    from ..report_registry import register_finding_text
    register_finding_text(CATEGORY_MEMORY_CORRUPTION, overflow_finding_text)


_register_presentation()
