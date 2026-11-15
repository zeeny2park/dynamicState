"""ai-dlc-dx hook 공통: UTF-8 입출력, 프로젝트 위치, aidlc-state.md 해석 (표준 라이브러리만)."""

import json
import os
import re
import sys
from pathlib import Path

PHASES = ("INCEPTION", "CONSTRUCTION", "OPERATIONS")
PHASE_ICON = {"INCEPTION": "🔵", "CONSTRUCTION": "🟢", "OPERATIONS": "🟡"}
CHECK = re.compile(r"^\s*-\s*\[([ xX])\]\s*(.+?)\s*$")
EMPTY_ANSWER = re.compile(r"^\s*\[Answer\]:\s*$", re.M)


def read_input() -> dict:
    """stdin JSON (Windows 기본 cp949 회피: 바이트로 읽고 UTF-8 해석)"""
    raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    try:
        return json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def write_out(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.buffer.flush()


def project_dir(data: dict) -> Path:
    ws = data.get("workspace") or {}
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    return Path(env or ws.get("project_dir") or data.get("cwd") or ".")


def _section(text: str, title: str) -> str:
    """'## title' 부터 다음 '## ' 머리말 전까지 ('###' 하위 머리말 포함)"""
    pattern = rf"^##\s+{re.escape(title)}\s*$(.*?)(?=^##\s|\Z)"
    m = re.search(pattern, text, re.M | re.S)
    return m.group(1) if m else ""


def _field(text: str, name: str) -> str:
    m = re.search(rf"\*\*{re.escape(name)}\*\*:\s*(.+)", text)
    return m.group(1).strip() if m else ""


def _phase_of(text: str) -> str:
    return next((p for p in PHASES if p in text.upper()), "")


def _progress(section: str) -> list:
    """Stage Progress 항목 [(완료 여부, 이름, phase)]. phase = 항목 앞머리 또는 '###' 머리말"""
    items, heading = [], ""
    for ln in section.splitlines():
        if ln.startswith("###"):
            heading = _phase_of(ln) or heading
        m = CHECK.match(ln)
        if m:
            name = m.group(2)
            items.append((m.group(1).lower() == "x", name, _phase_of(name[:14]) or heading))
    return items


def read_state(project: Path):
    """aidlc-state.md 요약 dict, 파일 없으면 None.

    1.0 양식 2종 처리: phase 머리말형 · 'PHASE - Stage' 형
    """
    path = project / "aidlc-docs" / "aidlc-state.md"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    status = _section(text, "Current Status")
    current = _field(status, "Current Stage") or _field(text, "Current Stage")
    items = _progress(_section(text, "Stage Progress"))
    skipped = [i for i in items if not i[0] and "SKIP" in i[1].upper()]
    pending = [i for i in items if not i[0] and "SKIP" not in i[1].upper()]
    nxt = _field(status, "Next Stage") or _field(text, "Next Stage")
    # phase: 모두 완료 → DONE, Current Stage 맨 앞 'PHASE - ' → 그 값, 없으면 첫 미완료 항목
    # (Current Stage 문장 중간의 단어는 무시)
    lead = re.match(r"\s*(INCEPTION|CONSTRUCTION|OPERATIONS)\b", current, re.I)
    if items and not pending:
        phase = "DONE"
    elif lead:
        phase = lead.group(1).upper()
    else:
        phase = pending[0][2] if pending else ""
    return {
        "current": current,
        "next": nxt or (pending[0][1] if pending else ""),
        "status": _field(status, "Status"),
        "phase": phase,
        "done": sum(1 for i in items if i[0]),
        "total": len(items) - len(skipped),
    }


def open_questions(project: Path, limit: int = 5) -> list:
    """빈 [Answer]: 가 남은 aidlc-docs 파일 (답변 대기 중인 질문 · 계획)"""
    docs = project / "aidlc-docs"
    found = []
    for p in sorted(docs.rglob("*.md")) if docs.is_dir() else []:
        if EMPTY_ANSWER.search(p.read_text(encoding="utf-8", errors="replace")):
            found.append(p.relative_to(project).as_posix())
            if len(found) >= limit:
                break
    return found


def last_audit_heading(project: Path) -> str:
    audit = project / "aidlc-docs" / "audit.md"
    if not audit.is_file():
        return ""
    """audit.md 의 마지막 AI 작업 항목 머리말 (hook 의 입력 자동 기록 항목은 제외)"""
    text = audit.read_text(encoding="utf-8", errors="replace")
    heads = [h.strip() for h in re.findall(r"^## (.+)$", text, re.M) if "hook 자동 기록" not in h]
    return heads[-1] if heads else ""


def strip_phase(stage: str) -> str:
    """'CONSTRUCTION - Code Generation (x)' → 'Code Generation (x)'"""
    return re.sub(r"^(INCEPTION|CONSTRUCTION|OPERATIONS)\s*[-·:]\s*", "", stage.strip(), flags=re.I)


def clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"
