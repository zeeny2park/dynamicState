"""statusLine: 화면 하단에 AI-DLC 진행 위치 1줄 표시.

예: AI-DLC ▸ 🟢 CONSTRUCTION · Code Generation (routine-rule) · 9/17 · 다음: Functional Design
"""

import sys
from pathlib import Path

sys.dont_write_bytecode = True  # 실습 리포지토리에 __pycache__ 만들지 않기
sys.path.insert(0, str(Path(__file__).resolve().parent))
from aidlc_common import (  # noqa: E402
    PHASE_ICON,
    clip,
    project_dir,
    read_input,
    read_state,
    strip_phase,
    write_out,
)

MAX = 120


def line(state) -> str:
    if not state:
        return "AI-DLC ▸ 시작 전"
    head = "AI-DLC ▸"
    if state["phase"] == "DONE":
        head += " ✅ 완료"
    elif state["phase"]:
        head += f" {PHASE_ICON[state['phase']]} {state['phase']}"
    current = clip(strip_phase(state["current"]) or "확인 필요", 40)
    text = f"{head} · {current} · {state['done']}/{state['total']}"
    nxt = strip_phase(state["next"])
    room = MAX - len(text) - len(" · 다음: ")
    if nxt and state["phase"] != "DONE" and room >= 8:
        text += f" · 다음: {clip(nxt, room)}"
    return text


if __name__ == "__main__":
    try:
        write_out(line(read_state(project_dir(read_input()))) + "\n")
    except Exception:
        write_out("AI-DLC ▸ 상태 읽기 오류\n")
