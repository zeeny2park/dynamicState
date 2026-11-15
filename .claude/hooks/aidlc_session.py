"""SessionStart hook (startup · resume · clear · compact): AI-DLC 진행 상황을 대화 맥락에 주입.

주입 내용: aidlc-state.md 요약 + audit.md 마지막 항목 + 답변 대기 중인 질문 파일
상태 파일이 없으면 아무것도 출력하지 않음
"""

import sys
from pathlib import Path

sys.dont_write_bytecode = True  # 실습 리포지토리에 __pycache__ 만들지 않기
sys.path.insert(0, str(Path(__file__).resolve().parent))
from aidlc_common import (  # noqa: E402
    last_audit_heading,
    open_questions,
    project_dir,
    read_input,
    read_state,
    write_out,
)


def main() -> None:
    data = read_input()
    project = project_dir(data)
    state = read_state(project)
    if not state:
        return
    source = data.get("source") or "startup"
    progress = f"- 진행: {state['done']}/{state['total']} 완료"
    if state["status"]:
        progress += f", 상태: {state['status']}"
    lines = [
        f"[ai-dlc-dx hook] AI-DLC 진행 중 (aidlc-docs/aidlc-state.md 기준, source={source})",
        f"- 현재 stage: {state['current'] or '확인 필요'}",
        f"- 다음 stage: {state['next'] or '확인 필요'}",
        progress,
    ]
    last = last_audit_heading(project)
    if last:
        lines.append(f"- audit.md 마지막 항목: {last}")
    waiting = open_questions(project)
    if waiting:
        lines.append(f"- 답변 대기 ([Answer]: 빈칸): {', '.join(waiting)}")
    lines.append(
        "- 이어서 진행할 때: aidlc-state.md · audit.md 마지막 항목을 읽고 session-continuity "
        "규칙대로 재개. 사용자는 `/aidlc` 로 상태 확인, `/aidlc-<phase>-<stage>` 로 stage 지정"
    )
    if source == "compact":
        lines.append(
            "- 대화가 압축됨: 진행 중이던 stage 의 계획 체크박스 · 승인 대기 여부를 "
            "기억에 의존하지 말고 파일로 다시 확인"
        )
    write_out("\n".join(lines) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sys.stderr.write(f"aidlc_session hook 오류: {e}\n")
    sys.exit(0)
