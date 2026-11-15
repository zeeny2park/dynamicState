"""UserPromptSubmit hook: 사용자 입력 원문을 aidlc-docs/audit.md 에 자동 기록.

1.0 MANDATORY 규칙 (입력 원문 기록) 의 기계 보장
기록 조건: aidlc-docs/ 가 있거나, 입력에 AI-DLC · aidlc 가 들어 있을 때
실패해도 입력을 막지 않음 (항상 exit 0)
"""

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True  # 실습 리포지토리에 __pycache__ 만들지 않기
sys.path.insert(0, str(Path(__file__).resolve().parent))
from aidlc_common import project_dir, read_input, read_state, write_out  # noqa: E402

TRIGGER = re.compile(r"ai-?dlc", re.I)
HEADER = "# AI-DLC Audit Log\n\n"


def main() -> None:
    data = read_input()
    prompt = data.get("prompt") or ""
    # Claude Code 가 스스로 만든 turn (백그라운드 작업 알림 등) 은 사람 입력이 아님
    if not prompt.strip() or prompt.lstrip().startswith("<"):
        return
    project = project_dir(data)
    docs = project / "aidlc-docs"
    if not docs.is_dir() and not TRIGGER.search(prompt):
        return

    # 1.0 규칙 형식 YYYY-MM-DDTHH:MM:SSZ (UTC)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    state = read_state(project)
    context = state["current"] if state and state["current"] else "workflow 시작 전"
    entry = (
        "## 사용자 입력 (hook 자동 기록)\n"
        f"**Timestamp**: {ts}\n"
        f'**User Input**: "{prompt}"\n'
        f"**Context**: {context} · UserPromptSubmit hook\n\n---\n\n"
    )
    docs.mkdir(exist_ok=True)
    audit = docs / "audit.md"
    with open(audit, "a", encoding="utf-8", newline="\n") as f:
        if audit.stat().st_size == 0:
            f.write(HEADER)
        f.write(entry)

    # plain stdout = Claude 에게 전달되는 맥락
    write_out(
        "[ai-dlc-dx hook] 이 사용자 입력 원문은 aidlc-docs/audit.md 에 자동 기록됨 "
        f"(Timestamp: {ts}). audit 항목을 쓸 때 User Input 원문을 다시 적지 말고 "
        f"`**User Input**: (hook 기록 {ts})` 로 대신하고, AI Response · Context 만 기록할 것. "
        f"현재 시각 = {ts}: 이번 턴 audit 항목의 Timestamp 는 추측하지 말고 이 값을 사용.\n"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # hook 오류로 사용자 입력이 막히지 않게
        sys.stderr.write(f"aidlc_audit hook 오류: {e}\n")
    sys.exit(0)
