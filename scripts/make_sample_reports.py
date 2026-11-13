#!/usr/bin/env python3
"""Generate the sample incident reports (Markdown + HTML, Korean and English) from live benchmark targets.

Each target of the diagnosis-accuracy benchmark is built, started through the contained fixture launcher, diagnosed
with its ground-truth symptom and rendered by the one report path (``incident_report.export_incident_report``).
An ``index.html`` lists the samples. The files are made world-readable on purpose: samples are published.

    python3 scripts/make_sample_reports.py --out /path/to/samples [--targets deadlock_pipeline overflow_ring ...]
"""
import argparse
import html
import os
import shutil
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from benchmarks.diagnosis_accuracy import run_benchmark as rb  # noqa: E402
from extractor.incident_report import export_incident_report  # noqa: E402

DEFAULT_TARGETS = [
    "deadlock_pipeline", "self_deadlock_state", "orphan_lock_cfg", "lock_convoy", "spin_flag",
    "leak_registry", "mapgrow_slabs", "frag_sparse", "accept_workers",
    "overflow_ring", "overflow_tbl", "uaf_jobq", "dfree_outbox", "dfree_reqbuf",
    "ok_busy_server", "ok_idle_server", "ok_sawtooth",
]
KIND_KO = {
    "deadlock": "교착 상태", "self_deadlock": "자기 교착", "orphan_lock": "고아 락", "lock_contention": "락 경합 (성능 저하)",
    "busy_wait": "바쁜 대기 (스핀)", "memory_leak": "메모리 누수", "mapping_growth": "malloc 밖 메모리 증가",
    "heap_retention": "힙 단편화·보유 (성능 저하)", "thread_growth": "스레드 누수", "heap_overflow": "힙 버퍼 오버플로",
    "use_after_free": "해제 후 사용", "double_free": "이중 해제", "long_stall": "긴 멈춤", "none": "정상 대조군",
}
VERDICT_KO = {"CONFIRMED_FAULT": "확인된 결함", "PROBABLE_FAULT": "결함 추정", "DEGRADED": "성능 저하",
              "HEALTHY": "정상 (점검 범위 안)", "INCONCLUSIVE": "판단 불가"}


def make_one(gt, out_dir, langs, tmp):
    binary = rb.build_target(gt, tmp)
    rows = []
    # A target that keeps growing (leak, mapping growth, thread growth) gets a fresh process per language, as the
    # benchmark's --repeat does: the second diagnosis of one ageing leak target ran out of heap-walk budget.
    fresh_per_lang = gt["kind"] in rb.GROWTH_KINDS
    proc = rb._launch(binary, gt, repeat_slots=1 if fresh_per_lang else len(langs))
    try:
        rb._wait_ready(proc, gt)
        for i, lang in enumerate(langs):
            if fresh_per_lang and i:
                rb._kill(proc)
                proc = rb._launch(binary, gt, repeat_slots=1)
                rb._wait_ready(proc, gt)
            md = os.path.join(out_dir, f"{gt['id']}.{lang}.md")
            page = os.path.join(out_dir, f"{gt['id']}.{lang}.html")
            res = export_incident_report(pid=proc.pid, companion_elf_path=binary, symptom=gt["symptom"],
                                         language=lang, output_path=md, report_html_path=page,
                                         corpus_dir=os.path.join(tmp, "corpus"))
            for p in (md, page):
                os.chmod(p, 0o644)
            rows.append({"lang": lang, "verdict": (res.get("diagnosis") or {}).get("verdict", "?"),
                         "md": os.path.basename(md), "html": os.path.basename(page)})
    finally:
        rb._kill(proc)
    return rows


def write_index(out_dir, entries, commit):
    cells = []
    for gt, rows in entries:
        ko = next((r for r in rows if r["lang"] == "ko"), rows[0])
        links = " · ".join(f'<a href="{r["html"]}">{r["lang"]} HTML</a> / <a href="{r["md"]}">{r["lang"]} MD</a>' for r in rows)
        cells.append(f"<tr><td><code>{html.escape(gt['id'])}</code></td><td>{KIND_KO.get(gt['kind'], gt['kind'])}</td>"
                     f"<td class=v>{VERDICT_KO.get(ko['verdict'], ko['verdict'])} <small>{ko['verdict']}</small></td>"
                     f"<td>{html.escape(gt['symptom'])}</td><td>{links}</td></tr>")
    doc = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>dynamicState 보고서 샘플</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 16px;line-height:1.6}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}}
code{{background:#f2f3f5;padding:0 .3em;border-radius:3px}}.v{{white-space:nowrap}}small{{color:#666}}</style></head><body>
<h1>dynamicState 보고서 샘플</h1>
<p>{time.strftime('%Y-%m-%d')} · 커밋 <code>{commit}</code> · 벤치마크 대상 프로세스를 실제로 띄워 무정지 진단하고, 공통 양식(한국어·영어, Markdown·HTML)으로 생성했습니다.
HTML 보고서의 상세 기록은 관련 항목 옆의 "펼치기"에 있습니다. 생성 명령: <code>python3 scripts/make_sample_reports.py</code></p>
<table><tr><th>대상</th><th>결함 종류</th><th>판정</th><th>증상 (입력)</th><th>보고서</th></tr>{''.join(cells)}</table>
</body></html>"""
    path = os.path.join(out_dir, "index.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    os.chmod(path, 0o644)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS)
    ap.add_argument("--langs", nargs="+", default=["ko", "en"])
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    gts = {g["id"]: g for g in rb.load_ground_truth()}
    missing = [t for t in args.targets if t not in gts]
    if missing:
        ap.error(f"unknown targets: {missing}")
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.strip()
    tmp = tempfile.mkdtemp(prefix="samples_")
    entries = []
    try:
        for tid in args.targets:
            rows = make_one(gts[tid], args.out, args.langs, tmp)
            entries.append((gts[tid], rows))
            print(f"{tid:24s} " + "  ".join(f"{r['lang']}={r['verdict']}" for r in rows), flush=True)
            shutil.rmtree(os.path.join(tmp, "corpus"), ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    write_index(args.out, entries, commit)
    print(f"index: {os.path.join(args.out, 'index.html')}")


if __name__ == "__main__":
    main()
