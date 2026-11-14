"""Reproducibility section of the diagnostic report: what a reader needs to re-explain the same diagnosis.

``ReproducibilitySection`` is a field of :class:`extractor.diagnostic_report.DiagnosticReport`
(``section_j_reproducibility``).  Only values the engine actually recorded are filled in; everything else is
``None`` and is printed as "unknown" ("알 수 없음"), never guessed.

Where each value comes from:
  * build-ID status       ``section_b_target_context.build_id_check`` (set by ``TargetAssessor``: the process build ID
                          from /proc identity compared with the build ID of the debug image).  Absent -> UNKNOWN.
  * recipe id / version   the executed checks of section D (``recipe_id``, ``recipe_version`` copied from the recipe
                          specification when the check ran), in start-timestamp order.
  * timestamps / samples  the check start/end timestamps, section B investigation start/end, observation interval and
                          duration, ``collection_impact.samples_collected`` and the thread sampler's own
                          ``samples_collected`` / ``window_sec`` when the check kept them.
  * tool version/commit   ``pyproject.toml`` and ``git rev-parse HEAD`` of the checkout this code runs from.
  * kernel / arch / libc  ``target.abi`` of the diagnosis result (architecture, libc, libc version); the kernel release
                          only for a local target (the kernel of the host the report is generated on).
"""

from __future__ import annotations

import html
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

BUILD_ID_MATCHED = "MATCHED"
BUILD_ID_MISMATCHED = "MISMATCHED"
BUILD_ID_UNKNOWN = "UNKNOWN"

_NOT_RUN = ("NOT_EXECUTED", "SKIPPED")


@dataclass
class ReproducibilitySection:
    tool_version: Optional[str] = None
    tool_commit: Optional[str] = None
    target_kernel: Optional[str] = None
    target_arch: Optional[str] = None
    target_libc: Optional[str] = None
    # "diagnosis": recorded when the diagnosis ran; "export_time_detection": nothing was recorded, re-read at export
    target_source: Optional[str] = None
    # rows: {module, debug_image, process_build_id, debug_build_id, status, note}
    build_id_checks: List[Dict[str, Any]] = field(default_factory=list)
    # rows in execution order: {order, recipe_id, recipe_version, check_id, status, started_at, ended_at,
    #                           duration_s, samples, sampling_window_s}
    recipes: List[Dict[str, Any]] = field(default_factory=list)
    # {started_at, ended_at, interval_s, duration_s, samples_collected, wall_clock_ms}
    observation: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReproducibilitySection":
        names = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in (data or {}).items() if k in names})


# ---------------------------------------------------------------------------------------------------------- build

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_tool_cache: Dict[str, Optional[str]] = {}


def tool_identity() -> Dict[str, Optional[str]]:
    """Version (``pyproject.toml``) and commit (``git rev-parse HEAD``) of this checkout; None when unavailable."""
    if not _tool_cache:
        version = commit = None
        try:
            with open(os.path.join(_REPO_ROOT, "pyproject.toml"), encoding="utf-8") as fh:
                m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', fh.read())
            version = m.group(1) if m else None
        except OSError:
            pass
        try:
            out = subprocess.run(["git", "-C", _REPO_ROOT, "rev-parse", "--short=12", "HEAD"], capture_output=True,
                                 text=True, timeout=5)
            commit = out.stdout.strip() or None if out.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            pass
        _tool_cache.update({"version": version, "commit": commit})
    return dict(_tool_cache)


def _build_id_rows(sec_b: Dict[str, Any], debug_image: Optional[str]) -> List[Dict[str, Any]]:
    chk = sec_b.get("build_id_check") if isinstance(sec_b.get("build_id_check"), dict) else None
    module = sec_b.get("binary_path") or sec_b.get("companion_elf") or sec_b.get("target_process_name")
    image = sec_b.get("companion_elf") or debug_image
    if chk:
        return [{"module": module, "debug_image": image, "process_build_id": chk.get("process_build_id"),
                 "debug_build_id": chk.get("debug_build_id"), "status": chk.get("status") or BUILD_ID_UNKNOWN,
                 "note": None}]
    # Not recorded (older report, or the image / process had no readable build ID): never inferred from build_id alone.
    return [{"module": module, "debug_image": image, "process_build_id": None, "debug_build_id": None,
             "status": BUILD_ID_UNKNOWN, "note": "not_recorded"}]


def _recipe_rows(checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ran = [(i, c) for i, c in enumerate(checks) if isinstance(c, dict) and c.get("status") not in _NOT_RUN
           and c.get("start_timestamp")]
    ran.sort(key=lambda ic: (str(ic[1].get("start_timestamp")), ic[0]))
    rows = []
    for n, (_, c) in enumerate(ran, 1):
        ts = (c.get("actual_observations") or {}).get("thread_sampling") if isinstance(c.get("actual_observations"), dict) else None
        ts = ts if isinstance(ts, dict) else {}
        dur = c.get("duration_seconds")
        rows.append({
            "order": n, "recipe_id": c.get("recipe_id"), "recipe_version": c.get("recipe_version") or None,
            "check_id": c.get("check_id"), "status": c.get("status"),
            "started_at": c.get("start_timestamp"), "ended_at": c.get("completion_timestamp"),
            "duration_s": round(float(dur), 3) if isinstance(dur, (int, float)) else None,
            "samples": ts.get("samples_collected"), "sampling_window_s": ts.get("window_sec"),
        })
    return rows


def build_reproducibility(report: Dict[str, Any], result: Optional[Dict[str, Any]] = None) -> ReproducibilitySection:
    """Reproducibility section from a ``DiagnosticReport`` dict and (optionally) the diagnosis result dict."""
    result = result or {}
    sec_b = report.get("section_b_target_context") or {}
    sec_d = report.get("section_d_detailed_inspection_results") or {}
    target = result.get("target") if isinstance(result.get("target"), dict) else {}
    abi = target.get("abi") if isinstance(target.get("abi"), dict) else {}
    impact = result.get("collection_impact") if isinstance(result.get("collection_impact"), dict) else {}
    ident = tool_identity()
    recorded = sec_b.get("target_abi") if isinstance(sec_b.get("target_abi"), dict) else None
    abi = recorded or abi
    source = "diagnosis" if recorded else (target.get("abi_source") or ("diagnosis" if abi else None))
    detected = abi.get("status") == "DETECTED"
    libc = abi.get("libc") if detected and abi.get("libc") not in (None, "", "unknown", "UNKNOWN") else None
    if libc and abi.get("libc_version"):
        libc = f"{libc} {abi['libc_version']}"
    samples = impact.get("samples_collected")
    return ReproducibilitySection(
        tool_version=ident["version"], tool_commit=ident["commit"],
        target_kernel=abi.get("kernel_release") or None,   # the target host's, never the rendering host's
        target_arch=abi.get("architecture") if detected else None,
        target_libc=libc,
        target_source=source,
        build_id_checks=_build_id_rows(sec_b, target.get("debug_image")),
        recipes=_recipe_rows(sec_d.get("checks") or []),
        observation={
            "started_at": sec_b.get("investigation_start_time") or None,
            "ended_at": sec_b.get("investigation_end_time") or None,
            "interval_s": sec_b.get("observation_interval_sec"),
            "duration_s": sec_b.get("observation_duration_sec"),
            "samples_collected": samples if isinstance(samples, int) else None,
            "wall_clock_ms": impact.get("wall_clock_ms") if isinstance(impact.get("wall_clock_ms"), (int, float)) else None,
        },
    )


# -------------------------------------------------------------------------------------------------------- render
# (en, ko) per key, like ``human_report.T`` / ``incident_report._MD``
_T: Dict[str, Any] = {
    "title": ("Reproducibility", "재현 정보"),
    "intro": ("What a reader needs to re-explain this diagnosis. A value the engine did not record is shown as unknown.",
              "이 진단을 다시 설명하는 데 필요한 정보입니다. 엔진이 기록하지 못한 값은 알 수 없음으로 표시합니다."),
    "unknown": ("unknown", "알 수 없음"),
    "redetected": (" (re-read at export time, not recorded during the diagnosis)",
                   " (진단 때 기록되지 않아 보고서를 만들 때 다시 읽음)"),
    "h_env": ("Tool and target", "도구와 대상"),
    "tool": ("dynamicState version / commit", "dynamicState 버전 / 커밋"),
    "kernel": ("Target kernel", "대상 커널"),
    "arch": ("Target architecture", "대상 아키텍처"),
    "libc": ("Target libc", "대상 libc"),
    "h_bid": ("Build ID against the debug info used", "빌드 ID와 사용한 디버그 정보의 일치 여부"),
    "bid_cols": (("Binary", "Debug info", "Process build ID", "Debug info build ID", "Match"),
                 ("바이너리", "디버그 정보", "프로세스 빌드 ID", "디버그 정보 빌드 ID", "일치 여부")),
    "bid_MATCHED": ("matched", "일치"), "bid_MISMATCHED": ("mismatched", "불일치"), "bid_UNKNOWN": ("unknown", "알 수 없음"),
    "bid_scope": ("Only the main binary is compared; shared libraries are not checked.",
                  "주 실행 파일만 비교하며 공유 라이브러리는 확인하지 않습니다."),
    "bid_nr": ("The comparison was not recorded for this diagnosis.", "이 진단에서는 비교 결과가 기록되지 않았습니다."),
    "h_obs": ("Observation window", "관측 구간"),
    "start": ("Started", "시작"), "end": ("Ended", "종료"),
    "interval": ("Sampling interval", "표본 간격"), "duration": ("Planned window", "계획한 관측 시간"),
    "samples": ("Samples collected", "수집한 표본 수"), "wall": ("Wall-clock time", "경과 시간"),
    "sec": ("{x} s", "{x}초"), "ms": ("{x} ms", "{x}ms"), "n": ("{x}", "{x}회"),
    "h_rec": ("Recipes in execution order", "실행한 레시피 (실행 순서)"),
    "rec_cols": (("#", "Recipe", "Version", "Result", "Started", "Ended", "Samples"),
                 ("순번", "레시피", "버전", "결과", "시작", "종료", "표본")),
    "rec_none": ("No recipe was executed.", "실행된 레시피가 없습니다."),
}


def _t(key: str, li: int) -> Any:
    return _T[key][li]


def _v(x: Any, li: int, fmt: Optional[str] = None) -> str:
    if x is None or x == "":
        return _t("unknown", li)
    return _t(fmt, li).format(x=x) if fmt else str(x)


def _env_pairs(s: ReproducibilitySection, li: int) -> List[tuple]:
    tool = _t("unknown", li) if not (s.tool_version or s.tool_commit) else \
        f"{s.tool_version or _t('unknown', li)} / {s.tool_commit or _t('unknown', li)}"
    sfx = _t("redetected", li) if s.target_source == "export_time_detection" else ""
    return [(_t("tool", li), tool), (_t("kernel", li), _v(s.target_kernel, li) + (sfx if s.target_kernel else "")),
            (_t("arch", li), _v(s.target_arch, li) + (sfx if s.target_arch else "")),
            (_t("libc", li), _v(s.target_libc, li) + (sfx if s.target_libc else ""))]


def _obs_pairs(s: ReproducibilitySection, li: int) -> List[tuple]:
    o = s.observation or {}
    return [(_t("start", li), _v(o.get("started_at"), li)), (_t("end", li), _v(o.get("ended_at"), li)),
            (_t("interval", li), _v(o.get("interval_s"), li, "sec")),
            (_t("duration", li), _v(o.get("duration_s"), li, "sec")),
            (_t("samples", li), _v(o.get("samples_collected"), li, "n")),
            (_t("wall", li), _v(round(o["wall_clock_ms"]) if isinstance(o.get("wall_clock_ms"), (int, float)) else None,
                                li, "ms"))]


def _bid_cells(r: Dict[str, Any], li: int) -> List[str]:
    return [_v(r.get("module"), li), _v(r.get("debug_image"), li), _v(r.get("process_build_id"), li),
            _v(r.get("debug_build_id"), li), _t("bid_" + str(r.get("status") or BUILD_ID_UNKNOWN), li)
            if ("bid_" + str(r.get("status"))) in _T else _t("unknown", li)]


def _rec_cells(r: Dict[str, Any], li: int) -> List[str]:
    return [str(r.get("order")), _v(r.get("recipe_id"), li), _v(r.get("recipe_version"), li), _v(r.get("status"), li),
            _v(r.get("started_at"), li), _v(r.get("ended_at"), li), _v(r.get("samples"), li)]


def render_markdown(s: ReproducibilitySection, language: str = "en", heading: str = "##") -> List[str]:
    """Markdown lines of the section (``heading`` is the section's own heading prefix)."""
    li = 1 if language == "ko" else 0
    out = [f"{heading} {_t('title', li)}", "", _t("intro", li), "", f"**{_t('h_env', li)}**"]
    out += [f"- {k}: `{v}`" for k, v in _env_pairs(s, li)]
    out += ["", f"**{_t('h_bid', li)}**", "", "| " + " | ".join(_t("bid_cols", li)) + " |", "| " + " | ".join([":---"] * 5) + " |"]
    for r in s.build_id_checks or []:
        out.append("| " + " | ".join(f"`{c}`" for c in _bid_cells(r, li)) + " |")
    out.append("")
    out.append(_t("bid_scope", li) + ("" if any(r.get("note") != "not_recorded" for r in s.build_id_checks or [])
                                      else " " + _t("bid_nr", li)))
    out += ["", f"**{_t('h_obs', li)}**"] + [f"- {k}: `{v}`" for k, v in _obs_pairs(s, li)]
    out += ["", f"**{_t('h_rec', li)}**", ""]
    if s.recipes:
        out += ["| " + " | ".join(_t("rec_cols", li)) + " |", "| " + " | ".join([":---"] * 7) + " |"]
        out += ["| " + " | ".join(f"`{c}`" if i else c for i, c in enumerate(_rec_cells(r, li))) + " |" for r in s.recipes]
    else:
        out.append(_t("rec_none", li))
    return out


def render_html(s: ReproducibilitySection, language: str = "en") -> str:
    """HTML fragment (no script) of the section; styled by the surrounding page's ``dsv`` / ``ds-summary`` classes."""
    li = 1 if language == "ko" else 0
    e = html.escape

    def table(cols, rows):
        head = "".join(f"<th>{e(c)}</th>" for c in cols)
        body = "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in rows)
        return f'<table class="ds-repro-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'

    def dl(pairs):
        return "<dl>" + "".join(f"<dt>{e(k)}</dt><dd><code>{e(v)}</code></dd>" for k, v in pairs) + "</dl>"

    nr = any(r.get("note") == "not_recorded" for r in s.build_id_checks or [])
    parts = [f'<section class="ds-repro" lang="{language}" id="reproducibility">',
             "<style>.ds-repro{max-width:860px;margin:24px auto;padding:16px 24px;border:1px solid #cbd5e1;border-radius:8px;"
             "background:#fff;color:#0f172a;font:14px/1.5 -apple-system,'Segoe UI','Noto Sans KR',sans-serif;overflow-x:auto}"
             ".ds-repro table{border-collapse:collapse;width:100%;font-size:13px}.ds-repro th,.ds-repro td{border:1px solid #cbd5e1;"
             "padding:3px 6px;text-align:left;vertical-align:top;word-break:break-all}.ds-repro dt{font-weight:600;margin-top:4px}"
             ".ds-repro dd{margin:0}@media (prefers-color-scheme:dark){.ds-repro{background:#0f172a;color:#e2e8f0;border-color:#334155}"
             ".ds-repro th,.ds-repro td{border-color:#334155}}</style>",
             f"<h2>{e(_t('title', li))}</h2>", f"<p>{e(_t('intro', li))}</p>",
             f"<h3>{e(_t('h_env', li))}</h3>", dl(_env_pairs(s, li)),
             f"<h3>{e(_t('h_bid', li))}</h3>",
             table(_t("bid_cols", li), [_bid_cells(r, li) for r in s.build_id_checks or []]),
             f"<p>{e(_t('bid_scope', li) + (' ' + _t('bid_nr', li) if nr else ''))}</p>",
             f"<h3>{e(_t('h_obs', li))}</h3>", dl(_obs_pairs(s, li)),
             f"<h3>{e(_t('h_rec', li))}</h3>"]
    parts.append(table(_t("rec_cols", li), [_rec_cells(r, li) for r in s.recipes]) if s.recipes
                 else f"<p>{e(_t('rec_none', li))}</p>")
    parts.append("</section>")
    return "\n".join(parts)


# ------------------------------------------------------------------------------------------- incident report outline
# The incident report shows this section in its common outline (``human_report.compose``, section "Reproducibility /
# 재현 정보"): the same facts as ``render_markdown``, worded for a reader (checks named in words with the id after,
# results in words, local times with the timezone stated once, recipe start times as offsets from the start of the
# observation).  The exact timestamps of every check are in ``detail_html`` (a collapsed block) and in the JSON.
_O: Dict[str, Any] = {
    "h_rec": ("Checks run, with their recipe versions", "실행한 검사와 레시피 버전"),
    "window": ("{a} to {b}", "{a} ~ {b}"),
    "n_checks": (" checks", "개"),
    "v_common": ("{v} for {n} of them", "{n}개는 {v}"),
    "where": ("The order, version, start time and duration of every check are in the detail block of the HTML report "
              "and in the JSON (`reproducibility.recipes`).",
              "검사별 실행 순서, 레시피 버전, 시작 시각, 걸린 시간은 HTML 보고서의 상세 블록과 JSON "
              "(`reproducibility.recipes`)에 있습니다."),
    "rec_cols": (("#", "Check", "Version", "Result", "Started (after the window opened)", "Took", "Samples"),
                 ("순번", "검사", "버전", "결과", "시작 (관측 시작 후)", "걸린 시간", "표본")),
    "detail": ("Exact start and end times of every check, as recorded", "검사별 정확한 시작·종료 시각 (기록 그대로)"),
}


def _o(key: str, li: int) -> Any:
    return _O[key][li]


def _parse(ts: Any):
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(ts))
    except (TypeError, ValueError):
        return None


def _local(ts: Any, li: int) -> str:
    """An ISO timestamp as local time with its timezone (``2026-11-13 06:58:46 UTC``); unknown when absent."""
    d = _parse(ts)
    if d is None:
        return _v(ts, li)
    d = d.astimezone() if d.tzinfo else d
    off = d.strftime("%z")
    if not off or off in ("+0000", "-0000"):
        return f"{d:%Y-%m-%d %H:%M:%S} UTC" if off else f"{d:%Y-%m-%d %H:%M:%S}"
    return f"{d:%Y-%m-%d %H:%M:%S} {d.tzname() or ''} (UTC{off[:3]}:{off[3:]})".replace("  ", " ")


def _status_words(st: Any, li: int) -> str:
    from .human_report import T, check_group
    return T["g_" + check_group(st)][li] if st else _t("unknown", li)


def _rec_outline_cells(r: Dict[str, Any], start: Any, li: int) -> List[str]:
    from .human_report import check_label, fmt_ms
    t0, t1 = _parse(start), _parse(r.get("started_at"))
    off = (t1 - t0).total_seconds() if t0 is not None and t1 is not None else None
    after = _t("sec", li).format(x=f"+{off:.2f}") if off is not None else _t("unknown", li)
    took = fmt_ms(r["duration_s"] * 1000.0, li) if isinstance(r.get("duration_s"), (int, float)) else _t("unknown", li)
    return [str(r.get("order")), check_label(str(r.get("recipe_id")), li) if r.get("recipe_id") else _t("unknown", li),
            f"`{_v(r.get('recipe_version'), li)}`", _status_words(r.get("status"), li), after, took,
            _v(r.get("samples"), li)]


def outline_markdown(s: ReproducibilitySection, language: str = "en") -> List[str]:
    """The section's Markdown lines for the incident report outline (without its heading): only the short facts.
    The target kernel / architecture / libc and the build-ID match are in the report's target card; the per-check
    table (order, version, start offset, duration) is in ``detail_html`` and in the opt-in Markdown appendix."""
    li = 1 if language == "ko" else 0
    o = s.observation or {}
    tool = _env_pairs(s, li)[0]
    window = _o("window", li).format(a=_local(o.get("started_at"), li), b=_local(o.get("ended_at"), li))
    extra = [p for p in _obs_pairs(s, li)[2:4] if p[1] != _t("unknown", li)]
    window += "".join(f", {k} {v}" for k, v in extra)
    out = [_t("intro", li), "", f"- {tool[0]}: `{tool[1]}`", f"- {_t('h_obs', li)}: {window}"]
    if s.recipes:
        versions: Dict[str, List[str]] = {}
        for r in s.recipes:
            versions.setdefault(str(r.get("recipe_version") or _t("unknown", li)), []).append(str(r.get("recipe_id")))
        common = max(versions, key=lambda v: len(versions[v]))
        from .human_report import check_label
        parts = [_o("v_common", li).format(v=f"`{common}`", n=len(versions[common]))]
        parts += [f"`{v}`: " + ", ".join(check_label(x, li) for x in ids) for v, ids in versions.items() if v != common]
        out.append(f"- {_o('h_rec', li)}: {len(s.recipes)}" + _o("n_checks", li) + " (" + "; ".join(parts) + ")")
        out.append("- " + _o("where", li))
    else:
        out.append(f"- {_o('h_rec', li)}: {_t('rec_none', li)}")
    return out


def detail_html(s: ReproducibilitySection, language: str = "en") -> str:
    """The detail behind the section: every executed check in order with its recipe version, start offset and
    duration, the build-ID comparison, and the recorded timestamps exactly as stored."""
    e = html.escape
    li = 1 if language == "ko" else 0
    o = s.observation or {}
    out = []
    if s.recipes:
        from .human_report import _inline_html
        rows = [_rec_outline_cells(r, o.get("started_at"), li) for r in s.recipes]
        cols = list(_o("rec_cols", li))
        if all(r.get("samples") is None for r in s.recipes):
            cols, rows = cols[:-1], [r[:-1] for r in rows]
        cols += ["Started (recorded)", "Ended (recorded)"]
        rows = [r + [str(x.get("started_at") or ""), str(x.get("ended_at") or "")] for r, x in zip(rows, s.recipes)]
        out.append('<div class="dsd-scroll"><table class="table"><tr>' + "".join(f"<th>{e(c)}</th>" for c in cols) + "</tr>"
                   + "".join("<tr>" + "".join(f"<td>{_inline_html(c)}</td>" for c in r) + "</tr>" for r in rows)
                   + "</table></div>")
    if s.build_id_checks:
        out.append('<div class="dsd-scroll"><table class="table"><tr>' + "".join(f"<th>{e(c)}</th>" for c in _t("bid_cols", li))
                   + "</tr>" + "".join("<tr>" + "".join(f"<td><code>{e(c)}</code></td>" for c in _bid_cells(r, li)) + "</tr>"
                                       for r in s.build_id_checks) + "</table></div>")
    out.append("<p><strong>Observation window (as recorded)</strong></p><ul>"
               + "".join(f"<li><strong>{e(k)}</strong>: <code>{e(str(v))}</code></li>" for k, v in o.items()) + "</ul>")
    return "".join(out)
