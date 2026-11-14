"""Presentation registry: how a problem category and a recipe are shown to a person.

A recipe definition file (``extractor/recipe_plugins/*.py``) already registers its collector and its verdict rule
from that one file (IMP-018).  This registry is the reporting half of the same idea: the same file also registers

* ``register_category``       the plain name of a new problem category (en, ko),
* ``register_recipe_label``   the check-list entry of the recipe: group, name and "looks for" text (en, ko),
* ``register_finding_text``   the lines of the plain-language summary for a finding of that category,
* ``register_finding_viz``    the picture drawn for such a finding in the HTML report,

so adding a diagnosis needs no edit in human_report.py, report_visuals.py or healthy_verdict.py.  Built-in
categories keep their definitions in those modules; a registration here takes precedence.

Callables:
    finding_text(ctx, finding, report) -> {"lines": [markdown line, ...]}   (ctx: human_report._Ctx)
    finding_viz(lx, finding, report, uid) -> html fragment                   (lx: report_visuals._Lx)
Both must only show values present in the evidence and must HTML-escape (viz) every value from the target.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

CATEGORY_LABELS: Dict[str, Tuple[str, str]] = {}
RECIPE_LABELS: Dict[str, Tuple[str, str, str, str, str]] = {}   # recipe id -> (group, name en, name ko, what en, what ko)
FINDING_TEXT: Dict[str, Callable[..., Dict[str, Any]]] = {}
FINDING_VIZ: Dict[str, Callable[..., str]] = {}

# check-list groups a recipe label may use
GROUPS = ("CONCURRENCY", "MEMORY_INTEGRITY", "MEMORY_GROWTH", "ABNORMAL_STATE", "OTHER")

_loaded = False


def _ensure_plugins() -> None:
    """Rendering a saved result must see the same registrations as a live diagnosis."""
    global _loaded
    if not _loaded:
        _loaded = True
        from . import diagnostic_recipes  # noqa: F401 - importing it loads every recipe definition file


def register_category(category: str, en: str, ko: str) -> None:
    CATEGORY_LABELS[str(category)] = (en, ko)


def register_recipe_label(recipe_id: str, group: str, name_en: str, name_ko: str, what_en: str, what_ko: str) -> None:
    if group not in GROUPS:
        raise ValueError(f"group must be one of {GROUPS}, got {group!r}")
    RECIPE_LABELS[str(recipe_id)] = (group, name_en, name_ko, what_en, what_ko)


def register_finding_text(category: str, fn: Callable[..., Dict[str, Any]]) -> None:
    FINDING_TEXT[str(category)] = fn


def register_finding_viz(category: str, fn: Callable[..., str]) -> None:
    FINDING_VIZ[str(category)] = fn


def category_label(category: Any) -> Optional[Tuple[str, str]]:
    _ensure_plugins()
    return CATEGORY_LABELS.get(str(category))


def recipe_label(recipe_id: Any) -> Optional[Tuple[str, str, str, str, str]]:
    _ensure_plugins()
    return RECIPE_LABELS.get(str(recipe_id))


def finding_text(category: Any) -> Optional[Callable[..., Dict[str, Any]]]:
    _ensure_plugins()
    return FINDING_TEXT.get(str(category))


def finding_viz(category: Any) -> Optional[Callable[..., str]]:
    _ensure_plugins()
    return FINDING_VIZ.get(str(category))
