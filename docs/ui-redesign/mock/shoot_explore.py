"""Screenshots of the exploration mock (docs/ui-redesign/screens/explore/), headless Chromium over file:// URLs.

    python3 docs/ui-redesign/mock/shoot_explore.py [out_dir] [name-filter]

Each shot is (name, query, how): "full" = full page, "view" = one 1100x900 viewport scrolled to the stage's focus,
"clip:<key>" = the element with that data-key / id and some context. ?still=1 stops the canned clock so a shot is stable;
?bar=0 removes the mock toolbar. No server is started.
"""
import os
import sys

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
PAGE = "file://" + os.path.join(HERE, "explore.html")

SHOTS = [
    # each case at 1100 px, light, finished screen
    ("healthy", "case=healthy&stage=0", "full"),
    ("deadlock", "case=deadlock&stage=0", "full"),
    ("overflow", "case=overflow&stage=0", "full"),
    ("threads300", "case=threads300&stage=0", "full"),
    ("pool", "case=pool&stage=0", "full"),
    ("nodebug", "case=nodebug&stage=0", "full"),
    # opened states
    ("healthy-thread-stack", "case=healthy&stage=1", "clip:profile"),
    ("healthy-memory-maps", "case=healthy&stage=2", "clip:profile"),
    ("healthy-variable-search", "case=healthy&stage=3", "clip:profile"),
    ("healthy-watch-sparklines", "case=healthy&stage=4", "clip:observe"),
    ("healthy-compare", "case=healthy&stage=5", "clip:observe"),
    ("healthy-report-observation", "case=healthy&stage=6&view=report", "clip:obs-report"),
    ("deadlock-chips", "case=deadlock&stage=0", "clip:findings"),
    ("deadlock-chip-thread", "case=deadlock&stage=1", "clip:profile"),
    ("deadlock-lock", "case=deadlock&stage=2", "clip:profile"),
    ("deadlock-watch-flat", "case=deadlock&stage=3", "clip:observe"),
    ("overflow-chips", "case=overflow&stage=0", "clip:findings"),
    ("overflow-range-view", "case=overflow&stage=1", "clip:profile"),
    ("overflow-value-follow", "case=overflow&stage=2", "clip:profile"),
    ("overflow-report-observation", "case=overflow&stage=4&view=report", "clip:obs-report"),
    ("threads300-groups", "case=threads300&stage=1", "clip:profile"),
    ("threads300-members", "case=threads300&stage=3", "clip:profile"),
    ("pool-search", "case=pool&stage=1", "clip:profile"),
    ("pool-grid", "case=pool&stage=2", "clip:observe"),
    ("pool-grid-selected", "case=pool&stage=3", "clip:observe"),
    ("pool-compare", "case=pool&stage=4", "clip:observe"),
    ("nodebug-thread-symbols", "case=nodebug&stage=1", "clip:profile"),
    ("nodebug-variables-disabled", "case=nodebug&stage=2", "clip:profile"),
    ("nodebug-raw-range", "case=nodebug&stage=3", "clip:profile"),
    ("nodebug-exited", "case=nodebug&stage=5", "clip:observe"),
    # dark, English, narrowed desktop window, toolbar
    ("dark-deadlock-thread", "case=deadlock&stage=1&theme=dark", "clip:profile"),
    ("dark-pool-grid", "case=pool&stage=3&theme=dark", "clip:observe"),
    ("dark-healthy", "case=healthy&stage=4&theme=dark", "full"),
    ("en-overflow-range", "case=overflow&stage=1&lang=en", "clip:profile"),
    ("w760-healthy-watch", "case=healthy&stage=5", "clip:observe@760"),
    ("mockbar", "case=deadlock&stage=1&bar=1", "view"),
]


def shoot(out, only=None):
    os.makedirs(out, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch()
        for name, q, how in SHOTS:
            if only and only not in name:
                continue
            width = 1100
            if "@" in how:
                how, w = how.split("@")
                width = int(w)
            pg = b.new_page(viewport={"width": width, "height": 900}, device_scale_factor=1)
            bar = "" if "bar=1" in q else "&bar=0"
            pg.goto(PAGE + "?" + q + "&still=1" + bar)
            pg.wait_for_timeout(250)
            path = os.path.join(out, name + ".png")
            if how == "full":
                pg.evaluate("window.scrollTo(0,0)")
                pg.screenshot(path=path, full_page=True)
            elif how == "view":
                pg.screenshot(path=path)
            else:
                key = how.split(":", 1)[1]
                box = pg.evaluate("""k => { const n = document.getElementById(k) || document.querySelector('[data-key="'+k+'"]');
                    window.scrollTo(0,0); const r = n.getBoundingClientRect(); return {x: r.left, y: r.top + window.scrollY, w: r.width, h: r.height}; }""", key)
                pg.set_viewport_size({"width": width, "height": int(min(box["h"] + 120, 2600)) + 60})
                pg.evaluate("y => window.scrollTo(0, y)", max(0, box["y"] - 64))
                pg.wait_for_timeout(120)
                pg.screenshot(path=path)
            pg.close()
            print(name)
        b.close()


if __name__ == "__main__":
    shoot(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs", "ui-redesign", "screens", "explore"),
          sys.argv[2] if len(sys.argv) > 2 else None)
