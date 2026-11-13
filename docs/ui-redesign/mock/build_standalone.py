"""Build one self-contained HTML file from the exploration mock (explore.html + its stylesheets and scripts inlined).

    python3 docs/ui-redesign/mock/build_standalone.py [--out PATH] [--copy PATH ...]

Default output: docs/ui-redesign/mock/dist/explore.standalone.html. The output has no relative fetches, so it opens from
any plain static web server or from disk. The build is a pure function of the source files (no timestamps), so
building twice gives the same bytes; tests/test_explore_mock.py checks that.
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
DEFAULT_OUT = os.path.join(HERE, "dist", "explore.standalone.html")
PAGE = os.path.join(HERE, "explore.html")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def sources():
    """Every file the standalone page is made from, in inlining order (the page first)."""
    html = _read(PAGE)
    css = re.findall(r'<link rel="stylesheet" href="([^"]+)">', html)
    js = re.findall(r'<script src="([^"]+)"></script>', html)
    return [PAGE] + [os.path.normpath(os.path.join(HERE, p)) for p in css + js]


def build():
    html = _read(PAGE)

    def css(m):
        body = _read(os.path.normpath(os.path.join(HERE, m.group(1))))
        return "<style>/* inlined: " + os.path.basename(m.group(1)) + " */\n" + body.replace("</style", "<\\/style") + "</style>"

    def js(m):
        body = _read(os.path.normpath(os.path.join(HERE, m.group(1))))
        if re.search(r"</script", body, re.I):
            raise ValueError(m.group(1) + " contains </script")
        return "<script>/* inlined: " + os.path.basename(m.group(1)) + " */\n" + body + "</script>"

    html = re.sub(r'<link rel="stylesheet" href="([^"]+)">', css, html)
    html = re.sub(r'<script src="([^"]+)"></script>', js, html)
    html = html.replace("<title>dynamicState · 프로세스 탐색 (목업)</title>",
                        "<title>dynamicState · 프로세스 탐색 (목업, 단일 파일)</title>")
    leftover = re.findall(r'(?:href|src)="(?!#)[^"]+"', html)
    if leftover:
        raise ValueError("relative references left: %r" % leftover)
    return html


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--copy", action="append", default=[], help="also write the same file here")
    a = ap.parse_args(argv)
    out = build()
    for path in [a.out] + a.copy:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
        print("%s (%d bytes)" % (path, len(out.encode("utf-8"))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
