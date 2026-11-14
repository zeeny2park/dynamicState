"""Static location candidates: the general rules added after the held-out validation suite.

Every program here is written for this test (none is a benchmark target).  Each rule is checked with one program
where it must find the line and, where a rule could mislead, one where it must stay silent.
"""

import copy
import os
import shutil
import subprocess
import tempfile
import unittest

from extractor import static_location_candidates as slc

HAVE = bool(shutil.which("gcc") and shutil.which("g++") and shutil.which("readelf"))


def _finding(category, **subjects):
    det = [{"kind": k, "name": n} for k, names in subjects.items() for n in names]
    return {"category": category, "status": "PROBABLE_CAUSE", "subjects": [d["name"] for d in det],
            "subject_details": det, "recipe_ids": ["RX"]}


def _runaway(function, thread):
    return {"section_d_detailed_inspection_results": {"checks": [{
        "recipe_id": "RX", "status": "FAIL",
        "actual_observations": {"runaway_threads": [{"name": thread, "top_function": function}]}}]}}


@unittest.skipUnless(HAVE, "gcc/g++/readelf not available")
class GeneralRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="slcg_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.n = 0

    def build(self, files, cxx=False, opt="-O0"):
        type(self).n += 1
        d = os.path.join(self.tmp, f"p{self.n}")
        os.makedirs(d)
        srcs = []
        for name, text in files.items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write(text)
            if not name.endswith(".h"):
                srcs.append(name)
        out = os.path.join(d, "prog")
        subprocess.run(["g++" if cxx else "gcc", "-g", opt, "-pthread", *(["-std=c++17"] if cxx else []), *srcs,
                        "-o", out], cwd=d, check=True, capture_output=True, timeout=120)
        return out, {name: text.splitlines() for name, text in files.items()}

    def cands(self, binary, finding, report=None):
        before = copy.deepcopy(finding)
        lc = slc.location_candidates(finding, binary, report=report)
        self.assertEqual(finding, before)
        for c in lc["candidates"]:
            self.assertEqual((c["basis"], c["observed"]), ("static", False))
        return lc

    def line(self, lines, needle, nth=1):
        return [i for i, t in enumerate(lines, 1) if needle in t][nth - 1]

    def assertTop(self, lc, file, line):
        self.assertTrue(lc["candidates"], lc)
        top = lc["candidates"][0]
        self.assertEqual((top["file"], top["line"]), (file, line), lc["candidates"])

    # ---- macros, wrappers, multi-file
    def test_allocation_through_a_wrapper_in_another_file_points_at_the_call(self):
        files = {
            "mem.h": "#include <stddef.h>\nvoid *grab(size_t n);\n",
            "mem.c": "#include <stdlib.h>\n#include \"mem.h\"\nvoid *grab(size_t n)\n{\n    void *p = malloc(n);\n"
                     "    if (!p) abort();\n    return p;\n}\n",
            "main.c": "#include <unistd.h>\n#include \"mem.h\"\nstruct item { struct item *nx; char b[300]; };\n"
                      "struct item *pile;\nstatic void push(void)\n{\n    struct item *it = grab(sizeof *it);\n"
                      "    it->nx = pile;\n    pile = it;\n}\nint main(void) { for (int i = 0; i < 3; i++) push(); "
                      "pause(); }\n",
        }
        b, L = self.build(files, opt="-O2")
        lc = self.cands(b, _finding("MEMORY_LEAK", variable=["pile"]))
        self.assertTop(lc, "main.c", self.line(L["main.c"], "grab(sizeof"))
        self.assertIn("through `grab()`", lc["candidates"][0]["reason"])

    def test_call_hidden_in_a_header_macro_is_seen(self):
        files = {
            "q.h": "#include <pthread.h>\n#define TAKE(q) pthread_mutex_lock(&(q)->mu)\n"
                   "struct q { pthread_mutex_t mu; int n; };\nextern struct q work;\n",
            "main.c": "#include <unistd.h>\n#include \"q.h\"\nstruct q work = { PTHREAD_MUTEX_INITIALIZER, 0 };\n"
                      "static void *grabber(void *a)\n{\n    (void)a;\n    TAKE(&work);\n    return 0;\n}\n"
                      "int main(void) { pthread_t t; pthread_create(&t, 0, grabber, 0); pause(); }\n",
        }
        b, L = self.build(files)
        lc = self.cands(b, _finding("ORPHAN_LOCK", lock=["work.mu"]))
        self.assertTop(lc, "main.c", self.line(L["main.c"], "TAKE(&work)"))
        self.assertIn("no matching unlock", lc["candidates"][0]["reason"])

    def test_lock_wrapper_and_same_line_call_while_held(self):
        files = {"main.c": (
            "#include <pthread.h>\n#include <unistd.h>\n"
            "#define LOCKED(b) do { pthread_mutex_lock(&mu); b; pthread_mutex_unlock(&mu); } while (0)\n"
            "static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;\nstatic volatile int a, c;\n"
            "static int peek(void) { int v; LOCKED(v = a); return v; }\n"
            "static void bump(void) { LOCKED(a++; c = peek()); }\n"
            "int main(void) { bump(); pause(); }\n")}
        b, L = self.build(files)
        lc = self.cands(b, _finding("SELF_DEADLOCK", lock=["mu"]))
        lines = {c["line"] for c in lc["candidates"]}
        self.assertEqual(lines, {self.line(L["main.c"], "static int peek"), self.line(L["main.c"], "static void bump")})
        self.assertTrue(any("calls `peek()`" in c["reason"] for c in lc["candidates"]), lc["candidates"])

    def test_deadlock_through_lock_wrappers(self):
        files = {"main.c": (
            "#include <pthread.h>\n#include <unistd.h>\npthread_mutex_t ma = PTHREAD_MUTEX_INITIALIZER, "
            "mb = PTHREAD_MUTEX_INITIALIZER;\nvoid acquire(pthread_mutex_t *m) { pthread_mutex_lock(m); }\n"
            "static void *one(void *x)\n{\n    acquire(&ma);\n    acquire(&mb);\n    return x;\n}\n"
            "int main(void) { pthread_t t; pthread_create(&t, 0, one, 0); pause(); }\n")}
        b, L = self.build(files)
        lc = self.cands(b, _finding("DEADLOCK_INDICATORS", lock=["ma", "mb"]))
        self.assertTop(lc, "main.c", self.line(L["main.c"], "acquire(&ma)"))
        self.assertNotIn(self.line(L["main.c"], "void acquire"), {c["line"] for c in lc["candidates"]})

    def test_thread_start_through_a_wrapper_points_at_the_caller(self):
        files = {"main.c": (
            "#include <pthread.h>\n#include <unistd.h>\ntypedef void *(*fn_t)(void *);\n"
            "static int spawn(fn_t f) { pthread_t t; return pthread_create(&t, 0, f, 0); }\n"
            "static void *idle(void *a) { pause(); return a; }\n"
            "int main(void)\n{\n    for (int i = 0; i < 3; i++)\n        spawn(idle);\n    pause();\n}\n")}
        b, L = self.build(files)
        lc = self.cands(b, _finding("THREAD_LEAK", function=["idle"]))
        self.assertTop(lc, "main.c", self.line(L["main.c"], "spawn(idle)"))

    # ---- C++
    def test_cpp_member_lock_by_type_and_by_this(self):
        files = {"m.cpp": (
            "#include <mutex>\n#include <unistd.h>\nstruct Box { std::mutex m; int v = 0; };\nBox g_left, g_right;\n"
            "static void move(Box &a, Box &b)\n{\n    std::lock_guard<std::mutex> x(a.m);\n"
            "    std::lock_guard<std::mutex> y(b.m);\n    a.v--; b.v++;\n}\n"
            "class Store {\npublic:\n    int size() { std::lock_guard<std::mutex> h(mu_); return n_; }\n"
            "    void put() { std::lock_guard<std::mutex> h(mu_); if (size() < 9) n_++; }\n"
            "private:\n    std::mutex mu_;\n    int n_ = 0;\n};\nStore g_store;\n"
            "int main() { move(g_left, g_right); g_store.put(); pause(); }\n")}
        b, L = self.build(files, cxx=True)
        lc = self.cands(b, _finding("DEADLOCK_INDICATORS", lock=["g_left.m", "g_right.m"]))
        self.assertEqual({c["line"] for c in lc["candidates"]},
                         {self.line(L["m.cpp"], "x(a.m)"), self.line(L["m.cpp"], "y(b.m)")})
        lc = self.cands(b, _finding("SELF_DEADLOCK", lock=["g_store.mu_"]))
        self.assertEqual({c["line"] for c in lc["candidates"]},
                         {self.line(L["m.cpp"], "int size()"), self.line(L["m.cpp"], "void put()")})
        # an unrelated lock name of a different type: nothing
        self.assertEqual(self.cands(b, _finding("SELF_DEADLOCK", lock=["g_left.mu_"]))["candidates"], [])

    def test_cpp_member_copy_and_member_delete(self):
        files = {"c.cpp": (
            "#include <cstring>\n#include <unistd.h>\nclass Buf {\npublic:\n    Buf() : p_(new char[8]) {}\n"
            "    void put(const char *s, size_t n) { std::memcpy(p_, s, n); }\n    void drop() { delete[] p_; }\n"
            "    char *p_;\n};\nBuf *g_buf;\nBuf g_one;\n"
            "int main(int argc, char **) { g_buf = new Buf; g_buf->put(\"abcdefghijkl\", 10 + argc); g_one.drop(); "
            "pause(); }\n")}
        b, L = self.build(files, cxx=True)
        lc = self.cands(b, _finding("MEMORY_CORRUPTION", variable=["g_buf", "g_buf->p_"]))
        self.assertTop(lc, "c.cpp", self.line(L["c.cpp"], "std::memcpy"))
        self.assertIn("member `p_` of `this`", lc["candidates"][0]["reason"])
        lc = self.cands(b, _finding("INVALID_DOUBLE_FREE", variable=["g_one", "g_one.p_"]))
        self.assertTop(lc, "c.cpp", self.line(L["c.cpp"], "delete[] p_"))

    def test_container_of_pointers_dropped_without_delete(self):
        files = {"v.cpp": (
            "#include <pthread.h>\n#include <unistd.h>\n#include <vector>\nstruct Rec { char b[200]; };\n"
            "static std::vector<Rec *> recs;\n"
            "static void add() { Rec *r = new Rec(); recs.push_back(r); }\n"
            "static void trim() { if (recs.size() > 4) recs.erase(recs.begin()); }\n"
            "static void tidy() { for (Rec *r : recs) delete r; recs.clear(); }\n"
            "int main() { for (int i = 0; i < 9; i++) { add(); trim(); } tidy(); pause(); }\n")}
        b, L = self.build(files, cxx=True)
        lc = self.cands(b, _finding("MEMORY_LEAK"))
        lines = [c["line"] for c in lc["candidates"]]
        self.assertEqual(lines[0], self.line(L["v.cpp"], "static void trim"), lc["candidates"])
        # push_back keeps the pointer (a library call): the allocation is not "kept only in a local"
        self.assertNotIn(self.line(L["v.cpp"], "static void add"), lines)
        # tidy() deletes before clear(): not a drop
        self.assertNotIn(self.line(L["v.cpp"], "static void tidy"), lines)

    def test_pointer_handed_to_unseen_code_is_no_unreachable_candidate(self):
        files = {"h.c": (
            "#include <stdlib.h>\n#include <unistd.h>\ntypedef void (*sink_t)(void *);\nsink_t sinks[2];\n"
            "static void keep(void *p) { static void *last; last = p; }\n"
            "static void feed(int k) { char *b = malloc(64); sinks[k & 1](b); }\n"
            "int main(void) { sinks[0] = keep; sinks[1] = keep; for (int i = 0; i < 4; i++) feed(i); pause(); }\n")}
        b, _L = self.build(files)
        self.assertEqual(self.cands(b, _finding("MEMORY_LEAK"))["candidates"], [])

    # ---- mapping growth without owner, busy loop fallbacks
    def test_mapping_growth_without_owner(self):
        files = {"m.c": (
            "#include <sys/mman.h>\n#include <unistd.h>\nstatic void *(*src)(size_t);\n"
            "static void *pages(size_t n) { return mmap(0, n, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); }\n"
            "int main(void) { src = pages; for (int i = 0; i < 3; i++) src(4096); pause(); }\n")}
        b, L = self.build(files)
        lc = self.cands(b, _finding("MAPPING_GROWTH", thread_name=["m"]))
        self.assertTop(lc, "m.c", self.line(L["m.c"], "mmap("))
        self.assertIn("owner of the growing mappings was not named", lc["candidates"][0]["reason"])
        many = {"m.c": "#include <sys/mman.h>\n#include <unistd.h>\n" + "".join(
            f"void *p{i}(void) {{ return mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); }}\n"
            for i in range(5)) + "int main(void) { pause(); }\n"}
        b2, _ = self.build(many)
        self.assertEqual(self.cands(b2, _finding("MAPPING_GROWTH"))["candidates"], [])

    def test_spin_loop_with_a_header_without_code_and_named_thread_fallback(self):
        files = {"s.cpp": (
            "#include <atomic>\n#include <pthread.h>\n#include <thread>\n#include <unistd.h>\n"
            "static std::atomic<bool> flag{false};\nstatic volatile long n;\n"
            "static void spin()\n{\n    for (;;) {\n        if (flag.load())\n            break;\n        n++;\n    }\n}\n"
            "int main()\n{\n    std::thread t([] {\n        pthread_setname_np(pthread_self(), \"spinner\");\n"
            "        spin();\n    });\n    pause();\n}\n")}
        b, L = self.build(files, cxx=True)
        loop_body = self.line(L["s.cpp"], "if (flag.load())")
        lc = self.cands(b, _finding("PROCESS_INSTABILITY", thread_name=["spinner"]), report=_runaway("spin", "spinner"))
        self.assertTop(lc, "s.cpp", loop_body)
        # top frame outside the program's own code: found through the function that names the thread, ranked lower
        lc = self.cands(b, _finding("PROCESS_INSTABILITY", thread_name=["spinner"]),
                        report=_runaway("_M_run", "spinner"))
        self.assertTop(lc, "s.cpp", loop_body)
        self.assertIn("names thread `spinner`", lc["candidates"][0]["reason"])
        # no thread observed spinning: nothing
        self.assertEqual(self.cands(b, _finding("PROCESS_INSTABILITY", thread_name=["spinner"]))["candidates"], [])


class MacroExpansion(unittest.TestCase):
    def test_expand(self):
        macros = slc._parse_macros(slc._strip_code([
            "#define NEW(T) ((T *)calloc(1, sizeof(T)))", "#define CAP 16", "#define LOG(...) printf(__VA_ARGS__)",
            "#define BLOCK(b) do { \\", "  lock(); b; \\", "  unlock(); } while (0)"]))
        self.assertEqual(slc._expand_macros("p = NEW(struct x);", macros), "p = ((struct x *)calloc(1, sizeof(struct x)));")
        self.assertEqual(slc._expand_macros("int a[CAP];", macros), "int a[16];")
        self.assertEqual(slc._expand_macros("LOG(\"\", a, b);", macros), "printf(\"\", a, b);")
        self.assertEqual(slc._expand_macros("BLOCK(x++);", macros), "do { lock(); x++; unlock(); } while (0);")
        self.assertEqual(slc._expand_macros("s.CAP = 1;", macros), "s.CAP = 1;")      # a member, not the macro


if __name__ == "__main__":
    unittest.main()
