"""IMP-011 part 3: remote thread information.

The "remote" side is real: the natively built collector (daemon / one-shot / absent) behind a local ``sh``
transport, the same technique as tests/test_imp021_collector_daemon_channel.py, observing REAL multi-thread
processes (C fixtures compiled at test time).  Local and remote adapters observe the same live process and
their results are compared field by field.  ARM32 execution is not possible here (see the QEMU matrix).
"""

import json
import os
import select
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter
from extractor.thread_sampler import ThreadSampler, ThreadSamplingConfig, judge
from extractor.watch_session import WatchSessionManager

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COLLECTOR_SRC = os.path.join(REPO_ROOT, "target", "collector")
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")
WEIRD = "we ird)(na me"


def local_sh_runner(args, timeout, input_bytes=None):
    res = subprocess.run(["sh", "-c", args[-1]], input=input_bytes, capture_output=True, timeout=timeout)
    return res.returncode, res.stdout.decode(), res.stderr.decode()


def local_sh_stream(args):
    return subprocess.Popen(["sh", "-c", args[-1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)


def pid_alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


@unittest.skipUnless(shutil.which("make") and shutil.which("gcc") and os.path.exists("/proc/self/task"),
                     "make/gcc/procfs not available")
class RemoteThreadInfoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp011r_")
        build = os.path.join(cls.tmp, "build")
        shutil.copytree(COLLECTOR_SRC, build,
                        ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
        r = subprocess.run(["make", "-C", build, "dynamicstate-collector"], capture_output=True, text=True)
        if r.returncode != 0:
            raise unittest.SkipTest("native collector build failed: " + r.stderr[-300:])
        cls.real = os.path.join(build, "dynamicstate-collector")
        cls.bins = {}
        cls.mgr = WatchSessionManager(os.path.join(cls.tmp, "corpus"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _binary(cls, name):
        if name not in cls.bins:
            out = os.path.join(cls.tmp, name)
            subprocess.run(
                ["gcc", "-g", "-O0", "-Wl,--build-id=sha1", "-include",
                 os.path.join(FIXTURES, "imp011_ptracer_any.h"),
                 os.path.join(FIXTURES, name + ".c"), "-o", out, "-pthread"],
                check=True,
            )
            cls.bins[name] = out
        return cls.bins[name]

    def setUp(self):
        self.adapters = []
        self.addCleanup(self._close_all)
        self.log = os.path.join(self.tmp, f"spawn_{self._testMethodName}.log")
        open(self.log, "w").close()
        self.runner_calls = []

    def _close_all(self):
        for a in self.adapters:
            a.close()

    # ---- infrastructure ---------------------------------------------------------------------
    def _spawn(self, name, *args, min_threads=0):
        proc = subprocess.Popen([self._binary(name), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()
            proc.stdout.close()

        self.addCleanup(_kill)
        deadline = time.monotonic() + 20
        if min_threads:   # fixtures without a READY line: wait until every thread is asleep
            while True:
                states = []
                try:
                    tids = os.listdir(f"/proc/{proc.pid}/task")
                except OSError:
                    tids = []
                for t in tids:
                    try:
                        with open(f"/proc/{proc.pid}/task/{t}/stat") as f:
                            states.append(f.read().rsplit(")", 1)[1].split()[0])
                    except OSError:
                        pass
                if len(tids) >= min_threads and states and all(s == "S" for s in states):
                    time.sleep(0.2)
                    break
                self.assertIsNone(proc.poll(), "fixture exited early")
                self.assertLess(time.monotonic(), deadline, "fixture threads never reached steady state")
                time.sleep(0.05)
        else:
            while True:
                r, _, _ = select.select([proc.stdout], [], [], 0.2)
                if r and proc.stdout.readline().startswith(b"READY"):
                    break
                self.assertIsNone(proc.poll(), "fixture exited before READY")
                self.assertLess(time.monotonic(), deadline, "fixture never printed READY")
        return proc

    def _script(self, name, body):
        path = os.path.join(self.tmp, f"{name}_{self._testMethodName}")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)
        return path

    def _counting_collector(self):
        return self._script("coll", f"echo $$ >> {shlex.quote(self.log)}\nexec {shlex.quote(self.real)} \"$@\"\n")

    def _spawned(self):
        with open(self.log) as f:
            return [int(x) for x in f.read().split()]

    def _runner(self, args, timeout, input_bytes=None):
        self.runner_calls.append(args[-1])
        return local_sh_runner(args, timeout, input_bytes=input_bytes)

    def _adapter(self, collector, **kw):
        a = RemoteSshTargetAdapter(host="localhost", command_runner=self._runner, stream_opener=local_sh_stream,
                                   collector_path=collector, **kw)
        self.adapters.append(a)
        return a

    # =========================================================================================
    # (a) same fields, same stable values
    # =========================================================================================
    def test_a_remote_get_threads_equals_local_for_the_same_live_process(self):
        proc = self._spawn("proc_thread_spin_work_block", "swbc")
        local = LocalTargetAdapter()
        for label, kw in (("daemon", {}), ("per-call", {"use_daemon": False})):
            with self.subTest(transport=label):
                remote = self._adapter(self._counting_collector(), **kw)
                l1 = local.get_threads(proc.pid)
                r1 = remote.get_threads(proc.pid)
                time.sleep(0.4)
                r2 = remote.get_threads(proc.pid)
                l2 = local.get_threads(proc.pid)
                self.assertEqual([t["tid"] for t in l1], [t["tid"] for t in r1])
                self.assertGreaterEqual(len(r1), 5)
                for lt, rt in zip(l1, r1):
                    self.assertEqual(set(lt), set(rt), "same field names")
                    for k in lt:
                        if lt[k] is not None and rt[k] is not None:
                            self.assertIs(type(lt[k]), type(rt[k]), f"type of {k}")
                    self.assertEqual(lt["name"], rt["name"])
                names = {t["name"] for t in r1}
                self.assertTrue({"spin_hang", "busy_worker", "blocked_reader", "cv_idle"} <= names, names)
                by_name = {t["name"]: t for t in r1}
                lby = {t["name"]: t for t in l1}
                for blocked in ("blocked_reader", "cv_idle"):
                    lt, rt = lby[blocked], by_name[blocked]
                    self.assertEqual(rt["state"], "S")
                    self.assertEqual(lt["state"], rt["state"])
                    self.assertEqual(lt["syscall"]["nr"], rt["syscall"]["nr"])
                    self.assertEqual(rt["syscall"]["state"], "blocked")
                    self.assertEqual(lt["syscall"]["sp"], rt["syscall"]["sp"])
                    self.assertEqual(lt["syscall"]["pc"], rt["syscall"]["pc"])
                    self.assertEqual(lt["syscall"]["args"], rt["syscall"]["args"])
                    self.assertEqual(lt["stack_info"], rt["stack_info"])
                    self.assertEqual(rt["stack_info"]["sp_int"], rt["syscall"]["sp"])
                    self.assertIsInstance(rt["schedstat"], (dict, type(None)))
                spin, spin_l = by_name["spin_hang"], lby["spin_hang"]
                self.assertTrue(spin["is_running_user_space"] or spin["state"] == "R")
                # plausible monotonic counters between two remote reads (0.4 s apart), consistent with local
                spin2 = {t["name"]: t for t in r2}["spin_hang"]
                self.assertGreater(spin2["utime_ticks"], spin["utime_ticks"])
                for t1, t2 in zip(r1, r2):
                    for k in ("utime_ticks", "stime_ticks", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"):
                        self.assertGreaterEqual(t2[k], t1[k], k)
                self.assertGreaterEqual(spin2["utime_ticks"], {t["name"]: t for t in l1}["spin_hang"]["utime_ticks"])
                if spin["schedstat"] is not None:
                    self.assertGreater(spin2["schedstat"]["run_ns"], spin["schedstat"]["run_ns"])
                self.assertEqual(remote.last_threads_transport, "daemon" if label == "daemon" else "collector")

    def test_a_syscall_wire_format_and_framing(self):
        proc = self._spawn("proc_thread_spin_work_block", "b")
        p = subprocess.Popen([self.real, "--daemon"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (p.kill(), p.wait(), p.stdout.close(), p.stdin.close()))

        def ask(line):
            p.stdin.write(line + "\n")
            p.stdin.flush()
            reply = p.stdout.readline()
            self.assertTrue(reply.endswith("\n"))
            self.assertNotIn("\n", reply[:-1])
            return json.loads(reply)

        ok = ask(f"THREADS {proc.pid}")
        self.assertTrue(ok["success"])
        self.assertEqual(ok["pid"], proc.pid)
        self.assertEqual(ok["count"], len(ok["threads"]))
        self.assertFalse(ok["more"])
        t = next(x for x in ok["threads"] if x["comm"] == "blocked_reader")
        for k in ("tid", "comm", "state", "utime", "stime", "vol", "invol", "syscall", "cpu"):
            self.assertIn(k, t)
        self.assertEqual(len(t["syscall"].split()), 9)        # nr a0..a5 sp pc
        self.assertEqual(ask(f"THREADS {proc.pid} {t['tid']}")["count"], len([x for x in ok["threads"] if x["tid"] > t["tid"]]))
        self.assertEqual(ask("THREADS 0")["error"], "INVALID_PID")
        self.assertEqual(ask("THREADS abc")["error"], "INVALID_PID")
        self.assertEqual(ask(f"THREADS {proc.pid} -5")["error"], "INVALID_ARGS")
        self.assertEqual(ask("THREADS 4194303")["error"], "TARGET_TERMINATED")
        self.assertEqual(ask("PING")["status"], "PONG")      # the channel survives every error reply
        out = subprocess.run([self.real, "-p", str(proc.pid), "--threads"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertEqual(json.loads(out.stdout)["count"], ok["count"])

    # =========================================================================================
    # (b) thread sampler through the remote adapter
    # =========================================================================================
    def _collect_and_judge(self, adapter, pid, companion):
        cfg = ThreadSamplingConfig(runaway_cpu_share=0.3)   # robust against a loaded CI box; same for both sides
        series = ThreadSampler(adapter, self.mgr).collect(pid, companion, cfg)
        return series, judge(series)

    def test_b_sampler_remote_flags_spinner_and_long_waits_like_local(self):
        proc = self._spawn("proc_thread_spin_work_block", "swbc")
        comp = self._binary("proc_thread_spin_work_block")
        s_loc, j_loc = self._collect_and_judge(LocalTargetAdapter(), proc.pid, comp)
        remote = self._adapter(self._counting_collector())
        s_rem, j_rem = self._collect_and_judge(remote, proc.pid, comp)
        for j in (j_loc, j_rem):
            self.assertEqual(j["thread_sampling"]["status"], "OK", j["thread_sampling"])
        self.assertIsNone(s_rem.stop_reason)
        self.assertEqual([t["name"] for t in j_loc["runaway_threads"]], ["spin_hang"])
        self.assertEqual([t["name"] for t in j_rem["runaway_threads"]], ["spin_hang"])
        self.assertEqual(j_rem["runaway_threads"][0]["verdict"], "CPU monopoly without observable progress")

        def waits(j):
            return {t["name"]: (t["syscall"], t["verdict"], t["expectation"]) for t in j["long_wait_threads"]}
        self.assertEqual(waits(j_loc), waits(j_rem))
        self.assertEqual(waits(j_rem)["blocked_reader"][0], "read")
        self.assertEqual(waits(j_rem)["cv_idle"][0], "futex")
        self.assertEqual(sorted(t["name"] for t in j_loc["thread_summary"]),
                         sorted(t["name"] for t in j_rem["thread_summary"]))
        self.assertEqual(len(self._spawned()), 1)
        # remote samples carry the scheduler counters the follow-up "always runnable" rule needs
        self.assertTrue(any("schedstat" in r for r in s_rem.samples[-1]["threads"].values()) or
                        not os.path.exists("/proc/self/schedstat"))

    # =========================================================================================
    # (c) CFI call stacks through the remote adapter / (d) deadlock recipe
    # =========================================================================================
    def _inspect(self, adapter, pid, name):
        return self.mgr.inspect_thread_callstacks_and_locks(pid=pid, companion_elf_path=self._binary(name),
                                                            adapter=adapter)

    @staticmethod
    def _stacks(res):
        return {t["tid"]: [(f.get("function_name"), f.get("unwind"), bool(f.get("estimated"))) for f in t["callstack"]]
                for t in res["threads"]}

    def test_c_remote_blocked_thread_callstack_is_cfi_unwound_and_equals_local(self):
        proc = self._spawn("proc_thread_circular_deadlock", min_threads=3)
        loc = self._inspect(LocalTargetAdapter(), proc.pid, "proc_thread_circular_deadlock")
        remote = self._adapter(self._counting_collector())
        rem = self._inspect(remote, proc.pid, "proc_thread_circular_deadlock")
        self.assertEqual(self._stacks(loc), self._stacks(rem))
        self.assertEqual([t["unwind_status"] for t in loc["threads"]], [t["unwind_status"] for t in rem["threads"]])
        for t in rem["threads"]:
            self.assertEqual(t["unwind_status"], "COMPLETE", t.get("unwind_stop_reason"))
            self.assertFalse(any(f["estimated"] for f in t["callstack"]))
            self.assertTrue(any(f["unwind"] == "cfi" for f in t["callstack"][1:]))
        worker = next(t for t in rem["threads"] if "worker_1" in [f["function_name"] for f in t["callstack"]])
        names = [f["function_name"] for f in worker["callstack"]]
        self.assertEqual(names[1:3], ["pthread_mutex_lock", "worker_1"])      # libc wait wrapper frames then user code
        self.assertEqual(worker["callstack"][0]["unwind"], "registers")

    def test_c_library_image_not_fetchable_stops_and_labels_estimated(self):
        proc = self._spawn("proc_thread_circular_deadlock", min_threads=3)
        remote = self._adapter(self._counting_collector())
        with mock.patch.object(RemoteSshTargetAdapter, "read_target_file", return_value=None):
            rem = self._inspect(remote, proc.pid, "proc_thread_circular_deadlock")
        for t in rem["threads"]:
            self.assertNotEqual(t["unwind_status"], "COMPLETE", t["unwind_stop_reason"])
            frames = t["callstack"]
            self.assertTrue(frames)
            self.assertTrue(any(f["estimated"] for f in frames), frames)
            first_est = next(i for i, f in enumerate(frames) if f["estimated"])
            self.assertTrue(all(f["estimated"] for f in frames[first_est:]), "everything past the gap is estimated")
            self.assertTrue(all(not f["estimated"] for f in frames[:first_est]))
            # no CFI frame can follow a module whose image is unavailable
            for f in frames[first_est:]:
                self.assertNotEqual(f["unwind"], "cfi")

    def test_c_library_images_are_fetched_once_and_cached(self):
        from extractor import remote_module_images as rmi
        rmi.clear_cache()
        proc = self._spawn("proc_thread_circular_deadlock", min_threads=3)
        remote = self._adapter(self._counting_collector())
        def libs():   # image fetches (the identity probe also reads /proc/PID/exe through the same API)
            return [c for c in rtf.call_args_list if not c.args[2].startswith("/proc/")]
        with mock.patch.object(RemoteSshTargetAdapter, "read_target_file", autospec=True,
                               side_effect=RemoteSshTargetAdapter.read_target_file) as rtf:
            self._inspect(remote, proc.pid, "proc_thread_circular_deadlock")
            first = len(libs())
            self._inspect(remote, proc.pid, "proc_thread_circular_deadlock")
            self.assertEqual(len(libs()), first, "second inspection reuses the cached images")
        self.assertGreaterEqual(first, 1)
        fetched = [c.args[2] for c in libs()]
        self.assertEqual(len(fetched), len(set(fetched)), "each library fetched at most once")
        self.assertTrue(any(f.endswith(".so.6") or ".so" in f for f in fetched), fetched)
        self.assertTrue(all(c.args[3] == rmi.max_image_bytes() + 1 for c in libs()), "size cap applied")

    def test_c_oversized_library_image_is_skipped_not_guessed(self):
        from extractor import remote_module_images as rmi
        rmi.clear_cache()
        proc = self._spawn("proc_thread_circular_deadlock", min_threads=3)
        remote = self._adapter(self._counting_collector())
        with mock.patch.dict(os.environ, {"DYNAMICSTATE_REMOTE_IMAGE_MAX_BYTES": "4096"}):
            rem = self._inspect(remote, proc.pid, "proc_thread_circular_deadlock")
        for t in rem["threads"]:
            self.assertNotEqual(t["unwind_status"], "COMPLETE")
            self.assertTrue(any(f["estimated"] for f in t["callstack"]))
        rmi.clear_cache()

    def test_d_deadlock_recipe_through_remote_names_the_same_locks_and_threads(self):
        proc = self._spawn("proc_thread_circular_deadlock", min_threads=3)
        loc = self._inspect(LocalTargetAdapter(), proc.pid, "proc_thread_circular_deadlock")
        remote = self._adapter(self._counting_collector())
        rem = self._inspect(remote, proc.pid, "proc_thread_circular_deadlock")
        self.assertTrue(loc["deadlock_detected"])
        self.assertTrue(rem["deadlock_detected"])

        def cycle(r):
            return sorted((e["waiter_tid"], e["lock_name"], e["owner_tid"]) for e in r["deadlock_cycle"])
        self.assertEqual(cycle(loc), cycle(rem))
        self.assertEqual({e["lock_name"] for e in rem["deadlock_cycle"]}, {"g_mutex_a", "g_mutex_b"})
        self.assertEqual(sorted((l["name"], l["owner_tid"], sorted(l["waiting_tids"])) for l in loc["locks"]),
                         sorted((l["name"], l["owner_tid"], sorted(l["waiting_tids"])) for l in rem["locks"]))
        self.assertEqual({t["tid"]: (t.get("syscall_name"), (t.get("waiting_on_lock") or {}).get("lock_name"))
                          for t in loc["threads"]},
                         {t["tid"]: (t.get("syscall_name"), (t.get("waiting_on_lock") or {}).get("lock_name"))
                          for t in rem["threads"]})

    # =========================================================================================
    # (e) cost: O(samples), one collector process
    # =========================================================================================
    def test_e_five_samples_of_a_16_thread_process_cost_five_exchanges_and_one_collector(self):
        proc = self._spawn("proc_imp011_many_threads", "16")
        remote = self._adapter(self._counting_collector())
        t0 = time.monotonic()
        recs = [remote.read_thread_samples(proc.pid) for _ in range(5)]
        wall = time.monotonic() - t0
        self.assertTrue(all(r is not None and len(r) == 18 for r in recs), [len(r or []) for r in recs])  # 16+weird+main
        self.assertEqual(remote.daemon_stats["requests"], 5)       # one exchange per sample, not per thread
        self.assertEqual(remote.daemon_stats["opens"], 1)
        self.assertEqual(self.runner_calls, [], "no per-call ssh command at all")
        self.assertEqual(len(self._spawned()), 1, "exactly one collector process")
        print(f"\n[IMP-011 cost] daemon: 5 samples of 18 threads in {wall * 1000:.1f} ms, 5 exchanges, 1 collector")
        pids = self._spawned()
        remote.close()
        self.assertFalse(pid_alive(pids[0]))

    def test_e_per_call_collector_costs_one_command_per_sample(self):
        proc = self._spawn("proc_imp011_many_threads", "16")
        remote = self._adapter(self._counting_collector(), use_daemon=False)
        t0 = time.monotonic()
        for _ in range(5):
            self.assertEqual(len(remote.read_thread_samples(proc.pid)), 18)
        wall = time.monotonic() - t0
        self.assertEqual(len(self.runner_calls), 5)
        self.assertEqual(len(self._spawned()), 5)
        print(f"\n[IMP-011 cost] per-call: 5 samples in {wall * 1000:.1f} ms, 5 commands, 5 collector runs")

    def test_f_no_collector_fallback_is_one_batched_command_per_sample_with_the_same_fields(self):
        proc = self._spawn("proc_imp011_many_threads", "16")
        with_coll = self._adapter(self._counting_collector())
        bare = self._adapter(None)
        ref = with_coll.get_threads(proc.pid)
        n_before = len(self.runner_calls)      # get_threads(collector) uses the daemon + one maps command
        t0 = time.monotonic()
        recs = [bare.read_thread_samples(proc.pid) for _ in range(5)]
        wall = time.monotonic() - t0
        self.assertEqual(len(self.runner_calls) - n_before, 5, "one command per sample, never per thread/file")
        self.assertEqual(bare.last_threads_transport, "shell")
        script = self.runner_calls[-1]
        self.assertNotIn("[[", script)
        self.assertIn("@@END", script)
        print(f"\n[IMP-011 cost] no-collector: 5 samples in {wall * 1000:.1f} ms, 5 commands")
        got = bare.get_threads(proc.pid)
        self.assertEqual([t["tid"] for t in got], [t["tid"] for t in ref])
        for a, b in zip(ref, got):
            self.assertEqual(set(a), set(b))
            self.assertEqual(a["name"], b["name"])
            self.assertEqual(a["state"], b["state"])
            self.assertEqual(a["syscall"].get("nr"), b["syscall"].get("nr"))
            self.assertEqual(a["syscall"].get("sp"), b["syscall"].get("sp"))
            self.assertEqual(a["syscall"].get("pc"), b["syscall"].get("pc"))
            self.assertEqual(a["stack_info"], b["stack_info"])
        by_name = {r["name"]: r for r in recs[0]}
        self.assertIn(WEIRD, by_name)
        self.assertEqual(set(recs[0][0]) - {"schedstat"}, {"tid", "name", "state", "utime_ticks", "stime_ticks",
                                                           "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches",
                                                           "io_syscalls", "syscall"})
        s, j = self._collect_and_judge(bare, proc.pid, self._binary("proc_imp011_many_threads"))
        self.assertEqual(j["thread_sampling"]["status"], "OK")

    def test_f_old_collector_without_threads_command_falls_back_to_shell(self):
        proc = self._spawn("proc_imp011_many_threads", "3")
        old = self._script("oldcoll", (
            'if [ "$1" = "--daemon" ]; then while read l; do case "$l" in PING*) echo \'{"success":true,"status":"PONG"}\';; '
            'QUIT*) echo \'{"success":true,"status":"BYE"}\'; exit 0;; *) echo \'{"success":false,"error":"UNKNOWN_COMMAND"}\';; esac; done; fi\n'
            "exit 2\n"))
        remote = self._adapter(old)
        threads = remote.get_threads(proc.pid)
        self.assertEqual(remote.last_threads_transport, "shell")
        self.assertEqual(len(threads), 5)                    # main + 3 + weird
        self.assertEqual(remote._threads_unsupported_for, old)
        n = len(self.runner_calls)
        remote.read_thread_samples(proc.pid)
        self.assertEqual(len(self.runner_calls) - n, 1, "no re-probing of the unsupported collector")

    # =========================================================================================
    # (g) vanishing threads, hostile comm, paging
    # =========================================================================================
    def test_g_threads_exiting_during_enumeration_do_not_fail_the_call(self):
        proc = self._spawn("proc_imp011_many_threads", "8", "x")
        for label, kw, coll in (("daemon", {}, True), ("per-call", {"use_daemon": False}, True), ("shell", {}, False)):
            with self.subTest(transport=label):
                remote = self._adapter(self._counting_collector() if coll else None, **kw)
                seen = set()
                for _ in range(40):
                    recs = remote.read_thread_samples(proc.pid)
                    self.assertIsNotNone(recs)
                    names = [r["name"] for r in recs]
                    seen.add(len(names))
                    for r in recs:
                        self.assertIn(r["state"], "RSDTtZXxKWP")
                    self.assertEqual(sum(1 for n in names if len(n) == 3 and n[0] == "w" and n[1:].isdigit()), 8)
                    self.assertIn(WEIRD, names)
                self.assertGreaterEqual(len(seen), 1)

    def test_g_comm_with_spaces_and_parentheses_parses_in_every_transport(self):
        proc = self._spawn("proc_imp011_many_threads", "2")
        local = {t["tid"]: t["name"] for t in LocalTargetAdapter().get_threads(proc.pid)}
        self.assertIn(WEIRD, local.values())
        for label, kw, coll in (("daemon", {}, True), ("per-call", {"use_daemon": False}, True), ("shell", {}, False)):
            with self.subTest(transport=label):
                remote = self._adapter(self._counting_collector() if coll else None, **kw)
                got = {t["tid"]: t["name"] for t in remote.get_threads(proc.pid)}
                self.assertEqual(got, local)
                samples = {r["tid"]: r["name"] for r in remote.read_thread_samples(proc.pid)}
                self.assertEqual(samples, local)
                weird = next(t for t in remote.get_threads(proc.pid) if t["name"] == WEIRD)
                self.assertEqual(weird["state"], "S")
                self.assertGreaterEqual(weird["utime_ticks"], 0)

    def test_g_more_threads_than_one_reply_page_are_paged(self):
        proc = self._spawn("proc_imp011_many_threads", "200")
        local_tids = sorted(t["tid"] for t in LocalTargetAdapter().get_threads(proc.pid))
        self.assertEqual(len(local_tids), 202)
        remote = self._adapter(self._counting_collector())
        recs = remote.read_thread_samples(proc.pid)
        self.assertEqual([r["tid"] for r in recs], local_tids)
        self.assertEqual(remote.daemon_stats["requests"], 1)         # one logical request ...
        self.assertEqual(len(self._spawned()), 1)
        per_call = self._adapter(self._counting_collector(), use_daemon=False)
        self.assertEqual([r["tid"] for r in per_call.read_thread_samples(proc.pid)], local_tids)
        self.assertEqual(len(self.runner_calls), 2)                  # ... 2 pages (128 + 74) for the per-call path
        # every reply line is bounded
        out = subprocess.run([self.real, "-p", str(proc.pid), "--threads"], capture_output=True, text=True).stdout
        self.assertLess(len(out), 128 * 700)
        self.assertEqual(json.loads(out)["more"], True)

    def test_unsupported_architecture_keeps_the_explicit_unsupported_status(self):
        # gating is unchanged: for a 32-bit ARM target the CFI feature is not supported and no unwinder is built
        from extractor.target_abi import TargetABI, FEATURE_CFI_UNWIND, check_support
        abi = TargetABI(architecture="arm", word_size=32, endianness="little")
        self.assertFalse(check_support(abi, FEATURE_CFI_UNWIND).supported)


if __name__ == "__main__":
    unittest.main()
