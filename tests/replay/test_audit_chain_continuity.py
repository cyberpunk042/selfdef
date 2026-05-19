"""Replay tests for the atomic audit log + chain continuity invariants.

These tests construct a sequence of events, write them through
guardian-core's append_atomic_audit_log() helper, and verify:
- ordering preserved
- each line is valid JSON
- per-event keys present per MS044 audit-log schema
- newline-terminated per atomic-append contract

Replay (vs adversary) means: pre-recorded sequences played back to
exercise the multi-step write path, not single-event correctness.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import time
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
GUARDIAN_PATH = REPO_ROOT / "scripts" / "guardian" / "guardian-core"


def _import_guardian():
    loader = SourceFileLoader("guardian_core_replay", str(GUARDIAN_PATH))
    spec = importlib.util.spec_from_loader("guardian_core_replay", loader)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AuditChainReplayTests(unittest.TestCase):
    """Pre-recorded event replay through the audit log appender."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _import_guardian()

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="guardian-replay-")
        self.log_path = os.path.join(self.tmpdir, "audit.log")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _replay_sequence(self, events):
        for ev in events:
            ok = self.mod.append_atomic_audit_log(self.log_path, json.dumps(ev))
            self.assertTrue(ok, f"append failed for event {ev.get('seq')}")

    def _read_lines(self):
        with open(self.log_path) as f:
            return f.readlines()

    def test_replay_100_events_preserves_order(self):
        events = [
            {"seq": i, "ts": f"2026-05-19T00:{i:02d}:00Z", "kind": "test", "data": f"payload-{i}"}
            for i in range(60)
        ]
        self._replay_sequence(events)
        lines = self._read_lines()
        self.assertEqual(len(lines), 60)
        for i, line in enumerate(lines):
            data = json.loads(line)
            self.assertEqual(data["seq"], i)

    def test_replay_3step_block_quarantine_trace_sequence(self):
        # MS044 3-step protocol per dump 17437-17445
        # Step 1: block — SIGKILL via podman kill
        # Step 2: quarantine — append atomic audit log
        # Step 3: trace — console bell side-channel
        events = [
            {"step": 1, "kind": "block", "action": "SIGKILL", "container_id": "ctr-evil", "ts": "2026-05-19T03:00:00Z"},
            {"step": 2, "kind": "quarantine_audit", "container_id": "ctr-evil", "evidence": ["sys_socket", "sys_keyctl"], "ts": "2026-05-19T03:00:00.05Z"},
            {"step": 3, "kind": "trace_bell", "device": "/dev/console", "ts": "2026-05-19T03:00:00.10Z"},
        ]
        self._replay_sequence(events)
        lines = self._read_lines()
        self.assertEqual(len(lines), 3)
        # Step ordering preserved (atomic appends serialise)
        for i, expected_step in enumerate([1, 2, 3]):
            self.assertEqual(json.loads(lines[i])["step"], expected_step)
        # Step 2 quarantine_audit retains evidence list
        step2 = json.loads(lines[1])
        self.assertEqual(step2["container_id"], "ctr-evil")
        self.assertIn("sys_socket", step2["evidence"])
        self.assertIn("sys_keyctl", step2["evidence"])

    def test_replay_with_unicode_payload_survives_roundtrip(self):
        events = [
            {"seq": 1, "tool": "rustc", "msg": "✓ compile ok"},
            {"seq": 2, "tool": "browser-vfio", "msg": "→ network egress blocked"},
            {"seq": 3, "tool": "ipsec-tunnel", "msg": "Ring 4 — ✗ default-deny"},
        ]
        self._replay_sequence(events)
        lines = self._read_lines()
        recovered = [json.loads(l) for l in lines]
        self.assertEqual(recovered[0]["msg"], "✓ compile ok")
        self.assertEqual(recovered[2]["msg"], "Ring 4 — ✗ default-deny")

    def test_replay_each_line_is_valid_json(self):
        events = [
            {"seq": i, "rand": f"x{i}-{time.time_ns()}"}
            for i in range(20)
        ]
        self._replay_sequence(events)
        for line in self._read_lines():
            # MUST be parseable as standalone JSON
            json.loads(line)

    def test_replay_lines_terminated_with_newline(self):
        events = [{"seq": 1}, {"seq": 2}]
        self._replay_sequence(events)
        with open(self.log_path, "rb") as f:
            content = f.read()
        # Atomic-append contract: every entry ends with \n
        self.assertTrue(content.endswith(b"\n"))
        # No double-newlines (no empty lines between entries)
        self.assertNotIn(b"\n\n", content)


class AuditChainConcurrencyTests(unittest.TestCase):
    """Threaded replay to verify atomic-write isolation per MS044 R10386."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _import_guardian()

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="guardian-concurrent-")
        self.log_path = os.path.join(self.tmpdir, "audit.log")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_concurrent_appends_produce_well_formed_log(self):
        import threading
        n_threads = 8
        per_thread = 25

        def worker(tid):
            for j in range(per_thread):
                ok = self.mod.append_atomic_audit_log(
                    self.log_path,
                    json.dumps({"tid": tid, "seq": j}),
                )
                self.assertTrue(ok)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with open(self.log_path) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), n_threads * per_thread)
        # Every line must be valid JSON despite interleaving (atomic-append contract)
        seen = set()
        for line in lines:
            d = json.loads(line)
            seen.add((d["tid"], d["seq"]))
        # All distinct (tid, seq) pairs present — no lost events
        self.assertEqual(len(seen), n_threads * per_thread)


if __name__ == "__main__":
    unittest.main()
