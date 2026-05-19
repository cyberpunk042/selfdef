"""Adversary tests for MS042 declaration-vs-observed mismatch scenarios.

Each scenario constructs a synthetic Tetragon event line representing a
declaration violation (declared read-only / observed write, declared
no-network / observed socket, declared no-secrets / observed keyring
access, etc.) and verifies the guardian-core event parser flags it
correctly.

These are L1 unit tests against the parser only — full L4 integration
through the UNIX socket lives in tests/replay/ once the daemon ships.

Per MS042 E0429-E0430 dump 17422-17445 + operator standing direction
"you cannot invent crap" — every scenario maps to a documented
declaration field.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
GUARDIAN_PATH = REPO_ROOT / "scripts" / "guardian" / "guardian-core"


def _import_guardian():
    loader = SourceFileLoader("guardian_core_adv", str(GUARDIAN_PATH))
    spec = importlib.util.spec_from_loader("guardian_core_adv", loader)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AdversaryMismatchScenarios(unittest.TestCase):
    """Each test mirrors a documented MS042 declaration field."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _import_guardian()

    # --- field 1: read_paths ---
    def test_declared_ro_observed_write_triggers_response(self):
        # Declared read-only; observed sys_write — major severity per MS042
        event = json.dumps({
            "action": "SIGKILL",
            "process": {"docker": "ctr-abc", "binary": "/opt/tool/scraper"},
            "syscall": {"name": "sys_write"},
            "declared_field": "read_paths",
        })
        ok, ev = self.mod.parse_event(event)
        self.assertTrue(ok)
        self.assertEqual(ev["container_id"], "ctr-abc")
        self.assertEqual(ev["violated_syscall"], "sys_write")

    # --- field 2: write_paths ---
    def test_declared_write_scope_overflow_triggers_response(self):
        # Declared writes to /scratch/**; observed write to /etc/passwd
        event = json.dumps({
            "action": "SIGKILL",
            "process": {"docker": "ctr-bcd", "binary": "/opt/build/cargo"},
            "syscall": {"name": "sys_openat"},
            "declared_field": "write_paths",
        })
        ok, ev = self.mod.parse_event(event)
        self.assertTrue(ok)
        self.assertEqual(ev["violated_syscall"], "sys_openat")

    # --- field 3: network_domains ---
    def test_declared_no_network_observed_socket(self):
        # Declared network_domains: []; observed socket() syscall — critical
        event = json.dumps({
            "action": "SIGKILL",
            "process": {"docker": "ctr-cde", "binary": "/opt/payload"},
            "syscall": {"name": "sys_socket"},
            "declared_field": "network_domains",
        })
        ok, ev = self.mod.parse_event(event)
        self.assertTrue(ok)
        self.assertEqual(ev["violated_syscall"], "sys_socket")

    # --- field 4: env_vars ---
    def test_declared_no_env_observed_environ_read(self):
        event = json.dumps({
            "action": "SIGKILL",
            "process": {"docker": "ctr-def", "binary": "/opt/spy"},
            "syscall": {"name": "sys_openat"},
            "declared_field": "env_vars",
        })
        ok, ev = self.mod.parse_event(event)
        self.assertTrue(ok)

    # --- field 5: secret_access ---
    def test_declared_no_secrets_observed_keyring(self):
        # Critical severity — declared no-secrets; observed keyring read
        event = json.dumps({
            "action": "SIGKILL",
            "process": {"docker": "ctr-efg", "binary": "/opt/exfil"},
            "syscall": {"name": "sys_keyctl"},
            "declared_field": "secret_access",
        })
        ok, ev = self.mod.parse_event(event)
        self.assertTrue(ok)
        self.assertEqual(ev["violated_syscall"], "sys_keyctl")

    # --- field 6: side_effects ---
    def test_declared_no_exec_observed_execve(self):
        event = json.dumps({
            "action": "SIGKILL",
            "process": {"docker": "ctr-fgh", "binary": "/opt/runner"},
            "syscall": {"name": "sys_execve"},
            "declared_field": "side_effects",
        })
        ok, ev = self.mod.parse_event(event)
        self.assertTrue(ok)
        self.assertEqual(ev["violated_syscall"], "sys_execve")

    # --- field 7: rollback ---
    def test_declared_rollback_atomic_observed_persistent_commit(self):
        # The "process" substring is the activator here per parse_event's filter
        event = json.dumps({
            "action": "process-persistent-commit-detected",
            "process": {"docker": "ctr-ghi", "binary": "/opt/persist"},
            "syscall": {"name": "sys_sync"},
            "declared_field": "rollback",
        })
        ok, ev = self.mod.parse_event(event)
        self.assertTrue(ok)
        self.assertEqual(ev["violated_syscall"], "sys_sync")


class AdversaryNonResponseScenarios(unittest.TestCase):
    """Events that should NOT trigger response — verify no false-positive."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _import_guardian()

    def test_observe_only_event_skipped(self):
        # action=LOG_ONLY without "process" keyword → skipped
        event = json.dumps({"action": "LOG_ONLY", "process": {"binary": "/bin/sh"}, "syscall": {"name": "sys_read"}})
        ok, _ = self.mod.parse_event(event)
        self.assertFalse(ok)

    def test_status_heartbeat_skipped(self):
        event = json.dumps({"action": "heartbeat", "ts": "2026-05-19T00:00:00Z"})
        ok, _ = self.mod.parse_event(event)
        self.assertFalse(ok)

    def test_completely_unrelated_message_skipped(self):
        event = json.dumps({"hello": "world"})
        ok, _ = self.mod.parse_event(event)
        self.assertFalse(ok)


class AdversaryCorruptInputScenarios(unittest.TestCase):
    """Per MS044 R10358 — corrupt JSON lines are skipped, not fatal."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _import_guardian()

    def test_truncated_json_skipped(self):
        ok, _ = self.mod.parse_event('{"action": "SIGKILL", "process":')
        self.assertFalse(ok)

    def test_binary_garbage_skipped(self):
        # Build the binary-garbage string at runtime to avoid lexer NUL rejection
        # of the literal in source. Tests parser robustness, not source encoding.
        garbage = bytes([0, 1, 2]).decode("latin-1") + "not-json" + chr(0xff)
        ok, _ = self.mod.parse_event(garbage)
        self.assertFalse(ok)

    def test_oversized_line_does_not_crash(self):
        # 64 KiB line filled with valid JSON — parser must not OOM or crash
        payload = {"action": "SIGKILL", "process": {"docker": "x" * 60_000, "binary": "/x"}, "syscall": {"name": "sys_x"}}
        line = json.dumps(payload)
        ok, ev = self.mod.parse_event(line)
        self.assertTrue(ok)
        self.assertEqual(ev["violated_syscall"], "sys_x")

    def test_weird_character_in_field_handled(self):
        # NUL byte construction at runtime to avoid lexer NUL rejection in source.
        line = '{"action": "SIGKILL", "process": {"binary": "' + chr(0) + '"}}'
        ok, _ = self.mod.parse_event(line)
        # Either successfully parses (with NUL char) or rejects — must not crash.
        # No assertion on ok specifically; just that no exception escapes.
        self.assertIn(ok, (True, False))


if __name__ == "__main__":
    unittest.main()
