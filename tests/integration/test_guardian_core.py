"""Integration tests for MS044 Guardian Daemon (`guardian-core`).

Validates the 3-step block + quarantine + trace protocol via direct
import of the script's helper functions. The full main loop binds a
UNIX socket and forks `podman kill`, both of which require a live
Tetragon producer; those L4-level integration paths live in
`tests/replay/` once the daemon ships.

Run: ``pytest -xvs tests/integration/test_guardian_core.py``
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


# Load guardian-core as an importable module (it has no .py extension).
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
GUARDIAN_PATH = REPO_ROOT / "scripts" / "guardian" / "guardian-core"


def _import_guardian():
    # Extensionless scripts need SourceFileLoader directly.
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("guardian_core", str(GUARDIAN_PATH))
    spec = importlib.util.spec_from_loader("guardian_core", loader)
    assert spec is not None and spec.loader is not None, f"failed to spec from {GUARDIAN_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDoctrinalPreservation(unittest.TestCase):
    """Per MS044 R10399 — verbatim quote preservation must self-check."""

    def test_module_loads_without_doctrinal_drift(self):
        # Importing the module exercises the _verify_doctrinal_preservation()
        # call at module top — should not raise.
        try:
            mod = _import_guardian()
        except SystemExit as e:
            self.fail(f"guardian-core failed self-check on import: exit={e.code}")
        self.assertTrue(hasattr(mod, "GUARDIAN_VERSION"))


class TestAtomicAuditLog(unittest.TestCase):
    """MS044 R10386 — atomic ZFS audit log append.

    The atomic-write contract: append must either land fully or not at all;
    partial writes are not visible to subsequent readers.
    """

    def setUp(self):
        self.mod = _import_guardian()
        self.tmpdir = tempfile.mkdtemp(prefix="guardian-audit-")
        self.audit_path = os.path.join(self.tmpdir, "security_audit.log")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_append_creates_log_if_missing(self):
        line = json.dumps({"event": "test", "ts": "2026-05-19T00:00:00Z"})
        ok = self.mod.append_atomic_audit_log(self.audit_path, line)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(self.audit_path))
        with open(self.audit_path) as f:
            content = f.read()
        self.assertIn("\"event\": \"test\"", content)
        self.assertTrue(content.endswith("\n"), "audit log entries must end with newline")

    def test_multiple_appends_preserve_order(self):
        for i in range(5):
            self.mod.append_atomic_audit_log(self.audit_path, json.dumps({"seq": i}))
        with open(self.audit_path) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 5)
        for i, line in enumerate(lines):
            data = json.loads(line)
            self.assertEqual(data["seq"], i)

    def test_append_handles_unwritable_path_gracefully(self):
        # Path under /proc/1 is unwritable for non-root; helper should return False, not raise.
        ok = self.mod.append_atomic_audit_log("/proc/1/forbidden-audit.log", "x")
        self.assertFalse(ok)


class TestEventParser(unittest.TestCase):
    """Tetragon event parser per MS044 R10363."""

    def setUp(self):
        self.mod = _import_guardian()

    def test_parse_valid_event_returns_dict(self):
        # parse_event recognises events with action=SIGKILL or containing "process"
        # per MS044 R10361-R10367.
        line = json.dumps({
            "action": "SIGKILL",
            "process": {"docker": "abc123", "binary": "/usr/bin/curl"},
            "syscall": {"name": "sys_connect"},
        })
        ok, ev = self.mod.parse_event(line)
        self.assertTrue(ok)
        self.assertEqual(ev["container_id"], "abc123")
        self.assertEqual(ev["process_name"], "/usr/bin/curl")
        self.assertEqual(ev["violated_syscall"], "sys_connect")

    def test_parse_event_action_filter_rejects_non_kill(self):
        # action with neither SIGKILL nor "process" should be skipped.
        line = json.dumps({"action": "LOG_ONLY", "process": {"binary": "/usr/bin/echo"}})
        ok, _ = self.mod.parse_event(line)
        self.assertFalse(ok)

    def test_parse_event_violated_syscall_defaults(self):
        # When syscall.name missing, defaults to sys_execve per MS044 R10367.
        line = json.dumps({"action": "SIGKILL", "process": {"binary": "/usr/bin/x"}})
        ok, ev = self.mod.parse_event(line)
        self.assertTrue(ok)
        self.assertEqual(ev["violated_syscall"], "sys_execve")

    def test_parse_malformed_json_returns_false(self):
        ok, ev = self.mod.parse_event("not json at all")
        self.assertFalse(ok)

    def test_parse_empty_line_returns_false(self):
        ok, _ = self.mod.parse_event("")
        self.assertFalse(ok)


class TestConsoleBell(unittest.TestCase):
    """MS044 console bell side-channel per R10396."""

    def setUp(self):
        self.mod = _import_guardian()

    def test_console_bell_disabled_default_is_false(self):
        # No /etc/selfdef/guardian/console-bell.toml present in test sandbox
        # → defaults to enabled (returns False meaning "not disabled").
        # Per MS044 R10399.
        self.assertFalse(self.mod.console_bell_disabled())

    def test_console_bell_disabled_respects_toml_toggle(self):
        # Patch BELL_TOGGLE_CONFIG to point at our temp file with enabled=false.
        tmpdir = tempfile.mkdtemp(prefix="bell-toml-")
        try:
            toml_path = os.path.join(tmpdir, "console-bell.toml")
            with open(toml_path, "w") as f:
                f.write("enabled = false\n")
            saved = self.mod.BELL_TOGGLE_CONFIG
            try:
                self.mod.BELL_TOGGLE_CONFIG = toml_path
                self.assertTrue(self.mod.console_bell_disabled())
            finally:
                self.mod.BELL_TOGGLE_CONFIG = saved
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_emit_console_bell_no_raise_on_missing_device(self):
        # Should not raise when the device path doesn't exist.
        try:
            self.mod.emit_console_bell("/dev/nonexistent-tty-for-test")
        except Exception as e:
            self.fail(f"emit_console_bell raised on missing device: {e}")


class TestCLI(unittest.TestCase):
    """argparse surface per MS044."""

    def setUp(self):
        self.mod = _import_guardian()

    def test_parse_args_defaults(self):
        args = self.mod.parse_args([])
        self.assertTrue(hasattr(args, "socket"))
        self.assertTrue(hasattr(args, "audit_log"))
        self.assertEqual(args.socket, self.mod.DEFAULT_SOCKET_PATH)
        self.assertEqual(args.audit_log, self.mod.DEFAULT_AUDIT_LOG_PATH)

    def test_parse_args_dry_run_flag(self):
        args = self.mod.parse_args(["--dry-run"])
        self.assertTrue(args.dry_run)

    def test_parse_args_socket_override(self):
        args = self.mod.parse_args(["--socket", "/tmp/test.sock"])
        self.assertEqual(args.socket, "/tmp/test.sock")

    def test_parse_args_help_exits_clean(self):
        with self.assertRaises(SystemExit) as cm:
            self.mod.parse_args(["--help"])
        # argparse uses exit code 0 for --help
        self.assertEqual(cm.exception.code, 0)


class TestProbeWrites(unittest.TestCase):
    """write_probe() helper used by the systemd readiness check."""

    def setUp(self):
        self.mod = _import_guardian()
        self.tmpdir = tempfile.mkdtemp(prefix="guardian-probe-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_probe_creates_file(self):
        path = os.path.join(self.tmpdir, "ready")
        self.mod.write_probe(path, "ready\n")
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            self.assertEqual(f.read(), "ready\n")


if __name__ == "__main__":
    unittest.main()
