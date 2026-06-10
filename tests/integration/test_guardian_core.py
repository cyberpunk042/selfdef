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


class TestSupervisedReconnectLoop(unittest.TestCase):
    """Tetragon-socket-dropout gotcha (operator audit 2026-06-10).

    The guardian must ride out an absent or dropped event pipe in-process
    instead of exiting into systemd's start-limit. Before this fix, a
    socket gap >~5s (firewall/VLAN reconfig, Tetragon restart) permanently
    failed the unit — Ring 0 containment dead until manual reset-failed.
    """

    def setUp(self):
        import logging
        self.mod = _import_guardian()
        # main_loop/run_supervised assert a configured logger.
        self.mod._log = logging.getLogger("guardian-core-test")
        self.mod._shutdown_requested.clear()
        self.tmpdir = tempfile.mkdtemp(prefix="guardian-supervise-")
        self.audit_log = os.path.join(self.tmpdir, "audit.log")
        self.console = os.path.join(self.tmpdir, "console")  # plain file: bell is harmless

    def tearDown(self):
        import shutil
        self.mod._shutdown_requested.clear()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _shutdown_after(self, secs: float):
        import threading
        t = threading.Timer(secs, self.mod._shutdown_requested.set)
        t.daemon = True
        t.start()
        return t

    def test_missing_socket_waits_instead_of_dying(self):
        # Socket absent: run_supervised must WAIT (not return) until shutdown.
        import time
        self._shutdown_after(0.4)
        start = time.monotonic()
        rc = self.mod.run_supervised(
            os.path.join(self.tmpdir, "no-such-pipe"),
            self.audit_log,
            self.console,
            reconnect_delay_secs=0.05,
        )
        elapsed = time.monotonic() - start
        self.assertEqual(rc, self.mod.EXIT_OK)
        # It actually rode out the gap rather than exiting immediately.
        self.assertGreaterEqual(elapsed, 0.3)

    def test_eof_without_shutdown_is_source_lost_not_clean_exit(self):
        # A regular file EOFs immediately after its lines: with NO shutdown
        # requested, main_loop must report source-lost (writer closed the
        # pipe, e.g. a Tetragon restart) — the old exit-0 here let a routine
        # Tetragon restart end the guardian pass as a "clean shutdown".
        stream = os.path.join(self.tmpdir, "events")
        with open(stream, "w") as f:
            f.write('{"action": "noop"}\n{"action": "noop"}\n')
        rc = self.mod.main_loop(stream, self.audit_log, self.console)
        self.assertEqual(rc, self.mod._SOURCE_LOST)

    def test_supervised_reconnects_after_eof_until_shutdown(self):
        # End-to-end: the supervised loop re-opens after EOF (source lost)
        # and only exits on the signal-driven shutdown — never dies into the
        # restart cycle on its own.
        import time
        stream = os.path.join(self.tmpdir, "events")
        with open(stream, "w") as f:
            f.write('{"action": "noop"}\n')
        self._shutdown_after(0.4)
        start = time.monotonic()
        rc = self.mod.run_supervised(
            stream, self.audit_log, self.console, reconnect_delay_secs=0.05
        )
        elapsed = time.monotonic() - start
        self.assertEqual(rc, self.mod.EXIT_OK)
        # Survived multiple EOF→reopen cycles instead of returning at the first.
        self.assertGreaterEqual(elapsed, 0.3)

    def test_signal_shutdown_still_returns_exit_ok(self):
        # A pre-set shutdown returns EXIT_OK immediately — graceful-shutdown
        # semantics per MS044 R10545 are preserved by the supervised loop.
        self.mod._shutdown_requested.set()
        rc = self.mod.run_supervised(
            os.path.join(self.tmpdir, "no-such-pipe"),
            self.audit_log,
            self.console,
            reconnect_delay_secs=0.05,
        )
        self.assertEqual(rc, self.mod.EXIT_OK)


if __name__ == "__main__":
    unittest.main()
