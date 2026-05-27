"""Meta-tests for MS045 UX coherence test harness L1 checks.

Verifies the harness itself behaves correctly:
- detects all 9 MS007 SATURATED mirror crates
- runs JSON report cleanly with a valid schema
- exit-code reflects pass/fail correctly
- --layer filter narrows execution
- --name filter narrows to single check
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
HARNESS_PATH = REPO_ROOT / "scripts" / "ux-harness" / "selfdef-ux-harness"


def _import_harness():
    loader = SourceFileLoader("selfdef_ux_harness", str(HARNESS_PATH))
    spec = importlib.util.spec_from_loader("selfdef_ux_harness", loader)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class HarnessCanonicalReferenceTests(unittest.TestCase):
    """Verify the harness pins all 9 MS007 mirror crates verbatim."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _import_harness()

    def test_expected_mirror_crates_count_is_9(self):
        self.assertEqual(len(self.mod.EXPECTED_MIRROR_CRATES), 9)

    def test_expected_tui_panels_count_is_4(self):
        self.assertEqual(len(self.mod.EXPECTED_TUI_PANELS), 4)

    def test_cli_p95_target_is_50ms(self):
        self.assertEqual(self.mod.CLI_STARTUP_P95_TARGET_MS, 50.0)

    def test_wcag_aa_threshold_is_4_5(self):
        self.assertEqual(self.mod.WCAG_AA_CONTRAST_MIN, 4.5)

    def test_doctrine_constants_match_selfdef_mirrors(self):
        self.assertEqual(self.mod.DOCTRINE_FULLSTACK_AT_THE_EDGES, "Fullstack at the edges")
        self.assertEqual(self.mod.DOCTRINE_NO_VANITY_GRAPHS, "A dashboard should not show vanity graphs")


class HarnessExecutionTests(unittest.TestCase):
    """Run the harness as a subprocess and verify behavior."""

    def _run(self, *args) -> tuple[int, str, str]:
        result = subprocess.run(
            [sys.executable, str(HARNESS_PATH), *args],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode, result.stdout, result.stderr

    def test_default_run_exits_zero(self):
        rc, _, _ = self._run()
        self.assertEqual(rc, 0)

    def test_json_output_is_valid_json(self):
        rc, stdout, _ = self._run("--json")
        self.assertEqual(rc, 0)
        data = json.loads(stdout)
        self.assertEqual(data["schema"], "selfdef-ux-harness/1.0.0")
        self.assertIn("counts", data)
        self.assertIn("results", data)
        self.assertGreaterEqual(data["counts"]["total"], 10)

    def test_layer_filter_narrows_results(self):
        rc, stdout, _ = self._run("--json", "--layer", "L1")
        self.assertEqual(rc, 0)
        data = json.loads(stdout)
        # All result layers must be L1
        for r in data["results"]:
            self.assertEqual(r["layer"], "L1")

    def test_name_filter_runs_single_check(self):
        rc, stdout, _ = self._run("--json", "--name", "mirror-crate-list")
        self.assertEqual(rc, 0)
        data = json.loads(stdout)
        self.assertEqual(data["counts"]["total"], 1)
        self.assertEqual(data["results"][0]["name"], "mirror-crate-list")

    def test_verbose_emits_per_check_stderr(self):
        rc, _, stderr = self._run("-v")
        self.assertEqual(rc, 0)
        # Verbose mode prints status lines to stderr per check
        self.assertIn("PASS", stderr)
        self.assertIn("L1", stderr)


class HarnessCheckTests(unittest.TestCase):
    """Direct invocation of individual check functions."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _import_harness()
        cls.repo_root = REPO_ROOT

    def test_mirror_crate_list_finds_all_9(self):
        ok, summary, detail = self.mod.check_mirror_crate_list(self.repo_root)
        self.assertTrue(ok, f"failed: {summary}")
        # The 9 MS043 mirrors (R10182-R10189) must all be present; later
        # milestones legitimately add more (e.g. the four-watchdog mirrors),
        # so assert the MS043 set is present, not an exact total count.
        self.assertEqual(len(detail.get("ms043", [])), 9)
        for crate in self.mod.EXPECTED_MIRROR_CRATES:
            self.assertIn(crate, detail.get("crates", []))

    def test_doctrine_preservation_passes(self):
        ok, _, _ = self.mod.check_doctrine_preservation(self.repo_root)
        self.assertTrue(ok)

    def test_tui_panel_schema_finds_4_panels(self):
        ok, _, detail = self.mod.check_tui_panel_schema(self.repo_root)
        self.assertTrue(ok)
        self.assertEqual(len(detail.get("panels", [])), 4)

    def test_minimal_web_panel_schema_active(self):
        ok, summary, _ = self.mod.check_minimal_web_panel_schema(self.repo_root)
        self.assertTrue(ok)
        # The check should be active now that selfdef-web is shipped
        self.assertNotIn("deferred", summary.lower())

    def test_guardian_unit_present(self):
        ok, _, _ = self.mod.check_guardian_unit_present(self.repo_root)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
