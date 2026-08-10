import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DETERMINISM_SPEC = importlib.util.spec_from_file_location(
    "pysuture_frozen_lock_determinism",
    ROOT / "scripts" / "check_frozen_lock_determinism.py",
)
if DETERMINISM_SPEC is None or DETERMINISM_SPEC.loader is None:
    raise RuntimeError("could not load the frozen-lock determinism script")
DETERMINISM_MODULE = importlib.util.module_from_spec(DETERMINISM_SPEC)
DETERMINISM_SPEC.loader.exec_module(DETERMINISM_MODULE)
_normalize_map_line = DETERMINISM_MODULE._normalize_map_line
_normalize_map_line_bytes = DETERMINISM_MODULE._normalize_map_line_bytes


class WorkflowContractTests(unittest.TestCase):
    def test_staticpython_e2e_concurrency_is_scoped_to_the_candidate_ref(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sync-staticpython.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("group: sync-staticpython-${{ github.ref }}", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertNotIn("group: sync-staticpython\n", workflow)

    def test_staticpython_candidate_can_be_pinned_and_uses_actions_auth(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sync-staticpython.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("staticpython_commit:", workflow)
        self.assertIn("inputs.staticpython_commit", workflow)
        self.assertIn("GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}", workflow)
        self.assertIn("staticpython-runtime-{expected[:12]}", workflow)
        self.assertIn("if not re.fullmatch", workflow)
        self.assertIn("immutable verified index does not match", workflow)

    def test_staticpython_proposal_is_idempotent_and_fails_closed_on_branch_drift(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sync-staticpython.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("ref: master", workflow)
        self.assertIn("git diff --quiet -- runtime-catalog.lock.json", workflow)
        self.assertIn("$catalogDiffExit = $LASTEXITCODE", workflow)
        self.assertNotIn("git status --porcelain", workflow)
        self.assertIn('git ls-remote --heads origin "refs/heads/$branch"', workflow)
        self.assertIn('git diff --name-only "origin/master...FETCH_HEAD"', workflow)
        self.assertIn("contains changes outside runtime-catalog.lock.json", workflow)
        self.assertIn("does not contain this exact verified catalog", workflow)
        self.assertIn("Verified existing orphan update branch", workflow)
        self.assertIn("repository policy prevented Actions", workflow)
        self.assertIn("Create the draft PR manually", workflow)

        branch_audit = workflow.index('git ls-remote --heads origin "refs/heads/$branch"')
        branch_create = workflow.index("git checkout -b $branch")
        pr_create = workflow.index("$proposal = gh pr create")
        permission_fallback = workflow.index("if ($proposalExit -ne 0)")
        self.assertLess(branch_audit, branch_create)
        self.assertLess(branch_create, pr_create)
        self.assertLess(pr_create, permission_fallback)

    def test_windowed_e2e_runs_full_unicode_multiprocessing_smoke(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sync-staticpython.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "Windowed Unicode, resource, argv, and multiprocessing smoke",
            workflow,
        )
        self.assertIn('@("--self-test", "参数 空格", "路径-中文")', workflow)
        self.assertIn("$windowInfo.ArgumentList.Add($_)", workflow)
        self.assertEqual(workflow.count("Set-Location $work"), 2)
        self.assertIn("$windowInfo.WorkingDirectory = $work", workflow)
        self.assertNotIn('$exe -ArgumentList @("--quiet")', workflow)
    def test_staticpython_gate_rebuilds_one_frozen_lock_below_two_roots(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sync-staticpython.yml").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "scripts" / "check_frozen_lock_determinism.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("  determinism:\n", workflow)
        self.assertIn("check_frozen_lock_determinism.py", workflow)
        self.assertIn("needs: [candidate, e2e, determinism, ui-pack-e2e]", workflow)
        self.assertIn('first = work_root / "first-project"', script)
        self.assertIn('/ "nested"', script)
        self.assertIn("second-location-with-a-different-length", script)
        self.assertIn('"--frozen-lock"', script)
        self.assertIn('"--offline"', script)
        self.assertIn(
            'REQUIRED_IDENTICAL_ARTIFACTS = ("executable", "map_semantics")',
            script,
        )
        self.assertIn("_normalized_map_sha256", script)
        self.assertIn("frozen build mutated pysuture.lock", script)
        self.assertIn("_assert_reports_match", script)
        self.assertIn("distribution directory must contain only", script)
        self.assertIn("include-hidden-files: true", workflow)

    def test_map_normalization_only_ignores_members_within_one_archive(self) -> None:
        prefix = " 0002:00ecacd8       __real@bff0000000000000    00000001416e6cd8     "
        first = prefix + "python313:unicodectype.obj"
        second = prefix + "python313:floatobject.obj"

        self.assertEqual(_normalize_map_line(first), _normalize_map_line(second))
        self.assertNotEqual(
            _normalize_map_line(first),
            _normalize_map_line(prefix + "other:floatobject.obj"),
        )
        self.assertNotEqual(
            _normalize_map_line(prefix + "python313:main.obj"),
            _normalize_map_line(prefix + "python313:other.obj"),
        )
        self.assertNotEqual(
            _normalize_map_line(prefix + r"C:\first-root\launcher.obj"),
            _normalize_map_line(prefix + r"C:\second-root\launcher.obj"),
        )
        self.assertNotEqual(
            _normalize_map_line_bytes(b"unmatched byte: \x80"),
            _normalize_map_line_bytes(b"unmatched byte: \x81"),
        )

    def test_runtime_executables_run_inside_the_snapshotted_directory(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sync-staticpython.yml").read_text(
            encoding="utf-8"
        )

        self.assertGreaterEqual(workflow.count("Push-Location $work"), 1)
        self.assertEqual(workflow.count("Set-Location $work"), 2)
        self.assertIn("$windowInfo.WorkingDirectory = $work", workflow)

    def test_ui_gate_requires_virtual_wx_resources_and_strict_pe_evidence(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "sync-staticpython.yml").read_text(
            encoding="utf-8"
        )
        app = (ROOT / "examples" / "wx-fltk-smoke" / "app.py").read_text(
            encoding="utf-8"
        )

        self.assertIn('python: ["3.11", "3.12", "3.13", "3.14", "3.15"]', workflow)
        self.assertIn("trusted_object_origins", workflow)
        self.assertIn("allowed_trusted_object_records", workflow)
        self.assertIn("forbidden_main_object_records", workflow)
        self.assertIn("non_system_dependencies", workflow)
        self.assertIn("runtime created or extracted files", workflow)
        self.assertIn('wx.core.__file__ != "staticpython-resource:///Lib/wx/core.py"', app)
        self.assertIn("os.listdir(locale_dir)", app)


if __name__ == "__main__":
    unittest.main()
