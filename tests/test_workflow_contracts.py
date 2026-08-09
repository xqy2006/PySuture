from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


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


if __name__ == "__main__":
    unittest.main()
