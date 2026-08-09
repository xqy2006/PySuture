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


if __name__ == "__main__":
    unittest.main()
