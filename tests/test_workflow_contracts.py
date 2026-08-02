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


if __name__ == "__main__":
    unittest.main()
