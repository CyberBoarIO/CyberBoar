# Exercise branch-sync behavior with a local GitHub CLI stub, without network access

from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sync-experimental-branches.sh"

FAKE_GH = r'''
import json
import os
from pathlib import Path
import sys
from urllib.parse import unquote

args = sys.argv[1:]
assert args.pop(0) == "api", args
method = "GET"
fields = {}
endpoint = None
while args:
    arg = args.pop(0)
    if arg == "-X":
        method = args.pop(0)
    elif arg in ("-f", "-F"):
        key, value = args.pop(0).split("=", 1)
        fields[key] = value
    elif arg == "--jq":
        args.pop(0)
    elif arg == "--paginate":
        pass
    else:
        assert endpoint is None, arg
        endpoint = arg
assert endpoint.startswith("repos/CyberBoarIO/CyberBoar/")
endpoint = endpoint.removeprefix("repos/CyberBoarIO/CyberBoar/")
state_path = Path(os.environ["FAKE_GH_STATE"])
state = json.loads(state_path.read_text())
with Path(os.environ["FAKE_GH_CALLS"]).open("a") as log:
    log.write(json.dumps(dict(method=method, endpoint=endpoint, fields=fields)) + "\n")
if state.get("fail") == endpoint:
    print("simulated API failure", file=sys.stderr)
    sys.exit(1)
if method == "GET" and endpoint == "git/ref/heads/main":
    print(state.get("main_sha", "abc123"))
elif method == "GET" and endpoint == "git/matching-refs/heads/experimental/":
    print(json.dumps([dict(ref="refs/heads/" + branch) for branch in state["branches"]]))
elif method == "GET" and endpoint.startswith("compare/"):
    branch, sha = unquote(endpoint.removeprefix("compare/")).split("...")
    assert sha == state.get("main_sha", "abc123")
    print(state["branches"][branch]["missing"])
elif endpoint == "pulls":
    branch = fields["base"]
    info = state["branches"][branch]
    if method == "GET":
        assert fields["state"] == "open" and fields["head"] == "CyberBoarIO:main"
        print(info.get("pr", ""))
    else:
        assert method == "POST" and fields["head"] == "main"
        assert "pr" not in info, "duplicate pull request"
        info["pr"] = "https://github.com/CyberBoarIO/CyberBoar/pull/42"
        state_path.write_text(json.dumps(state))
        print(info["pr"])
else:
    raise AssertionError("unexpected API operation: " + method + " " + endpoint)
'''


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"), "requires bash and jq")
class SyncExperimentalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        gh = self.root / "gh"
        gh.write_text(f"#!{sys.executable}\n" + FAKE_GH)
        gh.chmod(0o755)
        self.state = self.root / "state.json"
        self.calls = self.root / "calls.jsonl"
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                        GH_TOKEN="offline-test", GITHUB_REPOSITORY="CyberBoarIO/CyberBoar",
                        FAKE_GH_STATE=str(self.state), FAKE_GH_CALLS=str(self.calls))

    def run_sync(self):
        return subprocess.run(["bash", str(SCRIPT)], env=self.env,
                              capture_output=True, text=True, check=False)

    def writes(self):
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return [call for call in calls if call["method"] != "GET"]

    def test_creates_prs_only_for_branches_missing_main_and_reuses_them(self):
        self.state.write_text(json.dumps({"branches": {
            "experimental/new-feature": {"missing": 3},
            "experimental/up-to-date": {"missing": 0},
            "experimental/existing": {"missing": 2, "pr": "existing-pr"},
        }}))
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        writes = self.writes()
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["endpoint"], "pulls")
        self.assertEqual(writes[0]["method"], "POST")
        self.assertEqual(writes[0]["fields"]["base"], "experimental/new-feature")
        self.assertEqual(writes[0]["fields"]["head"], "main")
        self.assertIn("merge commit", writes[0]["fields"]["body"])
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.writes(), writes, "reruns must not duplicate PRs")

    def test_no_experimental_branches_is_a_noop(self):
        self.state.write_text(json.dumps({"branches": {}}))
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.writes(), [])

    def test_branch_names_are_encoded_in_comparison_urls(self):
        self.state.write_text(json.dumps({"branches": {
            "experimental/nested/feature#1": {"missing": 1},
        }}))
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("experimental%2Fnested%2Ffeature%231", self.calls.read_text())
        self.assertEqual(self.writes()[0]["fields"]["base"], "experimental/nested/feature#1")

    def test_api_failures_and_invalid_comparisons_do_not_create_prs(self):
        cases = [
            {"fail": "git/matching-refs/heads/experimental/", "branches": {}},
            {"main_sha": "", "branches": {}},
            {"branches": {"experimental/broken": {"missing": "null"}}},
        ]
        for state in cases:
            with self.subTest(state=state):
                self.calls.write_text("")
                self.state.write_text(json.dumps(state))
                result = self.run_sync()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.writes(), [])


if __name__ == "__main__":
    unittest.main()
