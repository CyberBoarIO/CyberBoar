# Check that the docs trigger passes on nothing but its secret's url and
# form-string lines

from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "trigger-docs.sh"

HOST = "docs-build.private.example"
PATH = "/hooks/7f3a9c/start"
URL = f"https://{HOST}{PATH}"
TOKEN = "s3cret-Token_value.42"
SECRET = f'''url = "{URL}"
form-string = "auth={TOKEN}"
form-string = "branch=main"
'''
PRIVATE = (URL, HOST, PATH, "7f3a9c", TOKEN, "auth=", "branch=")

# curl as a stub: logs its arguments and the config it read, prints a status
# and, like a real error, names the host on stderr
STUB = r'''
import json
import os
from pathlib import Path
import sys

config = sys.stdin.read()
with Path(os.environ["FAKE_CALLS"]).open("a") as log:
    log.write(json.dumps({"args": sys.argv[1:], "config": config}) + "\n")
print("curl: (7) Failed to connect to " + os.environ["FAKE_HOST"], file=sys.stderr)
sys.stdout.write(os.environ.get("FAKE_CODE", "201"))
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires POSIX command stubs and Bash")
class TriggerDocsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.calls = self.root / "calls.jsonl"
        curl = self.root / "curl"
        curl.write_text(f"#!{sys.executable}\n" + STUB)
        curl.chmod(0o755)
        self.env = {
            "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
            "FAKE_CALLS": str(self.calls),
            "FAKE_HOST": HOST,
            "DOCS_TRIGGER": SECRET,
        }

    def run_script(self, **env):
        return subprocess.run(["bash", str(SCRIPT)], env=dict(self.env, **env), capture_output=True, text=True)

    def curl_calls(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def assert_quiet(self, result, masked=False):
        out = result.stdout + result.stderr
        if masked:
            # Actions consumes these lines and never shows them
            out = "\n".join(line for line in out.splitlines() if not line.startswith("::add-mask::"))
        for private in PRIVATE:
            self.assertNotIn(private, out)

    def test_sends_the_secret_as_it_is(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_quiet(result)
        (call,) = self.curl_calls()
        self.assertNotIn(TOKEN, " ".join(call["args"]), "the token is in the process list")
        self.assertIn("--proto", call["args"])
        self.assertEqual(call["config"], SECRET)

    def test_windows_line_endings_and_blank_lines(self):
        result = self.run_script(DOCS_TRIGGER="\r\n" + SECRET.replace("\n", "\r\n\r\n").rstrip())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.curl_calls()[0]["config"], SECRET)

    def test_secret_parts_are_masked_in_actions(self):
        result = self.run_script(GITHUB_ACTIONS="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        masks = {line[len("::add-mask::"):] for line in result.stdout.splitlines() if line.startswith("::add-mask::")}
        self.assertEqual(masks, {HOST, PATH, f"auth={TOKEN}", TOKEN, "branch=main"})
        self.assert_quiet(result, masked=True)

    def test_failures_name_nothing_private(self):
        for env in ({"FAKE_CODE": "404"}, {"FAKE_CODE": "000", "FAKE_EXIT": "7"}):
            with self.subTest(env=env):
                result = self.run_script(**env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("wasn't started", result.stderr)
                self.assert_quiet(result)

    def test_a_secret_with_anything_else_sends_nothing(self):
        for secret in (
            SECRET + 'upload-file = "/etc/passwd"\n',         # another curl option
            SECRET + 'proxy = "https://elsewhere.example"\n',
            SECRET.replace("https://", "http://"),
            SECRET + 'url = "https://elsewhere.example/"\n',   # a second url
            SECRET.replace(f'"auth={TOKEN}"', f'"auth={TOKEN}" "x"'),
            SECRET.replace(f'auth={TOKEN}', f'auth={TOKEN}\\'),
            SECRET.replace(f'"auth={TOKEN}"', '"nameless"'),
            SECRET.replace(f'"auth={TOKEN}"', f'"={TOKEN}"'),
            f'url = "{URL}"\n',                                # no form-string
            "",
        ):
            with self.subTest(secret=secret[-40:]):
                result = self.run_script(DOCS_TRIGGER=secret)
                self.assertNotEqual(result.returncode, 0)
                self.assert_quiet(result)
        self.assertEqual(self.curl_calls(), [])


if __name__ == "__main__":
    unittest.main()
