# Check native script failure handling with local command stubs

from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PWSH = shutil.which("pwsh")

STUB = r'''
import json
import os
from pathlib import Path
import sys

command = Path(sys.argv[0]).name
args = sys.argv[1:]
with Path(os.environ["FAKE_CALLS"]).open("a") as log:
    log.write(json.dumps([command, args, os.getcwd()]) + "\n")
if command == "go":
    if args == ["env", "GOOS"]:
        print(os.environ["FAKE_GOOS"])
    elif args == ["env", "GOARCH"]:
        print(os.environ["FAKE_GOARCH"])
    elif args[0] == os.environ.get("FAKE_GO_FAIL"):
        sys.exit(9)
    elif args[0] == "build" and "-o" in args:
        binary = Path(args[args.index("-o") + 1])
        binary.write_text(Path(__file__).read_text())
        binary.chmod(0o755)
        with Path(os.environ["FAKE_OUTPUTS"]).open("a") as outputs:
            outputs.write(str(binary) + "\n")
elif command.startswith("cyberboar"):
    if args[0] == os.environ.get("FAKE_BINARY_FAIL"):
        sys.exit(9)
elif command == "cygpath":
    print(args[-1])
else:
    assert command in ("python", "git.exe"), command
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires POSIX command stubs and Bash")
class PlatformScriptsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.calls = self.root / "calls.jsonl"
        self.outputs = self.root / "outputs.txt"
        for command in ("go", "cygpath", "python", "git.exe"):
            path = self.root / command
            path.write_text(f"#!{sys.executable}\n" + STUB)
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                        FAKE_CALLS=str(self.calls), FAKE_OUTPUTS=str(self.outputs))

    def run_script(self, script, goos, arch, *args, **env):
        self.calls.write_text("")
        self.outputs.write_text("")
        interpreter = [PWSH, "-NoProfile", "-File"] if script.endswith(".ps1") else ["bash"]
        result = subprocess.run(interpreter + [str(ROOT / "scripts" / script), *args],
                                cwd=self.root, env=dict(self.env, FAKE_GOOS=goos,
                                                       FAKE_GOARCH=arch, **env),
                                text=True, capture_output=True, check=False)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        outputs = self.outputs.read_text().splitlines()
        self.assertTrue(all(not Path(path).exists() for path in outputs), "temporary binary was left behind")
        return result, calls, outputs

    def test_supported_targets_run_binary_checks_and_tests(self):
        for goos, arch, script in [
            ("linux", "amd64", "platform-compatibility-linux.sh"),
            ("linux", "arm64", "platform-compatibility-linux.sh"),
            ("darwin", "amd64", "platform-compatibility-macos.sh"),
            ("darwin", "arm64", "platform-compatibility-macos.sh"),
            ("windows", "amd64", "platform-compatibility-windows-x64.sh"),
        ]:
            with self.subTest(goos=goos, arch=arch):
                args = (arch,) if goos != "windows" else ()
                result, calls, outputs = self.run_script(script, goos, arch, *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(outputs), 1)
                checks = [args for command, args, _ in calls if command.startswith("cyberboar")]
                self.assertEqual(checks, [["version"], ["check", "examples/baseline.yaml"]])
                self.assertTrue(any(command == "go" and args[0] == "test" for command, args, _ in calls))
                self.assertTrue(all(Path(cwd) == ROOT for _, _, cwd in calls))

    def test_wrong_targets_stop_before_building(self):
        for script, goos, arch, expected in [
            ("platform-compatibility-linux.sh", "darwin", "amd64", "amd64"),
            ("platform-compatibility-macos.sh", "darwin", "arm64", "amd64"),
            ("platform-compatibility-windows-x64.sh", "windows", "arm64", None),
        ]:
            with self.subTest(script=script):
                result, calls, outputs = self.run_script(script, goos, arch, *((expected,) if expected else ()))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outputs, [])
                self.assertTrue(all(args[0] == "env" for _, args, _ in calls))

    def test_build_and_binary_failures_stop_tests_and_clean_up(self):
        for failure in ({"FAKE_GO_FAIL": "build"}, {"FAKE_BINARY_FAIL": "version"},
                        {"FAKE_BINARY_FAIL": "check"}):
            with self.subTest(failure=failure):
                result, calls, _ = self.run_script("platform-compatibility-linux.sh", "linux", "amd64", **failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(command == "go" and args[0] == "test" for command, args, _ in calls))

    def test_quality_checks_reject_unknown_arguments_and_non_linux(self):
        for goos, args in [("linux", ("--unknown",)), ("darwin", ())]:
            with self.subTest(goos=goos):
                result, calls, _ = self.run_script("quality-checks.sh", goos, "amd64", *args)
                self.assertEqual(result.returncode, 2)
                self.assertTrue(all(args[0] == "env" for _, args, _ in calls))

    @unittest.skipUnless(PWSH, "requires PowerShell")
    def test_windows_arm64_propagates_failures_and_cleans_up(self):
        script = "platform-compatibility-windows-arm64.ps1"
        for failure in ({}, {"FAKE_GO_FAIL": "test"}, {"FAKE_BINARY_FAIL": "check"}):
            with self.subTest(failure=failure):
                result, calls, outputs = self.run_script(script, "windows", "arm64", **failure)
                if failure:
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(outputs), 1)
                if "FAKE_BINARY_FAIL" in failure:
                    self.assertFalse(any(command == "go" and args[0] == "test" for command, args, _ in calls))


if __name__ == "__main__":
    unittest.main()
