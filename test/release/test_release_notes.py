# Check release-note gates without tags, network access or publishing

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release-notes.sh"
BASH = os.environ.get("CYBERBOAR_TEST_BASH", "bash")


class ReleaseNotesTest(unittest.TestCase):
    def notes(self, text):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "scripts").mkdir()
            script = root / "scripts" / SCRIPT.name
            shutil.copyfile(SCRIPT, script)
            with (root / "CHANGELOG.md").open("w", encoding="utf-8", newline="\n") as changelog:
                changelog.write(text)
            return subprocess.run([BASH, script.as_posix(), "v1.0.0-rc.1"],
                                  text=True, capture_output=True, check=False)

    def test_valid_calendar_dates(self):
        for date in ("2026-10-12", "2024-02-29", "2000-02-29"):
            with self.subTest(date=date):
                result = self.notes(f"## [v1.0.0-rc.1] - {date}\n\nRelease notes.\n")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "Release notes.")

    def test_invalid_dates_and_ambiguous_sections(self):
        invalid = [f"## [v1.0.0-rc.1] - {date}\n\nRelease notes.\n"
                   for date in ("YYYY-MM-DD", "2026-13-01", "2026-04-31",
                                "2026-02-29", "1900-02-29", "0000-01-01")]
        invalid.extend([
            "## [v1.0.0-rc.1] - 2026-10-12\n\n",
            "## [v1.0.0] - 2026-10-12\n\nOther release.\n",
            "## [v1.0.0-rc.1] - 2026-10-12\n\nFirst.\n"
            "## [v1.0.0-rc.1] - 2026-10-13\n\nSecond.\n",
        ])
        for text in invalid:
            with self.subTest(text=text):
                result = self.notes(text)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
