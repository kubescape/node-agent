import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("storage-tag.sh").resolve()


class StorageTagTest(unittest.TestCase):
    def resolve(self, floor, latest="v0.0.350", chart="v0.0.349"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = {
                "go": 'printf "%s\\n" "$TEST_STORAGE_FLOOR"',
                "git": 'printf "hash\\trefs/tags/%s\\n" "$TEST_STORAGE_LATEST"',
                "curl": 'touch values.yaml',
                "yq": 'printf "%s\\n" "$TEST_STORAGE_CHART"',
            }
            for name, body in commands.items():
                executable = root / name
                executable.write_text("#!/bin/sh\n" + body + "\n")
                executable.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       TEST_STORAGE_FLOOR=floor, TEST_STORAGE_LATEST=latest,
                       TEST_STORAGE_CHART=chart)
            return subprocess.run(["bash", str(SCRIPT)], cwd=root, env=env,
                                  capture_output=True, text=True)

    def test_pseudo_version_is_not_a_registry_tag(self):
        result = self.resolve("v0.0.353-0.20261015161907-5b4dacf1bc8a")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("requires a source-built image", result.stderr)

    def test_release_floor_can_be_newest(self):
        result = self.resolve("v0.0.352")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "v0.0.352")

    def test_latest_release_can_be_newest(self):
        result = self.resolve("v0.0.348")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "v0.0.350")

    def test_chart_release_can_be_newest(self):
        result = self.resolve("v0.0.348", chart="v0.0.351")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "v0.0.351")


if __name__ == "__main__":
    unittest.main()
