"""Smoke tests -- confirm the project skeleton is present and wired up.

These run with the standard library alone (``python3 -m unittest``) and are also
discovered by pytest. Real ISO-TP / UDS / exploit tests arrive in later milestones.
"""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SkeletonSmokeTest(unittest.TestCase):
    def test_expected_files_exist(self):
        expected = [
            "CMakeLists.txt",
            "LICENSE",
            "ecu/CMakeLists.txt",
            "ecu/include/transport.h",
            "ecu/src/main.c",
            "toolkit/pyproject.toml",
            "toolkit/ecutk/__init__.py",
            "docker/setup-vcan.sh",
            ".github/workflows/ci.yml",
        ]
        for rel in expected:
            with self.subTest(path=rel):
                self.assertTrue(
                    os.path.exists(os.path.join(ROOT, rel)),
                    f"missing expected file: {rel}",
                )


if __name__ == "__main__":
    unittest.main()
