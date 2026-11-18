import datetime
import os
import tempfile
import unittest

from modules.reporter import generate_markdown_report


class TestExecutiveAssessment(unittest.TestCase):

    def generate_report(self, results):
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".md",
            delete=False,
            encoding="utf-8"
        ) as temp_file:
            output_path = temp_file.name

        try:
            generate_markdown_report(results, output_path)

            with open(output_path, "r", encoding="utf-8") as file:
                return file.read()

        finally:
            os.remove(output_path)

    def test_critical_assessment(self):
        report = self.generate_report([
            {
                "ioc": "1.1.1.1",
                "status": "Success",
                "malicious": 8,
                "suspicious": 0,
                "harmless": 50
            }
        ])

        self.assertIn("CRITICAL", report)

    def test_high_assessment(self):
        report = self.generate_report([
            {
                "ioc": "8.8.8.8",
                "status": "Success",
                "malicious": 1,
                "suspicious": 0,
                "harmless": 53
            }
        ])

        self.assertIn("HIGH", report)

    def test_medium_assessment(self):
        report = self.generate_report([
            {
                "ioc": "9.9.9.9",
                "status": "Success",
                "malicious": 0,
                "suspicious": 2,
                "harmless": 50
            }
        ])

        self.assertIn("MEDIUM", report)

    def test_all_scans_failed(self):
        report = self.generate_report([
            {"ioc": "invalid-1", "status": "Failed"},
            {"ioc": "invalid-2", "status": "Failed"}
        ])

        self.assertIn("UNABLE TO ASSESS", report)

    def test_clean_assessment(self):
        report = self.generate_report([
            {
                "ioc": "208.67.222.222",
                "status": "Success",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 55
            }
        ])

        self.assertIn("NO THREATS DETECTED", report)

    def test_mixed_successful_and_failed_scans(self):
        report = self.generate_report([
            {
                "ioc": "208.67.222.222",
                "status": "Success",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 55
            },
            {
                "ioc": "invalid-ioc",
                "status": "Failed"
            }
        ])

        self.assertIn("REVIEW REQUIRED", report)
        self.assertNotIn("NO THREATS DETECTED", report)


if __name__ == "__main__":
    unittest.main()
