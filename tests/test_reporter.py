import datetime
import os
import tempfile
import unittest
from unittest.mock import patch

from modules.reporter import generate_markdown_report, escape_markdown


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
            result = generate_markdown_report(results, output_path)
            self.assertTrue(result)

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

    def test_ioc_type_display(self):
        report = self.generate_report([
            {
                "ioc": "2001:4860:4860::8888",
                "status": "Success",
                "ioc_type": "ip_address",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 50
            },
            {
                "ioc": "a" * 40,
                "status": "Success",
                "ioc_type": "sha1",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 50
            },
            {
                "ioc": "b" * 64,
                "status": "Success",
                "ioc_type": "sha256",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 50
            }
        ])

        self.assertIn("| ip_address |", report)
        self.assertIn("| sha1 |", report)
        self.assertIn("| sha256 |", report)

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

    @patch("builtins.print")
    @patch("builtins.open", side_effect=PermissionError("Access denied"))
    def test_report_permission_error(self, mock_open, mock_print):
        result = generate_markdown_report([], "protected_report.md")

        self.assertFalse(result)
        mock_print.assert_called_once_with(
            "[!] Error: Permission denied when writing report 'protected_report.md'."
        )

    @patch("builtins.print")
    @patch("builtins.open", side_effect=OSError("Disk error"))
    def test_report_os_error(self, mock_open, mock_print):
        result = generate_markdown_report([], "report.md")

        self.assertFalse(result)
        mock_print.assert_called_once_with(
            "[!] Error writing report: Disk error"
        )

    def test_escape_markdown(self):
        value = "test|value`code`\nnext\\line"

        result = escape_markdown(value)

        self.assertEqual(
            result,
            "test\\|value\\`code\\` next\\\\line"
        )


if __name__ == "__main__":
    unittest.main()
