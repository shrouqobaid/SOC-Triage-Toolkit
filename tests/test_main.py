import os
import sys
import tempfile
import unittest
from unittest.mock import patch
import main


class TestMain(unittest.TestCase):

    @patch("sys.argv", ["main.py", "-f", "nonexistent.txt"])
    @patch("builtins.print")
    @patch("main.generate_markdown_report")
    def test_missing_input_file(self, mock_report, mock_print):
        main.main()

        mock_report.assert_not_called()
        mock_print.assert_any_call(
    "[!] Error: File 'nonexistent.txt' not found."
)
    def test_empty_input_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False
        ) as temp_file:
            input_path = temp_file.name

        self.addCleanup(os.unlink, input_path)

        with patch("sys.argv", ["main.py", "-f", input_path]):
            with patch("builtins.print") as mock_print:
                with patch("main.generate_markdown_report") as mock_report:
                    main.main()

        mock_report.assert_not_called()
        mock_print.assert_any_call(
            "[!] Error: Input file is empty."
        )

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", side_effect=PermissionError)
    @patch("main.generate_markdown_report")
    @patch("builtins.print")
    @patch("sys.argv", ["main.py", "-f", "protected.txt"])
    def test_permission_denied(self, mock_print, mock_report, mock_open, mock_exists):
        main.main()

        mock_report.assert_not_called()
        mock_print.assert_any_call(
            "[!] Error: Permission denied when reading 'protected.txt'."
        )

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", side_effect=OSError("Disk error"))
    @patch("builtins.print")
    @patch("sys.argv", ["main.py", "-f", "iocs.txt"])
    def test_input_file_os_error(self, mock_print, mock_open, mock_exists):
        main.main()

        mock_print.assert_any_call(
            "[!] Error reading input file: Disk error"
        )

    def test_successful_triage(self):
        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False
        ) as temp_file:
            temp_file.write("8.8.8.8\n")
            input_path = temp_file.name

        self.addCleanup(os.unlink, input_path)

        expected_result = {
            "ioc": "8.8.8.8",
            "status": "Success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 10
        }

        with patch("sys.argv", ["main.py", "-f", input_path]):
            with patch("main.check_ioc", return_value=expected_result) as mock_check:
                with patch("main.generate_markdown_report") as mock_report:
                    with patch("builtins.print"):
                        main.main()

        mock_check.assert_called_once_with("8.8.8.8")
        mock_report.assert_called_once_with(
            [expected_result],
            "SOC_Triage_Report.md"
        )


if __name__ == "__main__":
    unittest.main()
