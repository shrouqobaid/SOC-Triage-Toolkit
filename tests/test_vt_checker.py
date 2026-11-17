import unittest
from unittest.mock import patch, Mock

from modules import vt_checker


class TestCheckIOC(unittest.TestCase):

    @patch("modules.vt_checker.requests.get")
    def test_successful_ip_lookup(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 60
                    }
                }
            }
        }

        mock_get.return_value = mock_response

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "Success")
        self.assertEqual(result["malicious"], 3)
        self.assertEqual(result["suspicious"], 1)
        self.assertEqual(result["harmless"], 60)

        mock_get.assert_called_once()

    @patch("modules.vt_checker.requests.get")
    def test_rate_limit_429(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "60"}

        mock_get.return_value = mock_response

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "API Error")
        self.assertEqual(result["retry_after"], "60")

    @patch("modules.vt_checker.requests.get")
    def test_ioc_not_found_404(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_response = Mock()
        mock_response.status_code = 404

        mock_get.return_value = mock_response

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "Not Found")
        self.assertEqual(
            result["message"],
            "IOC not found in VirusTotal database."
        )

    @patch("modules.vt_checker.requests.get")
    def test_request_timeout(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_get.side_effect = vt_checker.requests.exceptions.Timeout

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "Error")
        self.assertEqual(
            result["message"],
            "Request timed out while contacting VirusTotal."
        )

    @patch("modules.vt_checker.requests.get")
    def test_invalid_json_response(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")

        mock_get.return_value = mock_response

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "Error")
        self.assertEqual(
            result["message"],
            "Invalid JSON response from VirusTotal."
        )


    @patch("modules.vt_checker.requests.get")
    def test_connection_error(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_get.side_effect = vt_checker.requests.exceptions.ConnectionError

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "Error")
        self.assertEqual(result["message"], "Network connection error.")

    @patch("modules.vt_checker.requests.get")
    def test_missing_attributes(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {}
        }

        mock_get.return_value = mock_response

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "Error")
        self.assertEqual(
            result["message"],
            "Missing or invalid attributes."
        )


    @patch("modules.vt_checker.requests.get")
    def test_missing_analysis_stats(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {}
            }
        }

        mock_get.return_value = mock_response

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "Error")
        self.assertEqual(
            result["message"],
            "Missing or invalid analysis statistics."
        )



    @patch("modules.vt_checker.requests.get")
    def test_invalid_analysis_stats_value(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": "3",
                        "suspicious": 1,
                        "harmless": 60
                    }
                }
            }
        }

        mock_get.return_value = mock_response

        result = vt_checker.check_ioc("8.8.8.8")

        self.assertEqual(result["status"], "Error")


if __name__ == "__main__":
    unittest.main()

