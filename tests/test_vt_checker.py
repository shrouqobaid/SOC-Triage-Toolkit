import unittest
from unittest.mock import patch, Mock

from modules import vt_checker

class TestClassifyIOC(unittest.TestCase):

    def test_valid_ipv4(self):
        result = vt_checker.classify_ioc("8.8.8.8")
        self.assertEqual(result, "ip_address")

    def test_valid_ipv6(self):
        result = vt_checker.classify_ioc("2001:4860:4860::8888")
        self.assertEqual(result, "ip_address")

    def test_valid_md5(self):
        result = vt_checker.classify_ioc(
            "d41d8cd98f00b204e9800998ecf8427e"
        )
        self.assertEqual(result, "md5")

    def test_valid_sha1(self):
        result = vt_checker.classify_ioc(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )
        self.assertEqual(result, "sha1")


    def test_valid_sha256(self):
        result = vt_checker.classify_ioc(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        self.assertEqual(result, "sha256")

    def test_invalid_hash_characters(self):
        result = vt_checker.classify_ioc(
            "g" * 32
        )
        self.assertIsNone(result)

    def test_empty_ioc(self):
        result = vt_checker.classify_ioc("   ")
        self.assertIsNone(result)

    def test_invalid_ioc(self):
        result = vt_checker.classify_ioc("hello_world")
        self.assertIsNone(result)


    def test_non_string_ioc(self):
        result = vt_checker.classify_ioc(12345)
        self.assertIsNone(result)

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
    @patch("modules.vt_checker.requests.get")
    def test_invalid_ioc_does_not_call_api(self, mock_get):

        vt_decorator_key = vt_checker.VT_API_KEY
        vt_checker.VT_API_KEY = "test_api_key"

        result = vt_checker.check_ioc("invalid_ioc_123")

        self.assertEqual(result["status"], "Invalid IOC")
        mock_get.assert_not_called()


    @patch("modules.vt_checker.requests.get")
    def test_non_string_ioc_does_not_call_api(self, mock_get):

        vt_checker.VT_API_KEY = "test_api_key"

        result = vt_checker.check_ioc(12345)

        self.assertEqual(result["status"], "Invalid IOC")
        mock_get.assert_not_called()

    @patch("modules.vt_checker.requests.get")
    def test_missing_api_key(self, mock_get):
        original_key = vt_checker.VT_API_KEY

        try:
            vt_checker.VT_API_KEY = None

            result = vt_checker.check_ioc("8.8.8.8")

            self.assertEqual(result["status"], "Error")
            self.assertEqual(
                result["message"],
                "API Key is missing or not configured."
            )
            mock_get.assert_not_called()

        finally:
            vt_checker.VT_API_KEY = original_key

    @patch("modules.vt_checker.requests.get")
    def test_server_error_500(self, mock_get):
        original_key = vt_checker.VT_API_KEY

        try:
            vt_checker.VT_API_KEY = "test_api_key"

            mock_response = Mock()
            mock_response.status_code = 500
            mock_get.return_value = mock_response

            result = vt_checker.check_ioc("8.8.8.8")

            self.assertEqual(result["status"], "API Error")
            self.assertEqual(
                result["message"],
                "HTTP status code: 500"
            )

        finally:
            vt_checker.VT_API_KEY = original_key


if __name__ == "__main__":
    unittest.main()
