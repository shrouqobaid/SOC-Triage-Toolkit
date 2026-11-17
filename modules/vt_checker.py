import os
import ipaddress
import re
import requests
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def classify_ioc(ioc):
    """
    Identify and validate IOC type:
    IPv4, IPv6, MD5, SHA1, SHA256.
    """

    if not isinstance(ioc, str):
        return None

    ioc = ioc.strip()

    if not ioc:
        return None

    # Step 1: Validate IP addresses
    try:
        ipaddress.ip_address(ioc)
        return "ip_address"
    except ValueError:
        pass

    # Step 2: Validate file hashes
    hash_types = {
        32: "md5",
        40: "sha1",
        64: "sha256"
    }

    hash_type = hash_types.get(len(ioc))

    if hash_type and re.fullmatch(r"[0-9a-fA-F]+", ioc):
        return hash_type

    return None

def check_ioc(ioc):
    """
    Check an IOC using VirusTotal API v3.
    """

    if not isinstance(ioc, str):
        return {
            "ioc": ioc,
            "status": "Invalid IOC",
            "message": "IOC must be a string."
        }

    ioc = ioc.strip()
    ioc_type = classify_ioc(ioc)

    # Reject invalid IOCs before making API requests
    if not ioc_type:
        return {
            "ioc": ioc,
            "status": "Invalid IOC",
            "message": "Invalid IP address or file hash."
        }

    if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
        return {
            "ioc": ioc,
            "status": "Error",
            "message": "API Key is missing or not configured."
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    # Select the correct VirusTotal endpoint
    if ioc_type == "ip_address":
        normalized_ip = str(ipaddress.ip_address(ioc))
        url = (
            f"https://www.virustotal.com/api/v3/"
            f"ip_addresses/{normalized_ip}"
        )
    else:
        url = (
            f"https://www.virustotal.com/api/v3/"
            f"files/{ioc.lower()}"
        )

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        # HTTP 429: Rate Limit
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")

            return {
                "ioc": ioc,
                "status": "API Error",
                "message": "VirusTotal rate limit exceeded.",
                "retry_after": retry_after
            }

        # IOC not found
        if response.status_code == 404:
            return {
                "ioc": ioc,
                "status": "Not Found",
                "message": "IOC not found in VirusTotal database."
            }

        # Other HTTP errors
        if response.status_code != 200:
            return {
                "ioc": ioc,
                "status": "API Error",
                "message": f"HTTP status code: {response.status_code}"
            }

        # Parse JSON response
        try:
            data = response.json()
        except ValueError:
            return {
                "ioc": ioc,
                "status": "Error",
                "message": "Invalid JSON response from VirusTotal."
            }

        # Validate response structure
        if not isinstance(data, dict):
            return {
                "ioc": ioc,
                "status": "Error",
                "message": "Unexpected API response format."
            }

        vt_data = data.get("data")

        if not isinstance(vt_data, dict):
            return {
                "ioc": ioc,
                "status": "Error",
                "message": "Missing or invalid data object."
            }

        attributes = vt_data.get("attributes")

        if not isinstance(attributes, dict):
            return {
                "ioc": ioc,
                "status": "Error",
                "message": "Missing or invalid attributes."
            }

        stats = attributes.get("last_analysis_stats")

        if not isinstance(stats, dict):
            return {
                "ioc": ioc,
                "status": "Error",
                "message": "Missing or invalid analysis statistics."
            }

        # Extract analysis statistics
        counts = {}

        for key in ("malicious", "suspicious", "harmless"):
            value = stats.get(key, 0)

            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return {
                    "ioc": ioc,
                    "status": "Error",
                    "message": f"Invalid analysis statistic: {key}"
                }

            counts[key] = value

        return {
            "ioc": ioc,
            "status": "Success",
            "malicious": counts["malicious"],
            "suspicious": counts["suspicious"],
            "harmless": counts["harmless"]
        }

    except requests.exceptions.Timeout:
        return {
            "ioc": ioc,
            "status": "Error",
            "message": "Request timed out while contacting VirusTotal."
        }

    except requests.exceptions.ConnectionError:
        return {
            "ioc": ioc,
            "status": "Error",
            "message": "Network connection error."
        }

    except requests.exceptions.RequestException as e:
        return {
            "ioc": ioc,
            "status": "Error",
            "message": f"Request failed: {str(e)}"
        }
