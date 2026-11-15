import os
import requests
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_ioc(ioc):
    """
    دالة لفحص الـ IOC عبر VirusTotal API (تدعم IPs و File Hashes)
    """
    if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
        return {"ioc": ioc, "status": "Error", "message": "API Key is missing or not configured."}

    headers = {
        "x-apikey": VT_API_KEY
    }

    # تحديد نوع الـ IOC (إذا كان يحتوي على نقاط فهو غالباً IP، وإلا فهو Hash)
    if "." in ioc and not len(ioc) in [32, 40, 64]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"

    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            
            return {
                "ioc": ioc,
                "status": "Success",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless
            }
        elif response.status_code == 404:
            return {"ioc": ioc, "status": "Not Found", "message": "IOC not found in VirusTotal database."}
        else:
            return {"ioc": ioc, "status": "API Error", "message": f"Status code: {response.status_code}"}
            
    except Exception as e:
        return {"ioc": ioc, "status": "Error", "message": str(e)}
