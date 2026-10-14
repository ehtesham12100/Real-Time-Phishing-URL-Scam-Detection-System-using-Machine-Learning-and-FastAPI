import requests
import socket
from urllib.parse import urlparse

# Google Safe Browsing API Key (retained from original project)
GOOGLE_SAFE_BROWSING_KEY = "AIzaSyDEevELiGI9vrFA23i--ke2i7YEzxgGUq8"

def check_google_safe_browsing(url: str, api_key: str = GOOGLE_SAFE_BROWSING_KEY) -> dict:
    """
    Checks the URL against the Google Safe Browsing v4 Threat List.
    Returns status and threat details without crashing if offline or quota exceeded.
    """
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "phishing-detection-system",
            "clientVersion": "2.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, params={"key": api_key}, json=payload, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data and len(data["matches"]) > 0:
                threat_type = data["matches"][0].get("threatType", "THREAT_DETECTED")
                return {
                    "status": "THREAT_FOUND",
                    "flagged": True,
                    "threat_type": threat_type,
                    "details": f"Google Safe Browsing database flagged this URL as {threat_type}."
                }
            return {
                "status": "CLEAN",
                "flagged": False,
                "threat_type": "None",
                "details": "Not listed in Google Safe Browsing threat databases."
            }
        else:
            return {
                "status": "API_LIMIT_OR_KEY_ERROR",
                "flagged": False,
                "threat_type": "None",
                "details": f"API returned status {response.status_code}. Proceeded with local AI analysis."
            }
    except Exception as e:
        return {
            "status": "UNREACHABLE",
            "flagged": False,
            "threat_type": "None",
            "details": "Google Safe Browsing check skipped (network timeout or offline)."
        }

def check_dns_resolution(hostname: str) -> dict:
    """
    Checks if domain has active DNS A/AAAA records.
    Inactive domains that are still linked in phishing lures are suspicious.
    """
    try:
        ip = socket.gethostbyname(hostname)
        return {"resolves": True, "ip": ip}
    except Exception:
        return {"resolves": False, "ip": "Unresolved"}
