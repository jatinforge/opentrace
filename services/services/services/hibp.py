import requests
from config import Config

def check_hibp(email):
    if not Config.HIBP_API_KEY:
        return {
            "configured": False,
            "breaches": [],
            "evidence": "HIBP API key not configured. Set HIBP_API_KEY in environment variables."
        }
    
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        "hibp-api-key": Config.HIBP_API_KEY,
        "User-Agent": "OpenTrace-SecurityTool"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            breaches = [{
                "name": b.get("Name", "Unknown"),
                "title": b.get("Title", "Unknown Service"),
                "date": b.get("BreachDate", "N/A"),
                "data_classes": b.get("DataClasses", [])
            } for b in data]
            return {"configured": True, "breaches": breaches, "evidence": "Official Have I Been Pwned API v3 check."}
        elif resp.status_code == 404:
            return {"configured": True, "breaches": [], "evidence": "No breach records found via official HIBP API."}
    except Exception:
        pass
    
    return {"configured": True, "breaches": [], "evidence": "API request failed or rate limited."}
