import requests
from utils.privacy import get_md5

def check_gravatar(email):
    md5_hash = get_md5(email)
    url = f"https://www.gravatar.com/{md5_hash}.json"
    headers = {"User-Agent": "OpenTrace-SecurityTool/1.0"}
    
    try:
        resp = requests.get(url, headers=headers, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            entry = data.get("entry", [{}])[0]
            return {
                "found": True,
                "profile_url": entry.get("profileUrl"),
                "display_name": entry.get("displayName") or entry.get("preferredUsername"),
                "avatar_url": entry.get("thumbnailUrl"),
                "about_me": entry.get("aboutMe"),
                "evidence": "Official Gravatar API endpoint verified."
            }
    except Exception:
        pass
    return {"found": False, "evidence": "No public Gravatar profile matches this hash."}
