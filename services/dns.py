import requests

def check_domain_dns(domain):
    results = {"mx": [], "spf": False, "dmarc": False}
    headers = {"Accept": "application/dns-json", "User-Agent": "OpenTrace/1.0"}
    
    try:
        resp = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX", headers=headers, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            for answer in data.get("Answer", []):
                if answer.get("type") == 15:
                    results["mx"].append(str(answer.get("data", "")))
    except Exception:
        pass

    try:
        resp = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT", headers=headers, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            for answer in data.get("Answer", []):
                txt = str(answer.get("data", "")).strip('"')
                if "v=spf1" in txt.lower():
                    results["spf"] = True
    except Exception:
        pass

    try:
        resp = requests.get(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT", headers=headers, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            for answer in data.get("Answer", []):
                txt = str(answer.get("data", "")).strip('"')
                if "v=dmarc1" in txt.lower():
                    results["dmarc"] = True
    except Exception:
        pass

    return results
