
import os, json, time, random
from datetime import datetime
import requests
import pandas as pd
import numpy as np

# Config
SAVE_DIR = "./backend"
RESULT_JSON = "scan_results.json"
EDA_JSON = "eda_summary.json"
RL_JSON = "rl_policy.json"
TIMEOUT = 12
np.random.seed(42)
random.seed(42)

# Sample software inventory (simulate)
def get_installed_software():
    return {
        "OpenSSL": "1.1.1g",
        "Apache HTTPD": "2.4.49",
        "NGINX": "1.18.0",
    }

VENDOR_PRODUCT_MAP = {
    "OpenSSL": ("openssl", "openssl"),
    "Apache HTTPD": ("apache", "http_server"),
    "NGINX": ("nginx", "nginx"),
}

PATCH_HINTS = {
    "Apache HTTPD": "Update to >= 2.4.51",
    "OpenSSL": "Update to latest 1.1.1+ LTS or 3.x",
    "NGINX": "Update to >= 1.25.x",
}

SEVERITY_WEIGHT = {"Low": 1, "Medium": 3, "High": 6, "Critical": 10, "None": 0}

# --- Utilities ---
def severity_bucket(score):
    if score is None: return "Medium"
    if score < 4: return "Low"
    if score < 7: return "Medium"
    if score < 9: return "High"
    return "Critical"

def safe_get(url, params=None):
    try:
        return requests.get(url, params=params, timeout=TIMEOUT)
    except Exception:
        return None

# --- Fetch CVEs ---
def fetch_cves_circl(vendor, product):
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    r = safe_get(url)
    if r and r.status_code == 200:
        try: return r.json()
        except: return []
    return []

def run_scan():
    inventory = get_installed_software()
    records = []
    for sw, ver in inventory.items():
        vendor, product = VENDOR_PRODUCT_MAP.get(sw, (None, None))
        cve_id, sev, cvss = "None", "None", None
        reco = PATCH_HINTS.get(sw, "Update to latest")
        if vendor:
            items = fetch_cves_circl(vendor, product)
            if items:
                first = items[0]
                cve_id = first.get("id", "None")
                cvss = first.get("cvss", None)
                sev = severity_bucket(float(cvss)) if cvss else "Medium"
        records.append({
            "software": sw,
            "version": ver,
            "cve_id": cve_id,
            "severity": sev,
            "cvss": cvss,
            "patch_recommendation": reco,
            "status": "Vulnerable" if cve_id != "None" else "Safe",
            "applied_patch_version": None,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        time.sleep(0.3)

    os.makedirs(SAVE_DIR, exist_ok=True)
    with open(os.path.join(SAVE_DIR, RESULT_JSON), "w") as f:
        json.dump(records, f, indent=2)
    print(f"[✓] Saved results to {RESULT_JSON}")
    return pd.DataFrame(records)

if _name_ == "_main_":
    df = run_scan()
    print(df)
