# api_client.py
import os, json, requests
from typing import Dict, Any

API_URL  = os.getenv("API_URL", "http://192.168.248.111/api/scan-results")
API_KEY  = os.getenv("API_KEY", "your-team-api-key")
TIMEOUT  = int(os.getenv("API_TIMEOUT_S", "30"))

def _default_headers() -> Dict[str, str]:
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    return h

def post_results(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Envia um dict JSON diretamente."""
    try:
        resp = requests.post(API_URL, headers=_default_headers(), json=payload, timeout=TIMEOUT)
        ct = (resp.headers.get("Content-Type") or "").lower()
        if resp.ok:
            return {"status": "OK", "code": resp.status_code,
                    "data": resp.json() if "json" in ct else resp.text}
        return {"status": "ERRO", "code": resp.status_code, "data": resp.text}
    except Exception as e:
        return {"status": "ERRO", "message": str(e)}
