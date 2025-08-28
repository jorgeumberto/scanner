# plugins/curl_files.py
from utils import run_cmd, Timer
from typing import Dict, Any, List

# UUIDs - substitua pelos reais (ID 3)
UUIDS = {
    "robots":       "uuid-003-robots",
    "sitemap":      "uuid-003-sitemap",
    "humans":       "uuid-003-humans",
    "security_txt": "uuid-003-securitytxt",
}

FILES = {
    "robots": "robots.txt",
    "sitemap": "sitemap.xml",
    "humans": "humans.txt",
    "security_txt": ".well-known/security.txt",
}

def run_plugin(target: str, ai_fn):
    items: List[Dict[str, Any]] = []
    with Timer() as t:
        for key, path in FILES.items():
            url = target.rstrip("/") + "/" + path
            code = run_cmd(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", url], timeout=15).strip()
            ok = (code == "200")
            result = f"{path} -> HTTP {code}"
            severity = "low" if ok else ("info" if code == "404" else "low")
            uuid = UUIDS[key]
            items.append({
                "plugin_uuid": uuid,
                "scan_item_uuid": uuid,
                "result": result,
                "analysis_ai": ai_fn("CurlFiles", uuid, result),
                "severity": severity,
                "duration": t.duration,
                "auto": True
            })
    return {"plugin": "CurlFiles", "result": items}
