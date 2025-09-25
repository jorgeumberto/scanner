# plugins/admin_endpoints_guard.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urljoin

UUID_071 = "uuid-071-admin-protected"  # (71)

COMMON = ["/admin", "/admin/", "/admin/login", "/administrator", "/manage", "/panel", "/wp-admin", "/phpmyadmin"]

def _status(url: str, timeout: int, cookie="") -> str:
    hdr = f'-H "Cookie: {cookie}"' if cookie else ""
    return run_cmd(["bash","-lc", f'curl -sS -I -m {timeout} {hdr} "{url}" -o /dev/null -w "%{{http_code}}"'], timeout=timeout+2).strip()

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    paths = cfg.get("paths") or COMMON
    cookie = cfg.get("cookie","")

    evid: List[str] = []
    issues = 0
    with Timer() as t:
        for p in paths:
            u = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            st = _status(u, timeout, cookie)
            if st.startswith("200"):
                issues += 1
                evid.append(f"{p} -> {st} (pode estar exposto sem auth)")
            else:
                evid.append(f"{p} -> {st}")

    sev = "high" if issues else "info"
    txt = "\n".join(f"- {e}" for e in evid)
    
    item = {
        "scan_item_uuid":UUID_071,
        "result":txt,
        "analysis_ai":ai_fn("AdminEndpointsGuard",UUID_071,txt),
        "severity":sev,
        "duration":t.duration,
        "auto":True,
        "reference": "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
        "item_name": "Admin Endpoints Guard",
        }
    
    return {
        "plugin":"AdminEndpointsGuard",
        "plugin_uuid": UUID_071,
        "file_name": "admin_endpoints_guard.py",
        "description": "Detecta possíveis endpoints administrativos expostos sem autenticação.",
        "category": "Information Gathering",
        "result":[item],
    }
