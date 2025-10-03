# plugins/admin_endpoints_guard.py
from typing import Dict, Any, List
from utils import run_cmd as _run_cmd_shadow, Timer
from urllib.parse import urljoin

# === injected: capture executed shell commands for tagging ===
try:
    from utils import run_cmd as __run_cmd_orig  # keep original
except Exception as _e_inject:
    __run_cmd_orig = None

EXEC_CMDS = []  # type: list[str]

def run_cmd(cmd, timeout=None):
    """
    Wrapper injected to capture the exact command used.
    Keeps the original behavior, but records the command string.
    """
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    EXEC_CMDS.append(cmd_str)
    if __run_cmd_orig is None:
        raise RuntimeError("run_cmd original não disponível para execução.")
    return __run_cmd_orig(cmd, timeout=timeout)
# === end injected ===


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
            "command": EXEC_CMDS[-1] if EXEC_CMDS else "",
        }
    
    return {
        "plugin":"AdminEndpointsGuard",
        "plugin_uuid": UUID_071,
        "file_name": "admin_endpoints_guard.py",
        "description": "Detecta possíveis endpoints administrativos expostos sem autenticação.",
        "category": "Authorization and Access Control",
        "result":[item],
    }
