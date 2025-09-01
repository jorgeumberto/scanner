# plugins/login_https_only.py
from typing import Dict, Any
from utils import run_cmd, Timer
from urllib.parse import urlparse

PLUGIN_CONFIG_NAME = "login_https_only"
PLUGIN_CONFIG_ALIASES = ["https_login"]
UUID_059 = "uuid-059"  # (59)

def _status(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -I -m {timeout} "{url}" -o /dev/null -w "%{{http_code}}"'], timeout=timeout+2).strip()

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    login_url = cfg.get("login_url") or (target.rstrip("/") + "/login")

    with Timer() as t:
        parsed = urlparse(login_url)
        http_url  = login_url.replace("https://","http://") if parsed.scheme else "http://" + login_url
        https_url = login_url if login_url.startswith("https://") else ("https://" + parsed.netloc + (parsed.path or ""))

        st_http  = _status(http_url, timeout)
        st_https = _status(https_url, timeout)

        ok = st_https.startswith(("2","3"))
        redir_ok = st_http in ("301","302","307","308")
        msg = []
        if ok: msg.append(f"HTTPS acessível: {https_url} -> {st_https}")
        else:  msg.append(f"HTTPS possivelmente inacessível: {https_url} -> {st_https}")
        if redir_ok: msg.append(f"HTTP redireciona para HTTPS (bom): {http_url} -> {st_http}")
        else: msg.append(f"HTTP não redireciona (ruim): {http_url} -> {st_http}")

    sev = "low" if (not ok or not redir_ok) else "info"
    txt = "\n".join(f"- {m}" for m in msg)
    item = {"plugin_uuid":UUID_059,"scan_item_uuid":UUID_059,"result":txt,"analysis_ai":ai_fn("LoginHTTPSOnly",UUID_059,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"LoginHTTPSOnly","result":[item]}
