# plugins/session_regeneration_probe.py
from typing import Dict, Any
from utils import run_cmd, Timer
from urllib.parse import urlencode
import re

PLUGIN_CONFIG_NAME = "session_regeneration_probe"
PLUGIN_CONFIG_ALIASES = ["sess_regen"]
UUID_042 = "uuid-042"  # (42)

def _cookie_from_headers(raw: str) -> str:
    for ln in raw.splitlines():
        if ln.lower().startswith("set-cookie:"):
            return ln.split(":",1)[1].strip()
    return ""

def _post(url: str, data: Dict[str,str], headers: Dict[str,str], timeout: int, cookie="") -> str:
    hdrs = []
    for k,v in headers.items(): hdrs += ["-H", f"{k}: {v}"]
    if cookie: hdrs += ["-H", f"Cookie: {cookie}"]
    form = urlencode(data)
    return run_cmd(["bash","-lc", f'curl -sS -i -L -m {timeout} {" ".join(hdrs)} -X POST --data "{form}" "{url}"'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "enabled": false, "timeout": 20, "login_url": "...", "user_field":"username", "pass_field":"password", "username":"", "password":"" }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e credenciais)."
        return {"plugin":"SessionRegenerationProbe","result":[{"plugin_uuid":UUID_042,"scan_item_uuid":UUID_042,"result":txt,"analysis_ai":ai_fn("SessionRegenerationProbe",UUID_042,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 20))
    url = cfg.get("login_url","")
    uf  = cfg.get("user_field","username")
    pf  = cfg.get("pass_field","password")
    user= cfg.get("username","")
    pwd = cfg.get("password","")

    with Timer() as t:
        # 1a requisição para capturar cookie anônimo
        pre = run_cmd(["bash","-lc", f'curl -sSI -m {timeout} "{url}"'], timeout=timeout+2)
        cookie_pre = _cookie_from_headers(pre)

        # login
        body = _post(url, {uf:user, pf:pwd}, {}, timeout, cookie_pre)
        cookie_post = _cookie_from_headers(body)

    changed = (cookie_pre.split(";",1)[0] != cookie_post.split(";",1)[0])
    msg = f"cookie antes: {cookie_pre}\ncookie após login: {cookie_post}\nregenerou? {'sim' if changed else 'não'}"
    sev = "medium" if not changed else "info"
    item = {"plugin_uuid":UUID_042,"scan_item_uuid":UUID_042,"result":msg,"analysis_ai":ai_fn("SessionRegenerationProbe",UUID_042,msg),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"SessionRegenerationProbe","result":[item]}
