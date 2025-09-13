# plugins/session_logout_invalidation.py
from typing import Dict, Any
from utils import run_cmd, Timer
from urllib.parse import urlencode

PLUGIN_CONFIG_NAME = "session_logout_invalidation"
PLUGIN_CONFIG_ALIASES = ["sess_logout"]
UUID_044 = "uuid-044"  # (44)

def _post(url: str, data: Dict[str,str], timeout: int) -> str:
    form = urlencode(data)
    return run_cmd(["bash","-lc", f'curl -sS -i -L -m {timeout} -X POST --data "{form}" "{url}"'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "enabled": false, "timeout": 20, "login_url": "...", "logout_url": "...", "check_url": "...", "user_field":"username","pass_field":"password","username":"","password":"" }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoints de login/logout)."
        return {"plugin":"SessionLogoutInvalidation","result":[{"plugin_uuid":UUID_044,"scan_item_uuid":UUID_044,"result":txt,"analysis_ai":ai_fn("SessionLogoutInvalidation",UUID_044,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 20))
    login = cfg.get("login_url","")
    logout= cfg.get("logout_url","")
    check = cfg.get("check_url","/")
    uf = cfg.get("user_field","username")
    pf = cfg.get("pass_field","password")
    user = cfg.get("username","")
    pwd  = cfg.get("password","")

    with Timer() as t:
        # login
        raw = _post(login, {uf:user, pf:pwd}, timeout)
        cookie = ""
        for ln in raw.splitlines():
            if ln.lower().startswith("set-cookie:"):
                cookie = ln.split(":",1)[1].strip()
                break
        if not cookie:
            msg = "Não foi possível obter cookie pós-login."
            sev = "low"
        else:
            # acessar área restrita
            priv = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} -H "Cookie: {cookie}" "{check}" -i'], timeout=timeout+2)
            # logout
            _ = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} -H "Cookie: {cookie}" "{logout}" -i'], timeout=timeout+2)
            # tentar novamente área restrita
            priv2 = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} -H "Cookie: {cookie}" "{check}" -i'], timeout=timeout+2)
            sev = "medium" if priv2.lower().count("200 ok") > 0 else "info"
            msg = f"Acesso com cookie após logout retornou {'200 OK' if sev=='medium' else 'não-200'}."

    item = {"plugin_uuid":UUID_044,"scan_item_uuid":UUID_044,"result":msg,"analysis_ai":ai_fn("SessionLogoutInvalidation",UUID_044,msg),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"SessionLogoutInvalidation","result":[item]}
