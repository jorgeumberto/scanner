# plugins/user_enum_probe.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urlencode

PLUGIN_CONFIG_NAME = "user_enum_probe"
PLUGIN_CONFIG_ALIASES = ["user_enum","login_enum"]

UUID_061 = "uuid-061"  # (61) Enumeração de usuários ausente

def _post(url: str, data: Dict[str,str], headers: Dict[str,str], timeout: int) -> str:
    hdrs = []
    for k,v in headers.items(): hdrs += ["-H", f"{k}: {v}"]
    form = urlencode(data)
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} {" ".join(hdrs)} -X POST --data "{form}" "{url}" -i'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg:
    {
      "timeout": 20,
      "login_url": "http://site/login",
      "user_field": "username",
      "pass_field": "password",
      "valid_like": ["user exists","reset sent","found"],
      "invalid_like": ["user not found","unknown","inexistente"],
      "headers": {},
      "candidates": ["admin","testuser","john.doe@example.com"]
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    url     = cfg.get("login_url","")
    uf      = cfg.get("user_field","username")
    pf      = cfg.get("pass_field","password")
    like_ok = [s.lower() for s in (cfg.get("valid_like") or ["exists","reset sent"])]
    like_no = [s.lower() for s in (cfg.get("invalid_like") or ["not found","unknown"])]
    headers = cfg.get("headers") or {}
    cands   = cfg.get("candidates") or ["admin","test","user@example.com"]

    if not url:
        txt = "Config ausente: login_url."
        return {"plugin":"UserEnumProbe","result":[{"plugin_uuid":UUID_061,"scan_item_uuid":UUID_061,"result":txt,"analysis_ai":ai_fn("UserEnumProbe",UUID_061,txt),"severity":"info","duration":0.0,"auto":True}]}

    evid, leaks = [], 0
    with Timer() as t:
        for u in cands:
            body = _post(url, {uf:u, pf:"invalidPass123!"}, headers, timeout).lower()
            if any(x in body for x in like_ok) and not any(x in body for x in like_no):
                leaks += 1; evid.append(f"{u}: resposta sugere existência do usuário")
            elif any(x in body for x in like_no):
                evid.append(f"{u}: resposta nega/ambígua")
            else:
                evid.append(f"{u}: resposta neutra/ambígua")

    sev = "medium" if leaks else "info"
    txt = "\n".join(f"- {e}" for e in evid)
    item = {"plugin_uuid":UUID_061,"scan_item_uuid":UUID_061,"result":txt,"analysis_ai":ai_fn("UserEnumProbe",UUID_061,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"UserEnumProbe","result":[item]}
