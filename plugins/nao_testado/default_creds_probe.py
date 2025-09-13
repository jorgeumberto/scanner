# plugins/default_creds_probe.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer
from urllib.parse import urlencode

PLUGIN_CONFIG_NAME = "default_creds_probe"
PLUGIN_CONFIG_ALIASES = ["default_creds","weak_login"]

UUID_060 = "uuid-060"  # (60) Credenciais padrão/óbvias

COMMON = [
    ("admin","admin"), ("admin","password"), ("admin","123456"),
    ("root","root"), ("test","test"), ("user","user"), ("administrator","admin")
]

def _post(url: str, data: Dict[str,str], headers: Dict[str,str], timeout: int) -> str:
    hdrs = []
    for k,v in headers.items(): hdrs += ["-H", f"{k}: {v}"]
    form = urlencode(data)
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} {" ".join(hdrs)} -X POST --data "{form}" "{url}" -i'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: {
      "timeout": 20,
      "login_url": "http://site/login",
      "user_field": "username",
      "pass_field": "password",
      "success_like": ["dashboard","logout","minha conta"],
      "headers": {},
      "pairs": [["admin","admin"], ["test","test"]],
      "enabled": false  // previne tentativas se não autorizado
    }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Probe desabilitado por padrão (defina enabled=true no config)."
        return {"plugin":"DefaultCredsProbe","result":[{"plugin_uuid":UUID_060,"scan_item_uuid":UUID_060,"result":txt,"analysis_ai":ai_fn("DefaultCredsProbe",UUID_060,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 20))
    url     = cfg.get("login_url","")
    uf      = cfg.get("user_field","username")
    pf      = cfg.get("pass_field","password")
    ok_like = [s.lower() for s in (cfg.get("success_like") or ["logout","dashboard","minha conta"])]
    headers = cfg.get("headers") or {}
    pairs   = cfg.get("pairs") or COMMON

    if not url:
        txt = "Config ausente: login_url."
        return {"plugin":"DefaultCredsProbe","result":[{"plugin_uuid":UUID_060,"scan_item_uuid":UUID_060,"result":txt,"analysis_ai":ai_fn("DefaultCredsProbe",UUID_060,txt),"severity":"info","duration":0.0,"auto":True}]}

    evid, hits = [], 0
    with Timer() as t:
        for u,p in pairs[:12]:
            body = _post(url, {uf:u, pf:p}, headers, timeout).lower()
            if any(x in body for x in ok_like):
                hits += 1; evid.append(f"possível sucesso com {u}:{p} (verificar manualmente)")
            else:
                evid.append(f"{u}:{p} não indicou sucesso")

    sev = "high" if hits else "info"
    txt = "\n".join(f"- {e}" for e in evid)
    item = {"plugin_uuid":UUID_060,"scan_item_uuid":UUID_060,"result":txt,"analysis_ai":ai_fn("DefaultCredsProbe",UUID_060,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"DefaultCredsProbe","result":[item]}
