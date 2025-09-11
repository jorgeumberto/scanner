# plugins/auth_rate_limit_probe.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urlencode

PLUGIN_CONFIG_NAME = "auth_rate_limit_probe"
PLUGIN_CONFIG_ALIASES = ["rl_auth"]
UUID_063 = "uuid-063-bruteforce-limit"  # (63)
UUID_084 = "uuid-084-rate-limit"  # (84)

def _post(url: str, data: Dict[str,str], timeout: int) -> str:
    form = urlencode(data)
    return run_cmd(["bash","-lc", f'curl -sS -i -m {timeout} -X POST --data "{form}" "{url}"'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "timeout": 15, "login_url":"...", "user_field":"username","pass_field":"password","user":"admin","tries":6, "sleep":0 }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    url = cfg.get("login_url","")
    uf  = cfg.get("user_field","username")
    pf  = cfg.get("pass_field","password")
    user= cfg.get("user","admin")
    tries= int(cfg.get("tries", 6))
    slp  = int(cfg.get("sleep", 0))

    evid, hits429 = [], 0
    with Timer() as t:
        for i in range(max(2, tries)):
            body = _post(url, {uf:user, pf:"WrongPass!234"}, timeout).lower()
            code = next((ln.split()[1] for ln in body.splitlines() if ln.startswith("HTTP/")), "?")
            if code == "429" or "retry-after" in body:
                hits429 += 1
            evid.append(f"tentativa {i+1}: HTTP {code}")
            if slp: run_cmd(["bash","-lc", f"sleep {slp}"], timeout=slp+1)

    sev = "info" if hits429 else "low"
    res63 = "Rate limit/lockout aparente" if hits429 else "Sem evidência clara de rate limit"
    res84 = "\n".join(f"- {e}" for e in evid)
    return {
        "plugin":"AuthRateLimitProbe",
        "result":[
            {"plugin_uuid":UUID_063,"scan_item_uuid":UUID_063,"result":res63,"analysis_ai":ai_fn("AuthRateLimitProbe",UUID_063,res63),"severity":sev,"duration":t.duration,"auto":True},
            {"plugin_uuid":UUID_084,"scan_item_uuid":UUID_084,"result":res84,"analysis_ai":ai_fn("AuthRateLimitProbe",UUID_084,res84),"severity":"info","duration":t.duration,"auto":True}
        ]
    }
