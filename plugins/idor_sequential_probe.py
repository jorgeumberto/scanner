# plugins/idor_sequential_probe.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urljoin

PLUGIN_CONFIG_NAME = "idor_sequential_probe"
PLUGIN_CONFIG_ALIASES = ["idor_probe"]
UUID_068 = "uuid-068"  # (68)
UUID_070 = "uuid-070"  # (70)

def _status(url: str, timeout: int, cookie="") -> str:
    hdr = f'-H "Cookie: {cookie}"' if cookie else ""
    return run_cmd(["bash","-lc", f'curl -sS -I -m {timeout} {hdr} "{url}" -o /dev/null -w "%{{http_code}}"'], timeout=timeout+2).strip()

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: {
      "timeout": 12,
      "resources": [{"url":"/api/users/100"},{"url":"/api/orders/200"}],
      "cookie": ""
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    res = cfg.get("resources") or []
    cookie = cfg.get("cookie","")

    evid: List[str] = []
    leaks = 0
    with Timer() as t:
        for r in res:
            u = urljoin(target.rstrip("/") + "/", r.get("url","/").lstrip("/"))
            try:
                base, idval = u.rsplit("/",1)
                idnum = int(idval)
            except:
                continue
            for test in (idnum-1, idnum+1):
                u2 = f"{base}/{test}"
                st = _status(u2, timeout, cookie)
                if st.startswith("20"):  # sucesso suspeito
                    leaks += 1
                    evid.append(f"{u2} -> {st} (possível IDOR)")
                else:
                    evid.append(f"{u2} -> {st}")

    sev = "medium" if leaks else "info"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem indícios nos exemplos configurados"
    return {
        "plugin":"IDORSequentialProbe",
        "result":[
            {"plugin_uuid":UUID_068,"scan_item_uuid":UUID_068,"result":txt,"analysis_ai":ai_fn("IDORSequentialProbe",UUID_068,txt),"severity":sev,"duration":t.duration,"auto":True},
            {"plugin_uuid":UUID_070,"scan_item_uuid":UUID_070,"result":txt,"analysis_ai":ai_fn("IDORSequentialProbe",UUID_070,txt),"severity":sev,"duration":t.duration,"auto":True}
        ]
    }
