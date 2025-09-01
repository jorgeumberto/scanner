# plugins/reflect_xss_probe.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urljoin, quote_plus

PLUGIN_CONFIG_NAME = "reflect_xss_probe"
PLUGIN_CONFIG_ALIASES = ["xss_reflect"]
UUID_047 = "uuid-047"  # (47)

PARAMS = ["q","search","term","s"]
PAYLOAD = "<xssX>\"'<>"

def _get(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}"'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    paths = cfg.get("paths") or ["/","/search"]

    evid, hits = [], 0
    with Timer() as t:
        for p in paths:
            base = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            for k in PARAMS:
                u = base + (("&" if "?" in base else "?") + f"{k}={quote_plus(PAYLOAD)}")
                body = _get(u, timeout)
                if PAYLOAD.lower() in body.lower():
                    hits += 1
                    evid.append(f"{p}?{k}= refletiu payload (potencial XSS refletido).")
    sev = "medium" if hits else "info"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem reflexão direta do payload"
    item = {"plugin_uuid":UUID_047,"scan_item_uuid":UUID_047,"result":txt,"analysis_ai":ai_fn("ReflectXSSProbe",UUID_047,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"ReflectXSSProbe","result":[item]}
