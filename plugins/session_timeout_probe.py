# plugins/session_timeout_probe.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
import re

PLUGIN_CONFIG_NAME = "session_timeout_probe"
PLUGIN_CONFIG_ALIASES = ["sess_timeout"]
UUID_043 = "uuid-043"  # (43)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "timeout": 12, "paths": ["/"], "look_cookies": ["session","sid"] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    paths = cfg.get("paths") or ["/"]
    look  = [s.lower() for s in (cfg.get("look_cookies") or ["session","sid"])]

    evid, hits = [], 0
    with Timer() as t:
        for p in paths:
            raw = run_cmd(["bash","-lc", f'curl -sSI -m {timeout} "{target.rstrip("/") + p}"'], timeout=timeout+2)
            for ln in raw.splitlines():
                if ln.lower().startswith("set-cookie:"):
                    val = ln.split(":",1)[1].strip()
                    name = val.split("=",1)[0].lower()
                    if any(n in name for n in look):
                        if "max-age" in val.lower() or "expires=" in val.lower():
                            evid.append(f"{p}: cookie {name} possui expiração explícita -> {val}")
                            hits += 1
                        else:
                            evid.append(f"{p}: cookie {name} sem expiração explícita -> {val}")

    sev = "info" if hits else "low"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Nenhum Set-Cookie observado"
    item = {"plugin_uuid":UUID_043,"scan_item_uuid":UUID_043,"result":txt,"analysis_ai":ai_fn("SessionTimeoutProbe",UUID_043,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"SessionTimeoutProbe","result":[item]}
