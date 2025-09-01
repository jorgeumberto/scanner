# plugins/cmd_injection_probe.py
from typing import Dict, Any
from utils import run_cmd, Timer
from urllib.parse import urljoin, quote_plus

PLUGIN_CONFIG_NAME = "cmd_injection_probe"
PLUGIN_CONFIG_ALIASES = ["cmdi"]
UUID_053 = "uuid-053"  # (53)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "enabled": false, "timeout": 12, "path": "/ping?host=", "param": "host" }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoint seguro)."
        return {"plugin":"CmdInjectionProbe","result":[{"plugin_uuid":UUID_053,"scan_item_uuid":UUID_053,"result":txt,"analysis_ai":ai_fn("CmdInjectionProbe",UUID_053,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 12))
    path = cfg.get("path","/ping")
    param= cfg.get("param","host")
    base = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    # time-based: ; sleep 3
    url = base + (("&" if "?" in base else "?") + f"{param}={quote_plus('127.0.0.1; sleep 2')}")
    with Timer() as t:
        raw = run_cmd(["bash","-lc", f'curl -sS -m {timeout+4} "{url}" -w "\\nTIME_OK"'], timeout=timeout+6)
    sev = "medium" if t.duration > 1.8 else "info"
    item = {"plugin_uuid":UUID_053,"scan_item_uuid":UUID_053,"result":f"tempo ≈ {t.duration:.2f}s","analysis_ai":ai_fn("CmdInjectionProbe",UUID_053,f"tempo ≈ {t.duration:.2f}s"),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"CmdInjectionProbe","result":[item]}
