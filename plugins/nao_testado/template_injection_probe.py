# plugins/template_injection_probe.py
from typing import Dict, Any
from utils import run_cmd, Timer
from urllib.parse import urljoin, quote_plus

PLUGIN_CONFIG_NAME = "template_injection_probe"
PLUGIN_CONFIG_ALIASES = ["ti_probe"]
UUID_054 = "uuid-054"  # (54)

PROBES = ["{{7*7}}","${{7*7}}","<%= 7*7 %>"]

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "enabled": false, "timeout": 12, "path": "/", "param": "q" }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoint específico)."
        return {"plugin":"TemplateInjectionProbe","result":[{"plugin_uuid":UUID_054,"scan_item_uuid":UUID_054,"result":txt,"analysis_ai":ai_fn("TemplateInjectionProbe",UUID_054,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 12))
    path = cfg.get("path","/")
    param= cfg.get("param","q")
    base = urljoin(target.rstrip("/") + "/", path.lstrip("/"))

    evid, hits = [], 0
    with Timer() as t:
        for p in PROBES:
            url = base + (("&" if "?" in base else "?") + f"{param}={quote_plus(p)}")
            body = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}"'], timeout=timeout+2)
            if "49" in body:
                hits += 1; evid.append(f"Payload {p} avaliado (49).")

    sev = "medium" if hits else "info"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem indícios de avaliação de template"
    item = {"plugin_uuid":UUID_054,"scan_item_uuid":UUID_054,"result":txt,"analysis_ai":ai_fn("TemplateInjectionProbe",UUID_054,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"TemplateInjectionProbe","result":[item]}
