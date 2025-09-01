# plugins/dom_xss_heuristics.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urljoin, quote_plus
import re

PLUGIN_CONFIG_NAME = "dom_xss_heuristics"
PLUGIN_CONFIG_ALIASES = ["dom_xss","xss_dom"]

UUID_036 = "uuid-036"  # (36) XSS baseado em DOM ausente

SINKS = [
    "innerhtml", "outerhtml", "document.write(", "document.writeln(",
    "eval(", "settimeout(", "setinterval(", "createelement('script'",
    "location.hash", "location.search", "window.name"
]
PARAMS = ["q","s","search","term","query"]

def _get(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}"'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: {"timeout": 15, "paths": ["/","/search"], "payload": "<svg/onload=alert(1)>"}
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    paths   = cfg.get("paths") or ["/","/search"]
    payload = cfg.get("payload","<svg/onload=alert(1)>")

    evid, flags = [], 0
    with Timer() as t:
        # 1) busca por sinks no HTML estático
        for p in paths:
            url = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            html = _get(url, timeout).lower()
            hits = [s for s in SINKS if s in html]
            if hits:
                evid.append(f"{p}: possíveis sinks no HTML: {', '.join(sorted(set(hits)))}")

            # 2) reflexão direta do payload em parâmetros comuns (não prova DOM-XSS, mas alerta)
            for k in PARAMS:
                u = url + (("&" if "?" in url else "?") + f"{k}={quote_plus(payload)}")
                body = _get(u, timeout).lower()
                if payload.lower() in body:
                    flags += 1
                    evid.append(f"{p}?{k}= ... payload refletido no HTML (verificar DOM).")

    sev = "low" if flags else "info"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem evidências heurísticas de DOM-XSS"
    item = {"plugin_uuid":UUID_036,"scan_item_uuid":UUID_036,"result":txt,"analysis_ai":ai_fn("DOMXSSHeuristics",UUID_036,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"DOMXSSHeuristics","result":[item]}
