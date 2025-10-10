# plugins/dom_xss_heuristics.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urljoin, quote_plus
import re

PLUGIN_CONFIG_NAME = "dom_xss_heuristics"
PLUGIN_CONFIG_ALIASES = ["dom_xss","xss_dom"]

UUID_036 = "uuid-036"  # (36) XSS baseado em DOM

REFERENCE_URL = "https://owasp.org/www-community/attacks/DOM_Based_XSS"

SINKS = [
    "innerhtml", "outerhtml", "document.write(", "document.writeln(",
    "eval(", "settimeout(", "setinterval(", "createelement('script'",
    "location.hash", "location.search", "window.name"
]
PARAMS = ["q","s","search","term","query"]

def _get(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}"'], timeout=timeout+2)

def _build_commands_example(base_url: str, timeout: int, example_path: str, payload: str) -> str:
    """
    Retorna comandos cURL exemplificando:
      1) GET do HTML base
      2) GET com payload refletido no parâmetro 'q' (apenas exemplo)
    """
    url_base = urljoin(base_url.rstrip("/") + "/", example_path.lstrip("/"))
    url_payload = url_base + (("&" if "?" in url_base else "?") + f"q={quote_plus(payload)}")
    cmd1 = f'curl -sS -L -m {timeout} "{url_base}"'
    cmd2 = f'curl -sS -L -m {timeout} "{url_payload}"'
    return f"{cmd1} ; {cmd2}"

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: {"timeout": 15, "paths": ["/","/search"], "payload": "<svg/onload=alert(1)>",
          "sinks": [...], "params": [...]}
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    paths   = cfg.get("paths") or ["/","/search"]
    payload = cfg.get("payload","<svg/onload=alert(1)>")
    sinks   = [s.lower() for s in (cfg.get("sinks") or SINKS)]
    params  = cfg.get("params") or PARAMS

    evid: List[str] = []
    flags = 0

    with Timer() as t:
        # 1) Busca por sinks no HTML estático
        for p in paths:
            url = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            html = _get(url, timeout).lower()
            hits = [s for s in sinks if s in html]
            if hits:
                evid.append(f"{p}: possíveis sinks no HTML: {', '.join(sorted(set(hits)))}")

            # 2) Reflexão direta do payload em parâmetros comuns
            for k in params:
                u = url + (("&" if "?" in url else "?") + f"{k}={quote_plus(payload)}")
                body = _get(u, timeout).lower()
                if payload.lower() in body:
                    flags += 1
                    evid.append(f"{p}?{k}=... payload refletido no HTML (verificar DOM).")

    # Severidade conservadora: reflexão sugere investigação, mas não prova DOM-XSS
    sev = "low" if flags else "info"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem evidências heurísticas de DOM-XSS"

    # Comando exemplo (usa o primeiro path como demonstração)
    example_path = (paths[0] if paths else "/")
    command = _build_commands_example(target, timeout, example_path, payload)

    item = {
        "plugin_uuid": UUID_036,
        "scan_item_uuid": UUID_036,
        "result": txt,
        "analysis_ai": ai_fn("DOMXSSHeuristics", UUID_036, txt),
        "severity": sev,
        "duration": t.duration,
        "auto": True,
        "reference": REFERENCE_URL,
        "item_name": "DOM-based XSS Heuristics",
        "command": command
    }

    return {
        "plugin": "DOMXSSHeuristics",
        "plugin_uuid": UUID_036,
        "file_name": "dom_xss_heuristics.py",
        "description": "Heurísticas de XSS baseado em DOM via detecção de sinks e reflexão de payload em parâmetros comuns.",
        "category": "Client-Side Testing",
        "result": [item]
    }