# plugins/policy_headers_deep.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "policy_headers_deep"
PLUGIN_CONFIG_ALIASES = ["policies", "headers_policies"]

UUID_029 = "uuid-029"  # (29) Referrer-Policy / Permissions-Policy

def _curl_head(url: str, timeout: int) -> str:
    return run_cmd(["curl", "-sS", "-I", "-L", "-m", str(timeout), url], timeout=timeout+2)

def _get_header(lines: List[str], name: str) -> str:
    low = name.lower()+":"
    for ln in lines:
        if ln.lower().startswith(low):
            return ln.split(":",1)[1].strip()
    return ""

GOOD_REF = {"no-referrer","same-origin","strict-origin","strict-origin-when-cross-origin"}
BAD_REF  = {"unsafe-url"}

def _score_referrer(v: str) -> Tuple[str, List[str]]:
    evid, sev = [], "info"
    if not v:
        return "low", ["Ausente: Referrer-Policy"]
    val = v.split(",",1)[0].strip().lower()
    evid.append(f"Referrer-Policy: {v}")
    if val in BAD_REF:
        sev = "medium"; evid.append("Valor fraco (unsafe-url)")
    elif val not in GOOD_REF:
        sev = "low"; evid.append("Valor não recomendado; considere 'no-referrer' ou 'strict-origin-when-cross-origin'")
    return sev, evid

PP_HINTS = {
    "geolocation": "geolocation=() (bloquear por padrão)",
    "camera": "camera=()",
    "microphone": "microphone=()",
    "payment": "payment=()",
    "usb": "usb=()",
    "fullscreen": "fullscreen=(self)",  # costuma ser ok
}

def _score_permissions(v: str) -> Tuple[str, List[str]]:
    evid, sev = [], "info"
    if not v:
        return "low", ["Ausente: Permissions-Policy"]
    evid.append(f"Permissions-Policy: {v[:200]}{'...' if len(v)>200 else ''}")
    low = v.lower()
    weak = []
    for k,h in PP_HINTS.items():
        if k in low and "=*" in low:
            weak.append(k)
    if weak:
        sev = "medium"; evid.append(f"Diretivas permissivas detectadas: {', '.join(weak)}")
        evid.append("Sugestão: restrinja, ex.: " + ", ".join(PP_HINTS[w] for w in weak))
    return sev, evid

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    with Timer() as t:
        raw = _curl_head(target, timeout)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    refp = _get_header(lines, "Referrer-Policy")
    perm = _get_header(lines, "Permissions-Policy")

    sev_ref, ev_ref = _score_referrer(refp)
    sev_pp,  ev_pp  = _score_permissions(perm)

    def _mk(uuid, name, sev, ev):
        txt = "\n".join(f"- {e}" for e in ev) if ev else f"Nenhum achado para {name}"
        return {
            "plugin_uuid": uuid,
            "scan_item_uuid": uuid,
            "result": txt,
            "analysis_ai": ai_fn("PolicyHeadersDeep", uuid, txt),
            "severity": sev,
            "duration": t.duration,
            "auto": True
        }

    items = [
        _mk(UUID_029, "Referrer-Policy", sev_ref, ev_ref),
        _mk(UUID_029, "Permissions-Policy", sev_pp, ev_pp)
    ]
    return {"plugin": "PolicyHeadersDeep", "result": items}
