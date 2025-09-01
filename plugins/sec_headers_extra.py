# plugins/sec_headers_extra.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "sec_headers_extra"
PLUGIN_CONFIG_ALIASES = ["headers_extra", "security_headers"]

# >>> troque pelos UUIDs REAIS:
UUID_021 = "uuid-021"  # Cache-Control/Pragma
UUID_029 = "uuid-029"  # Referrer-Policy / Permissions-Policy
UUID_031 = "uuid-031"  # X-Frame-Options
UUID_032 = "uuid-032"  # Content-Security-Policy

def _curl_head(url: str, timeout: int) -> str:
    return run_cmd(["curl", "-sS", "-I", "-L", "-m", str(timeout), url], timeout=timeout+2)

def _get_header(lines: List[str], name: str) -> str:
    name_low = name.lower()
    for ln in lines:
        if ln.lower().startswith(name_low + ":"):
            return ln.split(":", 1)[1].strip()
    return ""

def _check_cache(lines: List[str]) -> Tuple[str, List[str]]:
    cc = _get_header(lines, "Cache-Control")
    pragma = _get_header(lines, "Pragma")
    cookie = _get_header(lines, "Set-Cookie")
    evid = []
    sev = "info"

    if not cc and not pragma:
        sev = "medium"
        evid.append("Ausente: Cache-Control/Pragma")
    else:
        evid.append(f"Cache-Control: {cc or '—'} | Pragma: {pragma or '—'}")
        # se tem cookie de sessão, recomenda no-store/no-cache
        if cookie and not any(x in (cc or "").lower() for x in ["no-store", "no-cache", "private"]):
            sev = "low"
            evid.append("Possível ajuste: adicionar 'no-store'/'no-cache' para respostas com cookies")

    return sev, evid

def _check_referrer_permissions(lines: List[str]) -> Tuple[str, List[str]]:
    refp = _get_header(lines, "Referrer-Policy")
    perm = _get_header(lines, "Permissions-Policy")
    evid = []
    sev = "info"

    if not refp:
        sev = "low"
        evid.append("Ausente: Referrer-Policy")
    else:
        evid.append(f"Referrer-Policy: {refp}")

    if not perm:
        # não é obrigatório, mas recomendado
        if sev != "medium":
            sev = "low"
        evid.append("Ausente: Permissions-Policy")
    else:
        evid.append(f"Permissions-Policy: {perm}")

    return sev, evid

def _check_xfo(lines: List[str]) -> Tuple[str, List[str]]:
    xfo = _get_header(lines, "X-Frame-Options")
    evid = []
    sev = "info"
    if not xfo:
        sev = "medium"
        evid.append("Ausente: X-Frame-Options")
    else:
        evid.append(f"X-Frame-Options: {xfo}")
        if "allow" in xfo.lower() and "sameorigin" not in xfo.lower() and "deny" not in xfo.lower():
            sev = "medium"
            evid.append("Política possivelmente permissiva (considere DENY ou SAMEORIGIN)")
    return sev, evid

def _check_csp(lines: List[str]) -> Tuple[str, List[str]]:
    csp = _get_header(lines, "Content-Security-Policy")
    evid = []
    sev = "info"
    if not csp:
        sev = "medium"
        evid.append("Ausente: Content-Security-Policy")
    else:
        evid.append(f"Content-Security-Policy: {csp[:200]}{'...' if len(csp)>200 else ''}")
        lc = csp.lower()
        if "'unsafe-inline'" in lc or "'unsafe-eval'" in lc or "*" in lc:
            sev = "low" if sev != "medium" else "medium"
            evid.append("Diretivas permissivas detectadas ('unsafe-inline'/'unsafe-eval' ou '*')")
    return sev, evid

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/sec_headers_extra.json):
    { "timeout": 15 }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))

    with Timer() as t:
        raw = _curl_head(target, timeout)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    sev21, ev21 = _check_cache(lines)
    sev29, ev29 = _check_referrer_permissions(lines)
    sev31, ev31 = _check_xfo(lines)
    sev32, ev32 = _check_csp(lines)

    items = []

    def _mk(uuid, name, sev, ev):
        text = "\n".join(f"- {e}" for e in ev) if ev else f"Nenhum achado para {name}"
        return {
            "plugin_uuid": uuid,
            "scan_item_uuid": uuid,
            "result": text,
            "analysis_ai": ai_fn("SecHeadersExtra", uuid, text),
            "severity": sev,
            "duration": t.duration,
            "auto": True
        }

    items.append(_mk(UUID_021, "Cache-Control/Pragma", sev21, ev21))
    items.append(_mk(UUID_029, "Referrer-Policy / Permissions-Policy", sev29, ev29))
    items.append(_mk(UUID_031, "X-Frame-Options", sev31, ev31))
    items.append(_mk(UUID_032, "Content-Security-Policy", sev32, ev32))

    return {
        "plugin": "SecHeadersExtra",
        "result": items
    }
