# plugins/sec_headers_extra.py
from typing import Dict, Any, List, Tuple, Optional
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "sec_headers_extra"
PLUGIN_CONFIG_ALIASES = ["headers_extra", "security_headers"]

# UUIDs alinhados ao curl_headers.py
UUID_043_CACHE          = "uuid-043-sec-extra-cache"                  # Cache Headers
UUID_041_REFERRER       = "uuid-041-sec-extra-referrer-policy"     # Referrer-Policy
UUID_042_PERMISSIONS    = "uuid-042-sec-extra-permissions-policy"  # Permissions-Policy
UUID_031_XFO            = "uuid-031-sec-extra-xframe"                   # X-Frame-Options
UUID_032_CSP            = "uuid-032-sec-extra-csp"                      # Content-Security-Policy

REFERENCE_URL = "https://owasp.org/www-project-secure-headers/"

def _curl_head(url: str, timeout: int) -> str:
    # -I para headers; -L segue redirects; -m timeout para não travar
    return run_cmd(["curl", "-sS", "-I", "-L", "-m", str(timeout), url], timeout=timeout + 2)

def _get_header(lines: List[str], name: str) -> Optional[str]:
    name_low = name.lower()
    for ln in lines:
        if ln.lower().startswith(name_low + ":"):
            return ln.split(":", 1)[1].strip()
    return None

def _check_cache(lines: List[str]) -> Tuple[str, str]:
    """
    Alinhado ao curl_headers:
    - Mensagem: consolida Cache-Control/Pragma/Expires quando presentes
    - Severidade: low se Cache-Control ausente (indicativo)
    """
    cc = _get_header(lines, "Cache-Control")
    pragma = _get_header(lines, "Pragma")
    expires = _get_header(lines, "Expires")

    parts = []
    if cc: parts.append(f"Cache-Control: {cc}")
    if pragma: parts.append(f"Pragma: {pragma}")
    if expires: parts.append(f"Expires: {expires}")
    msg = "; ".join(parts) if parts else "Cabeçalhos de cache ausentes"

    sev = "low" if not cc else "info"
    return sev, msg

def _check_referrer_policy(lines: List[str]) -> Tuple[str, str]:
    refp = _get_header(lines, "Referrer-Policy")
    if refp:
        return "info", f"Referrer-Policy: {refp}"
    return "low", "Referrer-Policy ausente"

def _check_permissions_policy(lines: List[str]) -> Tuple[str, str]:
    perm = _get_header(lines, "Permissions-Policy")
    if perm:
        return "info", f"Permissions-Policy: {perm}"
    return "low", "Permissions-Policy ausente"

def _check_xfo(lines: List[str]) -> Tuple[str, str, str]:
    """
    - Ausente => medium
    - Presente com diretivas muito permissivas => medium (nota)
    - Caso contrário => info
    Retorna (severity, mensagem principal, nota opcional)
    """
    xfo = _get_header(lines, "X-Frame-Options")
    if not xfo:
        return "medium", "X-Frame-Options ausente", ""
    note = ""
    lcx = xfo.lower()
    if "allow" in lcx and "sameorigin" not in lcx and "deny" not in lcx:
        note = "Política possivelmente permissiva (considere DENY ou SAMEORIGIN)"
        return "medium", f"X-Frame-Options: {xfo}", note
    return "info", f"X-Frame-Options: {xfo}", ""

def _check_csp(lines: List[str]) -> Tuple[str, str, List[str]]:
    """
    - Ausente => high (alinhado ao curl_headers)
    - Presente => info; se detectar diretivas permissivas ('unsafe-inline'/'unsafe-eval' ou '*'), adiciona observação (low informativo)
    """
    csp = _get_header(lines, "Content-Security-Policy")
    notes: List[str] = []
    if not csp:
        return "high", "CSP ausente", notes
    msg = f"Content-Security-Policy: {csp[:200]}{'...' if len(csp) > 200 else ''}"
    lc = csp.lower()
    if "'unsafe-inline'" in lc or "'unsafe-eval'" in lc or "*" in lc:
        notes.append("Diretivas permissivas detectadas ('unsafe-inline'/'unsafe-eval' ou '*')")
    return "info", msg, notes

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    cfg (configs/sec_headers_extra.json):
    { "timeout": 15 }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))

    with Timer() as t:
        raw = _curl_head(target, timeout)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    # Comando equivalente (para exibir nos itens)
    base_cmd = f"curl -sS -I -L -m {timeout} {target}"

    def make_item(uuid: str, result: str, severity: str, item_name: str) -> Dict[str, Any]:
        return {
            "scan_item_uuid": uuid,
            "result": result,
            "analysis_ai": ai_fn("SecHeadersExtra", uuid, result),
            "severity": severity,
            "duration": t.duration,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": item_name,
            "command": base_cmd
        }

    items: List[Dict[str, Any]] = []

    # Cache Headers (Cache-Control/Pragma/Expires)
    sev_cache, msg_cache = _check_cache(lines)
    items.append(make_item(
        UUID_043_CACHE,
        msg_cache,
        sev_cache,
        "Cache Headers"
    ))

    # Referrer-Policy
    sev_ref, msg_ref = _check_referrer_policy(lines)
    items.append(make_item(
        UUID_041_REFERRER,
        msg_ref,
        sev_ref,
        "Referrer-Policy"
    ))

    # Permissions-Policy
    sev_perm, msg_perm = _check_permissions_policy(lines)
    items.append(make_item(
        UUID_042_PERMISSIONS,
        msg_perm,
        sev_perm,
        "Permissions-Policy"
    ))

    # X-Frame-Options
    sev_xfo, msg_xfo, note_xfo = _check_xfo(lines)
    result_xfo = msg_xfo if not note_xfo else f"{msg_xfo}; {note_xfo}"
    items.append(make_item(
        UUID_031_XFO,
        result_xfo,
        sev_xfo,
        "X-Frame-Options Header"
    ))

    # Content-Security-Policy
    sev_csp, msg_csp, notes_csp = _check_csp(lines)
    result_csp = msg_csp if not notes_csp else f"{msg_csp}; " + "; ".join(notes_csp)
    items.append(make_item(
        UUID_032_CSP,
        result_csp,
        sev_csp,
        "Content-Security-Policy (CSP) Header"
    ))

    return {
        "plugin": "SecHeadersExtra",
        "plugin_uuid": "uuid-sec-headers-extra",
        "file_name": "sec_headers_extra.py",
        "description": "Performs additional checks on common HTTP security headers using curl, aligned with curl_headers output format.",
        "category": "Client-Side Testing",
        "result": items
    }