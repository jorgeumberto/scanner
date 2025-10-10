# plugins/cookie_flags_extra.py
from typing import Dict, Any, List, Tuple, Optional
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "ssrf_probe"
PLUGIN_CONFIG_ALIASES = ["cookies_extra", "cookie_hardening"]

# UUIDs próprios (sem relação com outros plugins)
UUID_ITEM_COOKIES = "uuid-cookie-flags-extra-item"
REFERENCE_URL = "https://owasp.org/www-project-secure-headers/"

def _curl_head(url: str, timeout: int) -> str:
    # -I para headers; -L segue redirects; -m controla timeout
    return run_cmd(["curl", "-sS", "-I", "-L", "-m", str(timeout), url], timeout=timeout + 2)

def _get_all_headers(lines: List[str], name: str) -> List[str]:
    name_low = name.lower()
    vals: List[str] = []
    for ln in lines:
        if ln.lower().startswith(name_low + ":"):
            vals.append(ln.split(":", 1)[1].strip())
    return vals

def _parse_cookie(kv: str) -> Dict[str, Any]:
    """
    Divide "name=value; Attr1; Attr2=val; ..." em componentes normalizados.
    Retorna: { name, value, attrs: {attr_lower: original_value_or_true}, raw }
    """
    parts = [p.strip() for p in kv.split(";")]
    name_val = parts[0] if parts else ""
    name = ""
    value = ""
    if "=" in name_val:
        name, value = name_val.split("=", 1)
        name = name.strip()
        value = value.strip()
    attrs: Dict[str, Any] = {}
    for p in parts[1:]:
        if not p:
            continue
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.strip().lower()] = True
    return {"name": name, "value": value, "attrs": attrs, "raw": kv}

def _size_bytes(s: str) -> int:
    try:
        return len(s.encode("utf-8"))
    except Exception:
        return len(s)

def _analyze_cookies(raw_list: List[str]) -> Tuple[str, str]:
    """
    Retorna (severity, mensagem consolidada).
    Severidade:
      - medium se flag crítica ausente (Secure/HttpOnly/SameSite) ou incoerência (SameSite=None sem Secure) ou conflito por nome.
      - info se todos ok.
    """
    if not raw_list:
        return "info", "Sem Set-Cookie"

    findings: List[str] = []
    global_issues = False
    cookie_by_name: Dict[str, List[Dict[str, Any]]] = {}

    parsed = [_parse_cookie(ck) for ck in raw_list]

    for idx, ck in enumerate(parsed, start=1):
        low_attrs = {k.lower(): v for k, v in ck["attrs"].items()}
        raw = ck["raw"]
        lname = ck["name"].lower() if ck["name"] else ""
        cookie_by_name.setdefault(lname, []).append(ck)

        has_secure = "secure" in low_attrs
        has_httponly = "httponly" in low_attrs
        samesite = str(low_attrs.get("samesite", "") or "").lower()
        has_samesite = "samesite" in low_attrs

        missing = []
        if not has_secure:
            missing.append("Secure")
        if not has_httponly:
            missing.append("HttpOnly")
        if not has_samesite:
            missing.append("SameSite")

        if samesite == "none" and not has_secure:
            missing.append("Secure (obrigatório com SameSite=None)")

        # Prefix rules (RFC 6265bis)
        if ck["name"].startswith("__Host-"):
            conds = []
            if not has_secure: conds.append("Secure")
            if "domain" in low_attrs: conds.append("sem Domain")
            path = str(low_attrs.get("path", "") or "")
            if path != "/" and path is not True:
                conds.append("Path=/")
            if conds:
                missing.append("__Host- requer: " + ", ".join(conds))
        if ck["name"].startswith("__Secure-") and not has_secure:
            missing.append("__Secure- requer Secure")

        # Notas informativas
        has_max_age = "max-age" in low_attrs
        has_expires = "expires" in low_attrs
        notes = []
        if not has_max_age and not has_expires:
            notes.append("sem Max-Age/Expires (possível cookie de sessão)")
        if "domain" in low_attrs:
            dom = low_attrs.get("domain")
            if dom in [".", "", None, True]:
                notes.append("Domain suspeito")
        if "partitioned" in low_attrs:
            notes.append("Partitioned (CHIPS) detectado")
        if "sameparty" in low_attrs:
            notes.append("SameParty detectado (experimental/obsoleto)")

        size_b = _size_bytes(raw)
        if size_b > 4096:
            notes.append(f"tamanho {size_b}B (>4096B)")

        # Consolidação por linha
        line = []
        if missing:
            global_issues = True
            line.append(f"Cookie#{idx} sem: {', '.join(missing)}")
        else:
            line.append(f"Cookie#{idx} ok (Secure/HttpOnly/SameSite)")

        if notes:
            line.append(" | " + "; ".join(notes))
        line.append(f" | {raw}")
        findings.append("".join(line))

    # Conflitos por nome (múltiplos Set-Cookie do mesmo cookie)
    for name, lst in cookie_by_name.items():
        if not name or len(lst) < 2:
            continue
        def attr_sig(c: Dict[str, Any]) -> str:
            a = {k: v for k, v in c["attrs"].items()}
            return "|".join(sorted(f"{k}={a[k]}" for k in a))
        sigs = {attr_sig(c) for c in lst}
        if len(sigs) > 1:
            global_issues = True
            findings.append(f"Conflito: múltiplos Set-Cookie para '{name}' com atributos diferentes")

    severity = "medium" if global_issues else "info"
    message = ";\n".join(findings) if findings else "Sem achados relevantes em cookies"
    return severity, message

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    cfg (configs/cookie_flags_extra.json):
    { "timeout": 15 }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))

    with Timer() as t:
        raw = _curl_head(target, timeout)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    cookies_raw = _get_all_headers(lines, "Set-Cookie")

    sev, msg = _analyze_cookies(cookies_raw)
    base_cmd = f"curl -sS -I -L -m {timeout} {target}"

    item = {
        "scan_item_uuid": UUID_ITEM_COOKIES,
        "result": msg,
        "analysis_ai": ai_fn("CookieFlagsExtra", UUID_ITEM_COOKIES, msg),
        "severity": sev,
        "duration": t.duration,
        "auto": True,
        "reference": REFERENCE_URL,
        "item_name": "Cookie Flags & Integrity",
        "command": base_cmd
    }

    return {
        "plugin": "CookieFlagsExtra",
        "plugin_uuid": "uuid-cookie-flags-extra",
        "file_name": "cookie_flags_extra.py",
        "description": "Deep analysis of Set-Cookie attributes (flags, coherence, conflicts, size, prefixes).",
        "category": "Client-Side Testing",
        "result": [item]
    }