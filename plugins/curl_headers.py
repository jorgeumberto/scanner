from utils import run_cmd, Timer
from typing import Dict, Any, List

def parse_headers(raw: str) -> Dict[str, Any]:
    headers = {}
    for line in raw.splitlines():
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return headers

def run_plugin(target: str, ai_fn) -> Dict[str, Any]:
    with Timer() as t:
        raw = run_cmd(["curl", "-sSI", target], timeout=30)

    headers = parse_headers(raw)
    cookies = headers.get("set-cookie", "")

    def make_item(uuid: str, result: str, severity: str, item_name:str) -> Dict[str, Any]:
        return {
            "scan_item_uuid": uuid,        # novo → já sai no JSON final
            "result": result,
            "analysis_ai": ai_fn("CurlHeaders", uuid, result),
            "severity": severity,
            "duration": t.duration,
            "auto": True,
            "reference": "https://owasp.org/www-project-secure-headers/",
            "item_name": item_name
        }

    items: List[Dict[str, Any]] = []

    # 1) Server
    server = headers.get("server")
    items.append(make_item("uuid-001-server", f"Server: {server}" if server else "Header Server ausente", "low" if server else "info", "Server Header"))

    # 2) X-Powered-By
    xpb = headers.get("x-powered-by")
    items.append(make_item("uuid-002-powered-by", f"X-Powered-By: {xpb}" if xpb else "X-Powered-By ausente", "low" if xpb else "info", "X-Powered-By Header"))

    # 19) HSTS
    hsts = headers.get("strict-transport-security")
    items.append(make_item("uuid-019-hsts", f"HSTS: {hsts}" if hsts else "HSTS ausente", "medium" if not hsts else "info", "HTTP Strict Transport Security (HSTS)"))

    # 20) X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    items.append(make_item("uuid-020-xcontent", f"X-Content-Type-Options: {xcto}" if xcto else "X-Content-Type-Options ausente", "medium" if not xcto else "info", "X-Content-Type-Options Header"))

    # 31) X-Frame-Options
    xfo = headers.get("x-frame-options")
    items.append(make_item("uuid-031-xframe", f"X-Frame-Options: {xfo}" if xfo else "X-Frame-Options ausente", "medium" if not xfo else "info", "X-Frame-Options Header"))

    # 32) CSP
    csp = headers.get("content-security-policy")
    items.append(make_item("uuid-032-csp", f"Content-Security-Policy: {csp}" if csp else "CSP ausente", "high" if not csp else "info", "Content-Security-Policy (CSP) Header"))

    # 33) CORS
    cors = headers.get("access-control-allow-origin")
    severity = "high" if cors == "*" else ("info" if cors else "low")
    items.append(make_item("uuid-033-cors", f"Access-Control-Allow-Origin: {cors}" if cors else "CORS ausente", severity, "Access-Control-Allow-Origin Header"))

    # 34) Proteção contra MIME sniffing
    xcto2 = headers.get("x-content-type-options")
    items.append(make_item("uuid-034-mimesniff", f"X-Content-Type-Options: {xcto2}" if xcto2 else "Proteção MIME ausente", "medium" if not xcto2 else "info", "MIME Sniffing Protection"))

    # 38) Cookies Secure
    has_secure = "secure" in cookies.lower() if cookies else False
    items.append(make_item("uuid-038-cookie-sec", cookies if cookies else "Sem Set-Cookies Secure", "medium" if cookies and not has_secure else "info", "Cookies Secure Flag"))

    # 39) Cookies HttpOnly
    has_httponly = "httponly" in cookies.lower() if cookies else False
    items.append(make_item("uuid-039-cookie-httponly", cookies if cookies else "Sem Cookies-HttpOnly", "medium" if cookies and not has_httponly else "info", "Cookies HttpOnly Flag"))

    # 40) Cookies SameSite
    has_samesite = "samesite" in cookies.lower() if cookies else False
    items.append(make_item("uuid-040-cookie-samesite", cookies if cookies else "Sem Set-Cookies-SameSite", "low" if cookies and not has_samesite else "info", "Cookies SameSite Attribute"))

    return {
        "plugin": "CurlHeaders", 
        "plugin_uuid": "uuid-curl-headers",
        "file_name": "curl_headers.py",
        "description": "Uses curl to get and parse HTTP headers from a web server.",
        "category": "Information Gathering",
        "result": items
    }

