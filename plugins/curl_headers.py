from utils import run_cmd, Timer
from typing import Dict, Any, List

# UUIDs dos itens na tabela scans_itens
UUIDS = {
    1:  "uuid-001-server",  # Banner do servidor exposto (Server)
    2:  "uuid-002-powered-by",  # Tecnologia exposta (X-Powered-By)
    19: "uuid-019-hsts",  # HSTS presente
    20: "uuid-020-xcontent",  # X-Content-Type-Options presente
    31: "uuid-031-xframe",  # X-Frame-Options presente
    32: "uuid-032-csp",  # Content-Security-Policy presente (CSP)
    33: "uuid-033-cors",  # CORS configurado
    34: "uuid-034-mimesniff",  # Proteção contra MIME sniffing
    38: "uuid-038-cookie-sec",  # Cookies Secure
    39: "uuid-039-cookie-httponly",  # Cookies HttpOnly
    40: "uuid-040-cookie-samesite",  # Cookies SameSite
}

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

    def make_item(uuid: str, result: str, severity: str) -> Dict[str, Any]:
        return {
            "plugin_uuid": uuid,           # mantido
            "scan_item_uuid": uuid,        # novo → já sai no JSON final
            "result": result,
            "analysis_ai": ai_fn("CurlHeaders", uuid, result),
            "severity": severity,
            "duration": t.duration,
            "auto": True
        }

    items: List[Dict[str, Any]] = []

    # 1) Server
    server = headers.get("server")
    items.append(make_item(UUIDS[1], f"Server: {server}" if server else "Header Server ausente", "low" if server else "info"))

    # 2) X-Powered-By
    xpb = headers.get("x-powered-by")
    items.append(make_item(UUIDS[2], f"X-Powered-By: {xpb}" if xpb else "X-Powered-By ausente", "low" if xpb else "info"))

    # 19) HSTS
    hsts = headers.get("strict-transport-security")
    items.append(make_item(UUIDS[19], f"HSTS: {hsts}" if hsts else "HSTS ausente", "medium" if not hsts else "info"))

    # 20) X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    items.append(make_item(UUIDS[20], f"X-Content-Type-Options: {xcto}" if xcto else "X-Content-Type-Options ausente", "medium" if not xcto else "info"))

    # 31) X-Frame-Options
    xfo = headers.get("x-frame-options")
    items.append(make_item(UUIDS[31], f"X-Frame-Options: {xfo}" if xfo else "X-Frame-Options ausente", "medium" if not xfo else "info"))

    # 32) CSP
    csp = headers.get("content-security-policy")
    items.append(make_item(UUIDS[32], f"Content-Security-Policy: {csp}" if csp else "CSP ausente", "high" if not csp else "info"))

    # 33) CORS
    cors = headers.get("access-control-allow-origin")
    severity = "high" if cors == "*" else ("info" if cors else "low")
    items.append(make_item(UUIDS[33], f"Access-Control-Allow-Origin: {cors}" if cors else "CORS ausente", severity))

    # 34) Proteção contra MIME sniffing
    xcto2 = headers.get("x-content-type-options")
    items.append(make_item(UUIDS[34], f"X-Content-Type-Options: {xcto2}" if xcto2 else "Proteção MIME ausente", "medium" if not xcto2 else "info"))

    # 38) Cookies Secure
    has_secure = "secure" in cookies.lower() if cookies else False
    items.append(make_item(UUIDS[38], cookies if cookies else "sem Set-Cookie", "medium" if cookies and not has_secure else "info"))

    # 39) Cookies HttpOnly
    has_httponly = "httponly" in cookies.lower() if cookies else False
    items.append(make_item(UUIDS[39], cookies if cookies else "sem Set-Cookie", "medium" if cookies and not has_httponly else "info"))

    # 40) Cookies SameSite
    has_samesite = "samesite" in cookies.lower() if cookies else False
    items.append(make_item(UUIDS[40], cookies if cookies else "sem Set-Cookie", "low" if cookies and not has_samesite else "info"))

    return {"plugin": "CurlHeaders", "result": items}
