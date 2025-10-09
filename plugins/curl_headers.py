from utils import run_cmd, Timer
from typing import Dict, Any, List, Union, Optional

HeaderValue = Union[str, List[str]]
HeadersDict = Dict[str, HeaderValue]

def parse_headers(raw: str) -> HeadersDict:
    """
    Converte o header bruto em dicionário case-insensitive, preservando múltiplos valores.
    - Chaves minúsculas.
    - Se uma chave aparecer mais de uma vez (ex.: set-cookie), guarda como lista.
    """
    headers: HeadersDict = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()

        if key in headers:
            # promover para lista se necessário
            if isinstance(headers[key], list):
                headers[key].append(val)
            else:
                headers[key] = [headers[key], val]
        else:
            headers[key] = val
    return headers

def get_one(headers: HeadersDict, name: str) -> Optional[str]:
    """
    Retorna um único valor para o header, se houver múltiplos retorna o primeiro.
    """
    v = headers.get(name.lower())
    if v is None:
        return None
    if isinstance(v, list):
        return v[0] if v else None
    return v

def get_all(headers: HeadersDict, name: str) -> List[str]:
    """
    Retorna todos os valores do header como lista.
    """
    v = headers.get(name.lower())
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]

def join_values(v: HeaderValue) -> str:
    if isinstance(v, list):
        return "; ".join(v)
    return v

def run_curl_headers(target: str, extra: List[str] = None, method: str = "HEAD") -> str:
    """
    Executa curl para obter apenas headers.
    - Usa -I para HEAD por padrão; para OPTIONS usa -X OPTIONS.
    - extra permite enviar headers adicionais, ex.: Origin.
    """
    extra = extra or []
    cmd = ["curl", "-sS", "-D", "-", "-o", "/dev/null"]
    if method and method.upper() != "HEAD":
        cmd += ["-X", method.upper()]
    else:
        cmd = ["curl", "-sS", "-I"]  # -I já faz HEAD, mais simples

    # Acrescenta headers extras
    for h in extra:
        cmd += ["-H", h]
    cmd += [target]
    return run_cmd(cmd, timeout=30)

def run_plugin(target: str, ai_fn) -> Dict[str, Any]:
    # 1) Requisição principal (HEAD)
    with Timer() as t_main:
        raw_main = run_curl_headers(target)

    headers_main = parse_headers(raw_main)

    # 2) Requisição GET com Origin (para avaliar CORS prático)
    origin_test = "http://evil.local"
    with Timer() as t_cors_get:
        raw_cors_get = run_curl_headers(target, extra=[f"Origin: {origin_test}"], method="GET")
    headers_cors_get = parse_headers(raw_cors_get)

    # 3) Preflight OPTIONS com Origin e Access-Control-Request-Method
    with Timer() as t_cors_opt:
        raw_cors_opt = run_curl_headers(
            target,
            extra=[f"Origin: {origin_test}", "Access-Control-Request-Method: GET"],
            method="OPTIONS"
        )
    headers_cors_opt = parse_headers(raw_cors_opt)

    # Helper para criar cada item com command incluso (comando adequado ao teste)
    def make_item(uuid: str, result: str, severity: str, item_name: str, command: str, duration: float) -> Dict[str, Any]:
        return {
            "scan_item_uuid": uuid,
            "result": result,
            "analysis_ai": ai_fn("CurlHeaders", uuid, result),
            "severity": severity,
            "duration": duration,
            "auto": True,
            "reference": "https://owasp.org/www-project-secure-headers/",
            "item_name": item_name,
            "command": command
        }

    items: List[Dict[str, Any]] = []

    # --------- Itens base (HEAD) ---------
    base_cmd = "curl -sS -I " + target

    # Server
    server = get_one(headers_main, "server")
    items.append(make_item(
        "uuid-001-server",
        f"Server: {server}" if server else "Header Server ausente",
        "low" if server else "info",
        "Server Header",
        base_cmd,
        t_main.duration
    ))

    # X-Powered-By
    xpb = get_one(headers_main, "x-powered-by")
    items.append(make_item(
        "uuid-002-powered-by",
        f"X-Powered-By: {xpb}" if xpb else "X-Powered-By ausente",
        "low" if xpb else "info",
        "X-Powered-By Header",
        base_cmd,
        t_main.duration
    ))

    # HSTS
    hsts = get_one(headers_main, "strict-transport-security")
    items.append(make_item(
        "uuid-019-hsts",
        f"HSTS: {hsts}" if hsts else "HSTS ausente",
        "medium" if not hsts else "info",
        "HTTP Strict Transport Security (HSTS)",
        base_cmd,
        t_main.duration
    ))

    # X-Content-Type-Options (apenas uma vez)
    xcto = get_one(headers_main, "x-content-type-options")
    items.append(make_item(
        "uuid-020-xcontent",
        f"X-Content-Type-Options: {xcto}" if xcto else "X-Content-Type-Options ausente",
        "medium" if not xcto else "info",
        "X-Content-Type-Options Header",
        base_cmd,
        t_main.duration
    ))

    # X-Frame-Options
    xfo = get_one(headers_main, "x-frame-options")
    items.append(make_item(
        "uuid-031-xframe",
        f"X-Frame-Options: {xfo}" if xfo else "X-Frame-Options ausente",
        "medium" if not xfo else "info",
        "X-Frame-Options Header",
        base_cmd,
        t_main.duration
    ))

    # CSP
    csp = get_one(headers_main, "content-security-policy")
    items.append(make_item(
        "uuid-032-csp",
        f"Content-Security-Policy: {csp}" if csp else "CSP ausente",
        "high" if not csp else "info",
        "Content-Security-Policy (CSP) Header",
        base_cmd,
        t_main.duration
    ))

    # CORS (sem Origin)
    acao_main = get_one(headers_main, "access-control-allow-origin")
    severity_cors_main = "high" if acao_main == "*" else ("info" if not acao_main else "low")
    items.append(make_item(
        "uuid-033-cors",
        f"Access-Control-Allow-Origin: {acao_main}" if acao_main else "CORS ausente (sem Origin)",
        severity_cors_main,
        "Access-Control-Allow-Origin Header",
        base_cmd,
        t_main.duration
    ))

    # Referrer-Policy
    refpol = get_one(headers_main, "referrer-policy")
    items.append(make_item(
        "uuid-041-referrer-policy",
        f"Referrer-Policy: {refpol}" if refpol else "Referrer-Policy ausente",
        "low" if not refpol else "info",
        "Referrer-Policy",
        base_cmd,
        t_main.duration
    ))

    # Permissions-Policy
    permpol = get_one(headers_main, "permissions-policy")
    items.append(make_item(
        "uuid-042-permissions-policy",
        f"Permissions-Policy: {permpol}" if permpol else "Permissions-Policy ausente",
        "low" if not permpol else "info",
        "Permissions-Policy",
        base_cmd,
        t_main.duration
    ))

    # Cache-Control / Pragma / Expires (indicativo; severidade baixa)
    cache_control = get_one(headers_main, "cache-control")
    pragma = get_one(headers_main, "pragma")
    expires = get_one(headers_main, "expires")

    cache_msg_parts = []
    if cache_control: cache_msg_parts.append(f"Cache-Control: {cache_control}")
    if pragma: cache_msg_parts.append(f"Pragma: {pragma}")
    if expires: cache_msg_parts.append(f"Expires: {expires}")
    cache_msg = "; ".join(cache_msg_parts) if cache_msg_parts else "Cabeçalhos de cache ausentes"

    items.append(make_item(
        "uuid-043-cache",
        cache_msg,
        "low" if not cache_control else "info",
        "Cache Headers",
        base_cmd,
        t_main.duration
    ))

    # Content-Type (informativo)
    ctype = get_one(headers_main, "content-type")
    items.append(make_item(
        "uuid-044-content-type",
        f"Content-Type: {ctype}" if ctype else "Content-Type ausente",
        "info",
        "Content-Type Header",
        base_cmd,
        t_main.duration
    ))

    # --------- Cookies (múltiplos Set-Cookie) ---------
    cookies_all = get_all(headers_main, "set-cookie")
    if cookies_all:
        insecure_details: List[str] = []
        for idx, ck in enumerate(cookies_all, start=1):
            low = ck.lower()
            has_secure = "secure" in low
            has_httponly = "httponly" in low
            has_samesite = "samesite=" in low
            missing = []
            if not has_secure: missing.append("Secure")
            if not has_httponly: missing.append("HttpOnly")
            if not has_samesite: missing.append("SameSite")
            if missing:
                insecure_details.append(f"Cookie#{idx} sem: {', '.join(missing)} | {ck}")

        if insecure_details:
            items.append(make_item(
                "uuid-038-040-cookies",
                ";\n".join(insecure_details),
                # Se qualquer flag crítica ausente, marcamos medium
                "medium",
                "Cookies Flags (Secure/HttpOnly/SameSite)",
                base_cmd,
                t_main.duration
            ))
        else:
            items.append(make_item(
                "uuid-038-040-cookies",
                "Todos os cookies com Secure, HttpOnly e SameSite",
                "info",
                "Cookies Flags (Secure/HttpOnly/SameSite)",
                base_cmd,
                t_main.duration
            ))
    else:
        items.append(make_item(
            "uuid-038-040-cookies",
            "Sem Set-Cookie",
            "info",
            "Cookies Flags (Secure/HttpOnly/SameSite)",
            base_cmd,
            t_main.duration
        ))

    # --------- CORS prático com Origin (GET) ---------
    cors_get_cmd = f'curl -sS -D - -o /dev/null -H "Origin: {origin_test}" {target}'
    acao_get = get_one(headers_cors_get, "access-control-allow-origin")
    acc_get = get_one(headers_cors_get, "access-control-allow-credentials")
    # Severidade prática:
    # - HIGH: ACAO == "*" e ACC == "true" (combinação perigosa) OU reflete origem e ACC true
    # - LOW: ACAO presente sem credenciais
    # - INFO: ausente
    sev_cors_get = "info"
    if acao_get:
        if (acao_get.strip() == "*" and (acc_get or "").lower() == "true") or (acao_get.strip() == origin_test and (acc_get or "").lower() == "true"):
            sev_cors_get = "high"
        elif acao_get.strip() == "*":
            sev_cors_get = "low"
        else:
            # origem específica sem credenciais
            sev_cors_get = "low"
    items.append(make_item(
        "uuid-045-cors-origin-get",
        f'GET c/ Origin => ACAO="{acao_get}", ACC="{acc_get}"' if acao_get or acc_get else "GET c/ Origin => CORS ausente",
        sev_cors_get,
        "CORS (GET com Origin)",
        cors_get_cmd,
        t_cors_get.duration
    ))

    # --------- CORS preflight (OPTIONS) ---------
    cors_opt_cmd = f'curl -sS -D - -o /dev/null -X OPTIONS -H "Origin: {origin_test}" -H "Access-Control-Request-Method: GET" {target}'
    acao_opt = get_one(headers_cors_opt, "access-control-allow-origin")
    acam_opt = get_one(headers_cors_opt, "access-control-allow-methods")
    acah_opt = get_one(headers_cors_opt, "access-control-allow-headers")
    acc_opt = get_one(headers_cors_opt, "access-control-allow-credentials")

    sev_cors_opt = "info"
    if acao_opt:
        if (acao_opt.strip() == "*" and (acc_opt or "").lower() == "true") or (acao_opt.strip() == origin_test and (acc_opt or "").lower() == "true"):
            sev_cors_opt = "high"
        elif acao_opt.strip() == "*":
            sev_cors_opt = "low"
        else:
            sev_cors_opt = "low"

    result_opt_parts = []
    if acao_opt: result_opt_parts.append(f'ACAO="{acao_opt}"')
    if acam_opt: result_opt_parts.append(f'ACAM="{acam_opt}"')
    if acah_opt: result_opt_parts.append(f'ACAH="{acah_opt}"')
    if acc_opt:  result_opt_parts.append(f'ACC="{acc_opt}"')
    result_opt = "OPTIONS preflight => " + (", ".join(result_opt_parts) if result_opt_parts else "CORS ausente")

    items.append(make_item(
        "uuid-046-cors-origin-options",
        result_opt,
        sev_cors_opt,
        "CORS (OPTIONS preflight)",
        cors_opt_cmd,
        t_cors_opt.duration
    ))

    return {
        "plugin": "CurlHeaders",
        "plugin_uuid": "uuid-curl-headers",
        "file_name": "curl_headers.py",
        "description": "Uses curl to get and parse HTTP headers from a web server, including CORS tests.",
        "category": "Client-Side Testing",
        "result": items
    }