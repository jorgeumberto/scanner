# plugins/cache_control_auth.py
from typing import Dict, Any, List, Tuple
from urllib.parse import urljoin
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "cache_control_auth"
PLUGIN_CONFIG_ALIASES = ["cache_auth", "cachecontrol"]

# (21) Cache-Control/Pragma para conteúdo sensível
UUID_021 = "uuid-021-cache-control-auth"

# Referência OWASP (Cache e Conteúdo Sensível)
REFERENCE_URL = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"

def _fetch_headers(url: str, timeout: int) -> List[str]:
    """
    Segue redirects e captura apenas os cabeçalhos DA ÚLTIMA RESPOSTA (após -L).
    Retorna a lista de linhas de header do último bloco.
    """
    cmd = f'curl -sS -L --max-redirs 3 -m {timeout} -o /dev/null -D - "{url}"'
    raw = run_cmd(["bash", "-lc", cmd], timeout=timeout + 2) or ""
    lines = [ln.rstrip("\r\n") for ln in raw.splitlines() if ln.strip()]

    blocks: List[List[str]] = []
    cur: List[str] = []
    for ln in lines:
        # Começo de um novo bloco de resposta
        if ln.upper().startswith("HTTP/"):
            if cur:
                blocks.append(cur)
            cur = [ln]
        else:
            if cur:
                cur.append(ln)
            else:
                # Linhas antes do primeiro HTTP/.. (raro) - ignore
                pass
    if cur:
        blocks.append(cur)
    return blocks[-1] if blocks else []

def _parse_headers(lines: List[str]) -> Tuple[str, Dict[str, List[str]]]:
    """
    Retorna (status_code_str, headers_dict) com:
    - nomes em lower()
    - preserva múltiplos valores (lista)
    """
    status = "?"
    headers: Dict[str, List[str]] = {}
    for i, ln in enumerate(lines):
        if i == 0 and ln.upper().startswith("HTTP/"):
            parts = ln.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = parts[1]
            continue
        if ":" in ln:
            name, val = ln.split(":", 1)
            key = name.strip().lower()
            v = val.strip()
            headers.setdefault(key, []).append(v)
    return status, headers

def _join_first(headers: Dict[str, List[str]], name: str) -> str:
    vals = headers.get(name.lower(), [])
    return vals[0] if vals else ""

def _all(headers: Dict[str, List[str]], name: str) -> List[str]:
    return headers.get(name.lower(), []) or []

def _score(url: str, status: str, headers: Dict[str, List[str]]) -> Tuple[str, List[str]]:
    """
    Regras de avaliação:
      - Quando há Set-Cookie (conteúdo provavelmente autenticado/sensível):
          * medium -> ausência de Cache-Control/Pragma
          * medium -> Cache-Control contém 'public'
          * low    -> possui CC/Pragma, mas sem 'no-store' e sem 'private'
          * info   -> possui 'no-store' ou 'private'
      - Quando NÃO há Set-Cookie => info (checagem informativa)
    """
    evid: List[str] = [f"URL: {url}", f"Status: {status}"]
    cc_raw   = _join_first(headers, "cache-control")
    pragma   = _join_first(headers, "pragma")
    cookies  = _all(headers, "set-cookie")
    ck_count = len(cookies)

    if ck_count:
        preview = cookies[0][:120] + ("..." if len(cookies[0]) > 120 else "")
        evid.append(f"Set-Cookie (x{ck_count}): {preview}")
    else:
        evid.append("Set-Cookie: —")

    if cc_raw:
        evid.append(f"Cache-Control: {cc_raw}")
    if pragma:
        evid.append(f"Pragma: {pragma}")

    sev = "info"
    if ck_count:
        cc_low = (cc_raw or "").lower()
        # Divide diretrizes por vírgula; remove espaços extras
        directives = {d.strip() for d in cc_low.split(",") if d.strip()}
        has_no_store = "no-store" in directives
        has_private  = "private" in directives
        has_no_cache = "no-cache" in directives
        has_public   = "public" in directives
        has_any_cc   = bool(cc_raw or pragma)

        if not has_any_cc:
            sev = "medium"
            evid.append("Risco: Set-Cookie sem Cache-Control/Pragma (pode haver cache indevido).")
        elif has_public:
            sev = "medium"
            evid.append("Risco: Cache-Control contém 'public' em resposta com Set-Cookie.")
        elif not (has_no_store or has_private):
            sev = "low"
            msg = "Sugestão: use 'no-store' e/ou 'private' para respostas autenticadas."
            if has_no_cache:
                msg += " Observação: 'no-cache' sozinho não impede armazenamento."
            evid.append(msg)
        else:
            evid.append("OK: cabeçalhos indicam não armazenamento ('no-store'/'private').")
    else:
        evid.append("Informação: sem Set-Cookie; checagem apenas informativa.")

    return sev, evid

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg opcional (configs/cache_control_auth.json):
    {
      "timeout": 15,
      "paths": ["/", "/dashboard", "/account", "/profile"]
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    paths: List[str] = cfg.get("paths") or ["/", "/dashboard", "/account", "/profile"]

    results: List[Dict[str, Any]] = []
    with Timer() as _t_total:
        for p in paths:
            url = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            with Timer() as t_one:
                # Busca e analisa headers finais
                lines = _fetch_headers(url, timeout)
                status, headers = _parse_headers(lines)
                sev, evid = _score(url, status, headers)
                text = "\n".join(f"- {e}" for e in evid)

            # Comando reproduzível para este path
            command = f'curl -sS -L --max-redirs 3 -m {timeout} -o /dev/null -D - "{url}"'

            results.append({
                "scan_item_uuid": f"{UUID_021}-{p.replace('/', '_').strip('_')}",
                "item_name": f"Cache headers: {p}",
                "result": text,
                "analysis_ai": ai_fn("CacheControlAuth", UUID_021, text),
                "severity": sev,
                "duration": t_one.duration,
                "auto": True,
                "reference": REFERENCE_URL,
                "command": command
            })

    return {
        "plugin": "CacheControlAuth",
        "plugin_uuid": UUID_021,
        "file_name": "cache_control_auth.py",
        "description": "Valida Cache-Control/Pragma em respostas que definem cookies, evitando cache indevido de conteúdo autenticado.",
        "category": "HTTP Security Headers",
        "result": results
    }