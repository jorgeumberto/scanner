from typing import Dict, Any, List, Tuple, Set, Optional
from urllib.parse import urljoin
from utils import run_cmd as _run_cmd_shadow
import time

# === injected: capture executed shell commands for tagging ===
try:
    from utils import run_cmd as __run_cmd_orig  # keep original
except Exception as _e_inject:
    __run_cmd_orig = None

EXEC_CMDS = []  # type: list[str]

def run_cmd(cmd, timeout=None):
    """
    Wrapper injected to capture the exact command used.
    Keeps the original behavior, but records the command string.
    """
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    EXEC_CMDS.append(cmd_str)
    if __run_cmd_orig is None:
        raise RuntimeError("run_cmd original não disponível para execução.")
    return __run_cmd_orig(cmd, timeout=timeout)
# === end injected ===


# ====== UUIDs (ajuste se tiver IDs próprios para “métodos HTTP”) ======
UUIDS = {
    201: "uuid-201-options-allow",     # OPTIONS / Allow header (resumo)
    202: "uuid-202-trace-enabled",     # TRACE habilitado
    203: "uuid-203-put-allowed",       # PUT permitido (via Allow)
    204: "uuid-204-delete-allowed",    # DELETE permitido (via Allow)
    205: "uuid-205-patch-allowed",     # PATCH permitido (via Allow)
    206: "uuid-206-propfind-allowed",  # PROPFIND (WebDAV) permitido (via Allow)
    207: "uuid-207-mkcol-allowed",     # MKCOL (WebDAV) permitido (via Allow)
    208: "uuid-208-move-allowed",      # MOVE (WebDAV) permitido (via Allow)
    209: "uuid-209-copy-allowed",      # COPY (WebDAV) permitido (via Allow)
    210: "uuid-210-cors-preflight",    # Preflight CORS (Access-Control-Allow-Methods/Origin)
}

# ---------- helpers ----------

def safe_join(base: str, path: str = "") -> str:
    if not base.endswith('/'):
        base = base + '/'
    if path.startswith('/'):
        path = path[1:]
    return urljoin(base, path)

def fetch_headers_for_method(url: str, method: str, extra_headers: Optional[List[str]] = None, max_time: int = 10) -> str:
    """
    Retorna cabeçalhos da resposta (-D -) sem corpo (-o /dev/null), usando o método informado.
    Não segue redirecionamento para não trocar o método (-L trocaria p/ GET em 30x).
    """
    cmd = ["curl", "-sS", "-k", "-D", "-", "-o", "/dev/null", "-X", method, "--max-time", str(max_time), url]
    if extra_headers:
        for h in extra_headers:
            cmd.extend(["-H", h])
    return run_cmd(cmd, timeout=max_time + 5)

def fetch_status_for_method(url: str, method: str, extra_headers: Optional[List[str]] = None, max_time: int = 10) -> int:
    """
    Retorna o código HTTP usando o método informado, sem baixar corpo.
    """
    cmd = ["curl", "-sS", "-k", "-o", "/dev/null", "-w", "%{http_code}", "-X", method, "--max-time", str(max_time), url]
    if extra_headers:
        for h in extra_headers:
            cmd.extend(["-H", h])
    out = run_cmd(cmd, timeout=max_time + 5).strip()
    try:
        return int(out)
    except Exception:
        return 0

def parse_headers(raw: str) -> Dict[str, List[str]]:
    """
    Converte cabeçalhos em dict multi-valor: {header_lower: [val1, ...]}.
    Ignora linhas de status (ex.: "HTTP/1.1 200 OK") e linhas sem ":".
    """
    headers: Dict[str, List[str]] = {}
    for line in raw.splitlines():
        line = line.strip("\r")
        if not line or ":" not in line or line.upper().startswith("HTTP/"):
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        headers.setdefault(key, []).append(val)
    return headers

def parse_allow_methods(headers_raw: str) -> Set[str]:
    """
    Extrai os métodos do(s) cabeçalho(s) Allow e Access-Control-Allow-Methods (se houver).
    """
    headers = parse_headers(headers_raw)
    allow_vals = headers.get("allow", []) + headers.get("access-control-allow-methods", [])
    methods: Set[str] = set()
    for val in allow_vals:
        for m in val.split(","):
            mm = m.strip().upper()
            if mm:
                methods.add(mm)
    return methods

def make_item(uuid: str, result: str, severity: str, duration: float, ai_fn, item_name: str) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": result,
        "analysis_ai": ai_fn("curl_http_methods", uuid, result) if callable(ai_fn) else None,
        "severity": severity,
        "duration": duration,
        "auto": True,
        "item_name": item_name,
            "command": EXEC_CMDS[-1] if EXEC_CMDS else "",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods",
    }

# ---------- checks ----------

def check_options_allow(target: str) -> Tuple[str, str, str]:
    """
    Coleta Allow (se presente) via OPTIONS.
    """
    url = safe_join(target)
    raw = fetch_headers_for_method(url, "OPTIONS")
    methods = sorted(parse_allow_methods(raw)) if raw else []
    if methods:
        return (url,
                f"{url} — OPTIONS/Allow presente: {', '.join(methods)} — Info: cabeçalho informativo; útil para clientes.",
                "info")
    return (url, f"{url} — OPTIONS sem Allow (ou não suportado) — Info: servidor não expõe lista de métodos.", "info")

def check_trace(target: str) -> Tuple[str, str, str]:
    """
    Verifica TRACE diretamente (sem side-effect relevante).
    """
    url = safe_join(target)
    code = fetch_status_for_method(url, "TRACE")
    if code not in (405, 501, 0):
        # Considera habilitado (ex.: 200/401/403/404)
        if code in (401, 403):
            return (url, f"{url} — TRACE HTTP {code} — Risco: método presente porém restrito (ideal desabilitar).", "medium")
        return (url, f"{url} — TRACE HTTP {code} — Risco: método de depuração habilitado; desabilite.", "high")
    return (url, f"{url} — TRACE HTTP {code} — Seguro: método desabilitado (405/501).", "info")

def check_via_allow(method: str, allow_set: Set[str], url: str, sev_when_allowed: str) -> Tuple[str, str, str]:
    """
    Classifica com base apenas no Allow (não executa o método para evitar side-effects).
    """
    if method in allow_set:
        motivo = {
            "high": "Risco: método sensível permitido; garanta autenticação/autorização estritas ou desabilite.",
            "medium": "Atenção: método permitido; valide necessidade e controles.",
            "info": "Info: método permitido.",
        }[sev_when_allowed]
        return (url, f"{url} — Allow contém {method} — {motivo}", sev_when_allowed)
    return (url, f"{url} — Allow não contém {method} — Seguro: método não anunciado.", "info")

def check_cors_preflight(target: str) -> Tuple[str, str, str]:
    """
    Simula um preflight simples (OPTIONS com Origin + Access-Control-Request-Method).
    """
    url = safe_join(target)
    raw = fetch_headers_for_method(
        url, "OPTIONS",
        extra_headers=[
            "Origin: https://example.com",
            "Access-Control-Request-Method: POST",
        ],
    )
    headers = parse_headers(raw)
    acam = ", ".join(headers.get("access-control-allow-methods", [])) or "—"
    acao = ", ".join(headers.get("access-control-allow-origin", [])) or "—"
    if acam != "—" or acao != "—":
        return (url, f"{url} — Preflight respondeu. Access-Control-Allow-Methods: {acam}; Access-Control-Allow-Origin: {acao} — Info.", "info")
    return (url, f"{url} — Preflight sem cabeçalhos ACA* — Info.", "info")

# ---------- plugin ----------
def _resolve_args(args: tuple):
    """
    Aceita chamadas (target, ai_fn) ou (target, config, ai_fn).
    Retorna (config, ai_fn).
    """
    config = None
    ai_fn = None
    if args:
        # Último arg tendencialmente é o ai_fn (callable)
        if callable(args[-1]):
            ai_fn = args[-1]
        # Se houver 2+ args, o primeiro extra costuma ser config
        if len(args) >= 2:
            config = args[0]
        elif len(args) == 1 and not callable(args[0]):
            config = args[0]
    return config, ai_fn

def run_plugin(target: str, *args) -> Dict[str, Any]:
    """
    Compatível com:
      - run_plugin(target, ai_fn)
      - run_plugin(target, config, ai_fn)
    """
    config, ai_fn = _resolve_args(args)

    items: List[Dict[str, Any]] = []

    # 201) OPTIONS / Allow
    t1 = time.perf_counter()
    url, msg, sev = check_options_allow(target)
    items.append(make_item(UUIDS[201], msg, sev, time.perf_counter() - t1, ai_fn, "OPTIONS / Allow"))

    # Parse Allow uma vez para derivar demais métodos (sem executar)
    raw_allow = fetch_headers_for_method(safe_join(target), "OPTIONS")
    allow_set = parse_allow_methods(raw_allow)

    # 202) TRACE (checado de fato, sem side-effect)
    t1 = time.perf_counter()
    url, msg, sev = check_trace(target)
    items.append(make_item(UUIDS[202], msg, sev, time.perf_counter() - t1, ai_fn, "TRACE"))

    # 203) PUT (via Allow)
    t1 = time.perf_counter()
    url = safe_join(target)
    _, msg, sev = check_via_allow("PUT", allow_set, url, sev_when_allowed="high")
    items.append(make_item(UUIDS[203], msg, sev, time.perf_counter() - t1, ai_fn, "PUT"))

    # 204) DELETE (via Allow)
    t1 = time.perf_counter()
    _, msg, sev = check_via_allow("DELETE", allow_set, url, sev_when_allowed="high")
    items.append(make_item(UUIDS[204], msg, sev, time.perf_counter() - t1, ai_fn, "DELETE"))

    # 205) PATCH (via Allow)
    t1 = time.perf_counter()
    _, msg, sev = check_via_allow("PATCH", allow_set, url, sev_when_allowed="medium")
    items.append(make_item(UUIDS[205], msg, sev, time.perf_counter() - t1, ai_fn, "PATCH"))

    # 206) PROPFIND (WebDAV) (via Allow)
    t1 = time.perf_counter()
    _, msg, sev = check_via_allow("PROPFIND", allow_set, url, sev_when_allowed="high")
    items.append(make_item(UUIDS[206], msg, sev, time.perf_counter() - t1, ai_fn, "PROPFIND"))

    # 207) MKCOL (WebDAV) (via Allow)
    t1 = time.perf_counter()
    _, msg, sev = check_via_allow("MKCOL", allow_set, url, sev_when_allowed="high")
    items.append(make_item(UUIDS[207], msg, sev, time.perf_counter() - t1, ai_fn, "MKCOL"))

    # 208) MOVE (WebDAV) (via Allow)
    t1 = time.perf_counter()
    _, msg, sev = check_via_allow("MOVE", allow_set, url, sev_when_allowed="high")
    items.append(make_item(UUIDS[208], msg, sev, time.perf_counter() - t1, ai_fn, "MOVE"))

    # 209) COPY (WebDAV) (via Allow)
    t1 = time.perf_counter()
    _, msg, sev = check_via_allow("COPY", allow_set, url, sev_when_allowed="high")
    items.append(make_item(UUIDS[209], msg, sev, time.perf_counter() - t1, ai_fn, "COPY"))

    # 210) CORS Preflight (informativo)
    t1 = time.perf_counter()
    url, msg, sev = check_cors_preflight(target)
    items.append(make_item(UUIDS[210], msg, sev, time.perf_counter() - t1, ai_fn, "CORS Preflight"))

    return {
        "plugin": "curl_http_methods",
        "file_name": "curl_http_methods.py",
        "description": "Check HTTP methods (OPTIONS, TRACE, PUT, DELETE, PATCH, WebDAV) and CORS preflight.",
        "category": "Information Gathering",
        "result": items
    }
