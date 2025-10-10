# plugins/idor_rbac_heuristics.py
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urljoin
from utils import run_cmd, Timer
import re

PLUGIN_CONFIG_NAME = "idor_rbac_heuristics"
PLUGIN_CONFIG_ALIASES = ["idor", "rbac", "authz"]

# UUIDs originais preservados
UUID_069 = "uuid-069"  # RBAC/ABAC efetivos
UUID_070 = "uuid-070"  # Acesso horizontal/vertical não permitido (sequencial)
UUID_071 = "uuid-071"  # Endpoints admin protegidos
UUID_068 = "uuid-068"  # IDOR / forced browsing

# Referências
REF_IDOR = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
REF_AUTHZ = "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"

DEFAULT_ENDPOINTS = [
    "/admin", "/admin/users", "/admin/panel", "/manager", "/dashboard",
    "/api/users/1", "/api/users/2", "/api/orders/1", "/api/orders/2",
    "/user/1", "/user/2", "/invoice/1", "/invoice/2"
]

def _curl_head(url: str, timeout: int, cookie: str = "") -> str:
    hdr = f'-H "Cookie: {cookie}"' if cookie else ""
    return run_cmd(["bash","-lc", f'curl -sS -I -L -m {timeout} {hdr} "{url}"'], timeout=timeout+2) or ""

def _curl_get(url: str, timeout: int, cookie: str = "") -> str:
    hdr = f'-H "Cookie: {cookie}"' if cookie else ""
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} {hdr} "{url}"'], timeout=timeout+2) or ""

def _extract_last_status(head: str) -> Tuple[Optional[int], str]:
    """
    Extrai o último status HTTP de uma cadeia com -L (redirects).
    Retorna (code, status_line) ou (None, "HTTP/??").
    """
    last = None
    status_line = "HTTP/??"
    for ln in head.splitlines():
        m = re.match(r"^HTTP/\d\.\d\s+(\d{3})\b", ln.strip(), re.I)
        if m:
            try:
                last = int(m.group(1))
                status_line = ln.strip()
            except Exception:
                continue
    return last, status_line

def _status_and_body(url: str, timeout: int, cookie: str = "") -> Tuple[Optional[int], str, str]:
    """
    Retorna (code, status_line, body_snippet)
    """
    head = _curl_head(url, timeout, cookie)
    code, status_line = _extract_last_status(head)
    body = _curl_get(url, timeout, cookie)
    return code, status_line, (body[:400] if body else "")

def _sequential_tests(base_url: str, timeout: int, cookie: str, idnum: int) -> List[Tuple[str, str, bool]]:
    """
    Testa idnum-1 e idnum+1.
    Retorna lista de (url_testada, http_code, suspeito_bool).
    """
    results: List[Tuple[str, str, bool]] = []
    for test in (idnum - 1, idnum + 1):
        u2 = f"{base_url}/{test}"
        head = _curl_head(u2, timeout, cookie)
        code, _ = _extract_last_status(head)
        code_s = str(code) if code is not None else "??"
        suspicious = code_s.startswith("20")  # sucesso suspeito
        results.append((u2, code_s, suspicious))
    return results

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg:
    {
      "timeout": 20,
      "endpoints": [ "/admin", "/api/users/1", ... ],     # heurísticas de forced browsing/IDOR/admin/RBAC
      "resources": [{"url":"/api/users/100"}, ...],       # probe sequencial (horizontal/vertical)
      "cookie": ""                                        # opcional (sessão autenticada para testes controlados)
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    endpoints: List[str] = cfg.get("endpoints") or DEFAULT_ENDPOINTS
    resources: List[Dict[str, Any]] = cfg.get("resources") or []
    cookie = cfg.get("cookie", "")

    evid_admin: List[str] = []   # UUID_071
    evid_idor: List[str] = []    # UUID_068
    evid_authz: List[str] = []   # UUID_069
    evid_seq: List[str] = []     # UUID_070 (horizontal/vertical)

    with Timer() as t:
        # Heurísticas gerais (forced browsing / admin / RBAC)
        for p in endpoints:
            url = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            code, status_line, body = _status_and_body(url, timeout, cookie)
            code_s = str(code) if code is not None else "??"
            body_low = (body or "").lower()

            # 071: Endpoints admin protegidos
            if any(seg in p for seg in ["/admin", "/manager"]):
                if code_s.startswith(("200", "302")) and "login" not in body_low:
                    evid_admin.append(f"{p} :: {status_line} (pode estar acessível sem auth)")

            # 068: IDOR / forced browsing (dados sensíveis em recursos possivelmente não autorizados)
            if any(seg in p for seg in ["/user/", "/users/", "/orders/", "/invoice/", "/api/users/", "/api/orders/"]):
                if code_s.startswith("200") and any(k in body_low for k in ["email", "cpf", "address", "user", "order", "invoice"]):
                    evid_idor.append(f"{p} :: {status_line} (respondeu com dados — possível IDOR)")

            # 069: Indícios de RBAC/ABAC no payload (informativo)
            if code_s.startswith("200") and any(k in body_low for k in ["permission", "role", "admin", "is_admin"]):
                evid_authz.append(f"{p} :: {status_line} (indícios de controle de acesso no payload)")

        # Probe sequencial (horizontal/vertical): reaproveita UUID_070
        for r in resources:
            u = urljoin(target.rstrip("/") + "/", (r.get("url") or "/").lstrip("/"))
            try:
                base, idval = u.rsplit("/", 1)
                idnum = int(idval)
            except Exception:
                # não é um ID numérico no final; ignora
                continue
            seq_results = _sequential_tests(base, timeout, cookie, idnum)
            for u2, st, suspicious in seq_results:
                if suspicious:
                    evid_seq.append(f"{u2} -> {st} (possível IDOR horizontal/vertical)")
                else:
                    evid_seq.append(f"{u2} -> {st}")

    # Severidades
    sev_admin = "medium" if evid_admin else "info"   # admin público ou redirecionando sem exigir login
    sev_idor  = "high"   if evid_idor  else "info"   # conteúdo sensível respondendo 200
    sev_authz = "low"    if evid_authz else "info"   # informativo
    sev_seq   = "medium" if any("possível IDOR" in e for e in evid_seq) else ("info" if evid_seq else "info")

    # Resultados formatados
    def _fmt(evid: List[str], default_msg: str) -> str:
        return "\n".join(f"- {e}" for e in evid) if evid else default_msg

    res_admin = _fmt(evid_admin, "Nenhum achado para endpoints admin")
    res_idor  = _fmt(evid_idor,  "Nenhum achado para IDOR / forced browsing")
    res_authz = _fmt(evid_authz, "Nenhum achado evidente de RBAC/ABAC no payload")
    res_seq   = _fmt(evid_seq,   "Sem indícios em recursos sequenciais")

    # Comandos exemplares (para reproduzir manualmente no primeiro endpoint/recurso)
    ep_example = endpoints[0] if endpoints else "/"
    url_example = urljoin(target.rstrip("/") + "/", ep_example.lstrip("/"))
    cmd_example_endpoints = f'curl -sS -I -L -m {timeout} "{url_example}"; curl -sS -L -m {timeout} "{url_example}"'

    res_example = resources[0]["url"] if resources else "/api/users/100"
    res_example_url = urljoin(target.rstrip("/") + "/", res_example.lstrip("/"))
    try:
        base_ex, id_ex = res_example_url.rsplit("/", 1)
        int(id_ex)  # valida ser numérico
        cmd_example_seq = f'curl -sS -I -L -m {timeout} "{base_ex}/{int(id_ex)-1}"; curl -sS -I -L -m {timeout} "{base_ex}/{int(id_ex)+1}"'
    except Exception:
        cmd_example_seq = f'curl -sS -I -L -m {timeout} "{res_example_url}"'

    items = [
        {
            "plugin_uuid": UUID_071,
            "scan_item_uuid": UUID_071,
            "result": res_admin,
            "analysis_ai": ai_fn("IdorRbacHeuristics", UUID_071, res_admin),
            "severity": sev_admin,
            "duration": t.duration,
            "auto": True,
            "reference": REF_AUTHZ,
            "item_name": "Endpoints admin protegidos",
            "command": cmd_example_endpoints
        },
        {
            "plugin_uuid": UUID_068,
            "scan_item_uuid": UUID_068,
            "result": res_idor,
            "analysis_ai": ai_fn("IdorRbacHeuristics", UUID_068, res_idor),
            "severity": sev_idor,
            "duration": t.duration,
            "auto": True,
            "reference": REF_IDOR,
            "item_name": "IDOR / Forced Browsing",
            "command": cmd_example_endpoints
        },
        {
            "plugin_uuid": UUID_069,
            "scan_item_uuid": UUID_069,
            "result": res_authz,
            "analysis_ai": ai_fn("IdorRbacHeuristics", UUID_069, res_authz),
            "severity": sev_authz,
            "duration": t.duration,
            "auto": True,
            "reference": REF_AUTHZ,
            "item_name": "Controles RBAC/ABAC (indícios no payload)",
            "command": cmd_example_endpoints
        },
        {
            "plugin_uuid": UUID_070,
            "scan_item_uuid": UUID_070,
            "result": res_seq,
            "analysis_ai": ai_fn("IdorRbacHeuristics", UUID_070, res_seq),
            "severity": sev_seq,
            "duration": t.duration,
            "auto": True,
            "reference": REF_IDOR,
            "item_name": "Acesso horizontal/vertical (probe sequencial)",
            "command": cmd_example_seq
        }
    ]

    return {
        "plugin": "IdorRbacHeuristics",
        "plugin_uuid": UUID_068,  # usa o de IDOR como identificador do plugin
        "file_name": "idor_rbac_heuristics.py",
        "description": "Heurísticas de IDOR/forced browsing, proteção de endpoints admin e indícios de RBAC/ABAC, incluindo probe sequencial horizontal/vertical.",
        "category": "Authorization",
        "result": items
    }