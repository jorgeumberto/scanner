# plugins/idor_rbac_heuristics.py
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "idor_rbac_heuristics"
PLUGIN_CONFIG_ALIASES = ["idor", "rbac", "authz"]

UUID_069 = "uuid-069"  # RBAC/ABAC efetivos
UUID_070 = "uuid-070"  # Acesso horizontal/vertical não permitido
UUID_071 = "uuid-071"  # Endpoints admin protegidos
UUID_068 = "uuid-068"  # IDOR / forced browsing

DEFAULT_ENDPOINTS = [
  "/admin", "/admin/users", "/admin/panel", "/manager", "/dashboard",
  "/api/users/1", "/api/users/2", "/api/orders/1", "/api/orders/2",
  "/user/1", "/user/2", "/invoice/1", "/invoice/2"
]

def _get_status_body(url: str, timeout: int) -> (str, str):
    head = run_cmd(["curl", "-sS", "-I", "-L", "-m", str(timeout), url], timeout=timeout+2)
    status = "HTTP/??"
    for ln in head.splitlines():
        if ln.upper().startswith("HTTP/"):
            status = ln.strip(); break
    body = run_cmd(["curl", "-sS", "-L", "-m", str(timeout), url], timeout=timeout+2)
    return status, body[:400]

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg:
    { "timeout": 20, "endpoints": [ ... ] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    endpoints = cfg.get("endpoints") or DEFAULT_ENDPOINTS

    evid_idor, evid_admin, evid_authz = [], [], []

    with Timer() as t:
        for p in endpoints:
            url = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            status, body = _get_status_body(url, timeout)
            code = status.split()[1] if len(status.split())>1 else "??"

            if any(seg in p for seg in ["/admin","/manager"]):
                if code.startswith(("200","302")) and "login" not in body.lower():
                    evid_admin.append(f"{p} :: {status} (pode estar acessível sem auth)")
            if any(seg in p for seg in ["/user/","/users/","/orders/","/invoice/","/api/users/","/api/orders/"]):
                if code.startswith("200") and any(k in body.lower() for k in ["email","cpf","address","user","order","invoice"]):
                    evid_idor.append(f"{p} :: {status} (respondeu com dados — possível IDOR)")
            # heurística geral de autorização fraca
            if code.startswith("200") and any(k in body.lower() for k in ["permission","role","admin","is_admin"]):
                evid_authz.append(f"{p} :: {status} (indícios de controle de acesso no payload)")

    sev_admin = "medium" if evid_admin else "info"
    sev_idor  = "high" if evid_idor else "info"
    sev_authz = "low"  if evid_authz else "info"

    def _mk(uuid, name, evid, sev):
        txt = "\n".join(f"- {e}" for e in evid) if evid else f"Nenhum achado para {name}"
        return {
            "plugin_uuid": uuid,
            "scan_item_uuid": uuid,
            "result": txt,
            "analysis_ai": ai_fn("IdorRbacHeuristics", uuid, txt),
            "severity": sev,
            "duration": t.duration,
            "auto": True
        }

    items = [
        _mk(UUID_071, "Endpoints admin protegidos", evid_admin, sev_admin),
        _mk(UUID_068, "IDOR / forced browsing",    evid_idor,  sev_idor),
        _mk(UUID_069, "Controles RBAC/ABAC",       evid_authz, sev_authz),
        _mk(UUID_070, "Acesso horizontal/vertical", evid_idor,  sev_idor)  # reuse da mesma evidência
    ]
    return {"plugin": "IdorRbacHeuristics", "result": items}
