# plugins/openssl_cert_dates.py
from typing import Dict, Any, List
from utils import run_cmd, Timer, extrair_host

PLUGIN_CONFIG_NAME = "openssl_cert_dates"
PLUGIN_CONFIG_ALIASES = ["cert_dates", "x509_dates"]

UUID_077 = "uuid-077"  # Certificado válido (CA, CN/SAN, expiração)
UUID_078 = "uuid-078"  # Assinatura/chave fortes (aqui só reforçamos data; força está em outros plugins)

def _x509_text(host: str, port: int, timeout: int) -> str:
    cmd = ["bash", "-lc", f'echo | openssl s_client -servername {host} -connect {host}:{port} 2>/dev/null | openssl x509 -noout -dates -subject -issuer']
    return run_cmd(cmd, timeout=timeout)

def _parse_dates(text: str) -> Dict[str,str]:
    out = {"not_before":"", "not_after":"", "subject":"", "issuer":""}
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("notBefore="): out["not_before"] = s.split("=",1)[1].strip()
        elif s.startswith("notAfter="): out["not_after"]  = s.split("=",1)[1].strip()
        elif s.startswith("subject="):  out["subject"]    = s
        elif s.startswith("issuer="):   out["issuer"]     = s
    return out

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg: { "timeout": 20, "port": 443, "warn_days": 30 }
    """
    cfg = cfg or {}
    timeout   = int(cfg.get("timeout", 20))
    port      = int(cfg.get("port", 443))
    warn_days = int(cfg.get("warn_days", 30))
    host = extrair_host(target)

    with Timer() as t:
        raw = _x509_text(host, port, timeout)
    info = _parse_dates(raw)

    evid: List[str] = []
    if info["subject"]: evid.append(info["subject"])
    if info["issuer"]:  evid.append(info["issuer"])
    if info["not_before"]: evid.append(f"notBefore={info['not_before']}")
    if info["not_after"]:  evid.append(f"notAfter={info['not_after']}")

    # Heurística simples de severidade: se há notAfter e já passou/está perto -> alerta
    sev = "info"
    if "notAfter=" in raw:
        # Compare via openssl (sem python datetime para evitar TZ bagunça)
        chk = run_cmd(["bash","-lc", f'date -u -d "{info["not_after"]}" +%s || true'], timeout=5).strip()
        now = run_cmd(["bash","-lc","date -u +%s"], timeout=5).strip()
        try:
            exp = int(chk); cur = int(now)
            days_left = int((exp - cur) / 86400)
            evid.append(f"Expira em ~{days_left} dias")
            if days_left < 0:
                sev = "high"; evid.append("Certificado EXPIRADO")
            elif days_left <= warn_days:
                sev = "low"; evid.append(f"Certificado expira em ≤ {warn_days} dias (atenção)")
        except:
            pass

    res77 = "\n".join(f"- {e}" for e in evid) if evid else "Não foi possível extrair datas do certificado"
    items = [
        {
            "plugin_uuid": UUID_077,
            "scan_item_uuid": UUID_077,
            "result": res77,
            "analysis_ai": ai_fn("OpenSSLCertDates", UUID_077, res77),
            "severity": sev,
            "duration": t.duration,
            "auto": True
        }
    ]
    # (78) não repete aqui; já avaliamos em outros plugins. Se quiser duplicar o reforço:
    items.append({
        "plugin_uuid": UUID_078,
        "scan_item_uuid": UUID_078,
        "result": "Verificação complementar de validade executada (ver item 77 acima).",
        "analysis_ai": ai_fn("OpenSSLCertDates", UUID_078, "Complemento de validade do certificado."),
        "severity": "info",
        "duration": t.duration,
        "auto": True
    })

    return {"plugin": "OpenSSLCertDates", "result": items}
