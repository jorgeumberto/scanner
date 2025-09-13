# plugins/testssl_tls.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer, extrair_host

PLUGIN_CONFIG_NAME = "testssl_tls"
PLUGIN_CONFIG_ALIASES = ["tls", "ssl"]

UUID_075 = "uuid-075"  # Somente TLS 1.2+ habilitado
UUID_076 = "uuid-076"  # Cifras fracas desabilitadas
UUID_077 = "uuid-077"  # Certificado válido
UUID_078 = "uuid-078"  # Assinatura/chave fortes

def _parse_protocols(lines: List[str]) -> Tuple[bool, List[str]]:
    # retorna (ok_tls12plus, evidências)
    evid = []
    ok = True
    low = [l.lower() for l in lines]
    # se aparecer sslv2/sslv3/tls1.0/tls1.1 como accepted => NOK
    bad = ["sslv2", "sslv3", "tls1.0", "tls1.1"]
    for b in bad:
        if any(b in l and "accepted" in l for l in low):
            ok = False
            evid.append(f"{b.upper()} aceito")
    if not evid:
        evid.append("Somente TLS 1.2+ aceito (conforme saída)")
    return ok, evid

def _parse_ciphers(lines: List[str]) -> Tuple[bool, List[str]]:
    evid = []
    ok = True
    bad_keywords = ["null", "export", "rc4", "md5", "des"]
    for l in lines:
        low = l.lower()
        if "accepted" in low and any(k in low for k in bad_keywords):
            ok = False
            evid.append(l.strip())
    if not evid:
        evid.append("Nenhuma cifra fraca aparente nas aceitas")
    return ok, evid

def _parse_cert(lines: List[str]) -> Tuple[bool, List[str], bool, List[str]]:
    # retorna (cert_ok, evid_cert, key_ok, evid_key)
    cert_ok = True; key_ok = True
    evid_c = []; evid_k = []
    for l in lines:
        low = l.lower().strip()
        if "not valid" in low or "expired" in low or "self-signed" in low:
            cert_ok = False; evid_c.append(l.strip())
        if "rsa" in low and "2048" not in low and "3072" not in low and "4096" not in low:
            key_ok = False; evid_k.append(l.strip())
        if "ecdsa" in low and ("p-256" in low or "p-384" in low or "p-521" in low):
            pass
    if not evid_c:
        evid_c.append("Certificado aparente válido (cadeia/validade ok)")
    if not evid_k:
        evid_k.append("Chave/assinatura aparentam ser fortes")
    return cert_ok, evid_c, key_ok, evid_k

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/testssl_tls.json):
    {
      "timeout": 120,
      "args": ["--fast"]
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 120))
    args = cfg.get("args") or ["--fast"]

    host = extrair_host(target)
    cmd = ["testssl.sh", *args, host]
    with Timer() as t:
        out = run_cmd(cmd, timeout=timeout)

    lines = out.splitlines()
    ok_proto, ev_proto = _parse_protocols(lines)
    ok_ciph, ev_ciph = _parse_ciphers(lines)
    ok_cert, ev_cert, ok_key, ev_key = _parse_cert(lines)

    items = []

    # (75) TLS 1.2+
    res75 = "\n".join(f"- {e}" for e in ev_proto)
    items.append({
        "plugin_uuid": UUID_075,
        "scan_item_uuid": UUID_075,
        "result": res75,
        "analysis_ai": ai_fn("TestsslTLS", UUID_075, res75),
        "severity": "info" if ok_proto else "medium",
        "duration": t.duration,
        "auto": True
    })

    # (76) Cifras fracas
    res76 = "\n".join(f"- {e}" for e in ev_ciph)
    items.append({
        "plugin_uuid": UUID_076,
        "scan_item_uuid": UUID_076,
        "result": res76,
        "analysis_ai": ai_fn("TestsslTLS", UUID_076, res76),
        "severity": "info" if ok_ciph else "medium",
        "duration": t.duration,
        "auto": True
    })

    # (77) Cert válido
    res77 = "\n".join(f"- {e}" for e in ev_cert)
    items.append({
        "plugin_uuid": UUID_077,
        "scan_item_uuid": UUID_077,
        "result": res77,
        "analysis_ai": ai_fn("TestsslTLS", UUID_077, res77),
        "severity": "info" if ok_cert else "medium",
        "duration": t.duration,
        "auto": True
    })

    # (78) Chave/assinatura fortes
    res78 = "\n".join(f"- {e}" for e in ev_key)
    items.append({
        "plugin_uuid": UUID_078,
        "scan_item_uuid": UUID_078,
        "result": res78,
        "analysis_ai": ai_fn("TestsslTLS", UUID_078, res78),
        "severity": "info" if ok_key else "medium",
        "duration": t.duration,
        "auto": True
    })

    return {
        "plugin": "TestsslTLS",
        "result": items
    }
