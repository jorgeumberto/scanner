# plugins/tls_fallback_openssl.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer, extrair_host

PLUGIN_CONFIG_NAME = "tls_fallback_openssl"
PLUGIN_CONFIG_ALIASES = ["tls_fallback", "openssl_tls"]

UUID_077 = "uuid-077"  # (77) Certificado válido (CA, CN/SAN, expiração)
UUID_078 = "uuid-078"  # (78) Assinatura/chave fortes (SHA-256+, RSA≥2048/ECDSA)

def _openssl_s_client(host: str, port: int, timeout: int) -> str:
    cmd = ["bash", "-lc", f'echo | openssl s_client -servername {host} -connect {host}:{port} 2>/dev/null | openssl x509 -noout -text']
    return run_cmd(cmd, timeout=timeout)

def _parse_cert_info(text: str) -> Dict[str, str]:
    info = {"subject": "", "issuer": "", "signature_algo": "", "pubkey_bits": "", "san": ""}
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("Subject:"): info["subject"] = s
        elif s.startswith("Issuer:"): info["issuer"] = s
        elif "Signature Algorithm:" in s and not info["signature_algo"]:
            info["signature_algo"] = s.split(":",1)[1].strip()
        elif "Public-Key:" in s and "(" in s and "bit" in s:
            info["pubkey_bits"] = s.split("(")[1].split("bit")[0].strip()
        elif "DNS:" in s:
            info["san"] += (" " + s)
    return info

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg:
    { "timeout": 25, "port": 443 }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 25))
    port = int(cfg.get("port", 443))
    host = extrair_host(target)

    with Timer() as t:
        raw = _openssl_s_client(host, port, timeout)
    info = _parse_cert_info(raw)

    # (77): validade/cadeia — difícil garantir via s_client; tratamos indícios:
    cert_ok = ("Issuer:" in info.get("issuer","")) and ("Subject:" in info.get("subject",""))
    ev77 = []
    if info["subject"]: ev77.append(info["subject"])
    if info["issuer"]:  ev77.append(info["issuer"])
    if not cert_ok:     ev77.append("Indício: não foi possível confirmar cadeia/validez com fallback")

    # (78): chave/assinatura fortes
    bits = 0
    try: bits = int(info.get("pubkey_bits","") or "0")
    except: bits = 0
    sig = (info.get("signature_algo","") or "").lower()
    key_ok = (bits >= 2048) or ("ecdsa" in sig)
    ev78 = []
    if info["signature_algo"]: ev78.append(f"Assinatura: {info['signature_algo']}")
    if info["pubkey_bits"]:    ev78.append(f"Chave: {info['pubkey_bits']} bits")
    if info["san"]:            ev78.append(f"SAN:{info['san'][:180]}{'...' if len(info['san'])>180 else ''}")

    res77 = "\n".join(f"- {e}" for e in ev77) if ev77 else "Nenhum dado de certificado extraído (fallback)"
    res78 = "\n".join(f"- {e}" for e in ev78) if ev78 else "Nenhuma info de chave/assinatura extraída (fallback)"

    items = [
        {
            "plugin_uuid": UUID_077,
            "scan_item_uuid": UUID_077,
            "result": res77,
            "analysis_ai": ai_fn("TLSFallbackOpenSSL", UUID_077, res77),
            "severity": "info" if cert_ok else "low",
            "duration": t.duration,
            "auto": True
        },
        {
            "plugin_uuid": UUID_078,
            "scan_item_uuid": UUID_078,
            "result": res78,
            "analysis_ai": ai_fn("TLSFallbackOpenSSL", UUID_078, res78),
            "severity": "info" if key_ok else "medium",
            "duration": t.duration,
            "auto": True
        }
    ]
    return {"plugin": "TLSFallbackOpenSSL", "result": items}
