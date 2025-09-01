# plugins/tls_crypto_inspector.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer, extrair_host

PLUGIN_CONFIG_NAME = "tls_crypto_inspector"
PLUGIN_CONFIG_ALIASES = ["tls_inspector","ssl_ciphers"]
UUID_075 = "uuid-075"  # (75) TLS 1.2+
UUID_076 = "uuid-076"  # (76) Cifras fracas desabilitadas
UUID_077 = "uuid-077"  # (77) Certificado válido
UUID_078 = "uuid-078"  # (78) Assinatura/chave fortes

def _openssl_client(host: str, timeout: int) -> str:
    # pega cert e negotiated protocol/cipher
    cmd = f'echo | openssl s_client -connect {host}:443 -servername {host} -showcerts 2>/dev/null'
    return run_cmd(["bash","-lc", cmd], timeout=timeout)

def _openssl_x509(cert_pem: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'echo "{cert_pem}" | openssl x509 -noout -text'], timeout=timeout)

def _nmap_ciphers(host: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'nmap --script ssl-enum-ciphers -p 443 {host} --min-rate 100 2>/dev/null | sed -n "1,160p"'], timeout=timeout)

def _extract_first_cert(client_out: str) -> str:
    # extrai o primeiro bloco -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----
    import re
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", client_out, re.S)
    return f"-----BEGIN CERTIFICATE-----{m.group(1)}-----END CERTIFICATE-----" if m else ""

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any] = None):
    """
    cfg: { "timeout": 45, "prefer_nmap": true }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 45))
    prefer_nmap = bool(cfg.get("prefer_nmap", True))
    host = extrair_host(target)

    evid75: List[str] = []
    evid76: List[str] = []
    evid77: List[str] = []
    evid78: List[str] = []

    sev75 = "info"; sev76 = "info"; sev77 = "info"; sev78 = "info"

    with Timer() as t:
        # handshake & cert
        cli = _openssl_client(host, timeout)
        if not cli.strip():
            txt = "Não foi possível negociar TLS com openssl s_client."
            item = [
                {"plugin_uuid": UUID_075, "scan_item_uuid": UUID_075, "result": txt, "analysis_ai": ai_fn("TLSCryptoInspector", UUID_075, txt), "severity":"low", "duration": t.duration, "auto": True},
                {"plugin_uuid": UUID_076, "scan_item_uuid": UUID_076, "result": txt, "analysis_ai": ai_fn("TLSCryptoInspector", UUID_076, txt), "severity":"low", "duration": t.duration, "auto": True},
                {"plugin_uuid": UUID_077, "scan_item_uuid": UUID_077, "result": txt, "analysis_ai": ai_fn("TLSCryptoInspector", UUID_077, txt), "severity":"low", "duration": t.duration, "auto": True},
                {"plugin_uuid": UUID_078, "scan_item_uuid": UUID_078, "result": txt, "analysis_ai": ai_fn("TLSCryptoInspector", UUID_078, txt), "severity":"low", "duration": t.duration, "auto": True}
            ]
            return {"plugin": "TLSCryptoInspector", "result": item}

        # versão/cipher negociada
        low = cli.lower()
        if "tlsv1.0" in low or "tlsv1.1" in low:
            evid75.append("Servidor parece aceitar TLS < 1.2 (negociação/advertência).")
            sev75 = "medium"
        else:
            evid75.append("Sem evidência de TLS < 1.2 na negociação padrão.")

        # nmap ciphers (opcional)
        nmap = _nmap_ciphers(host, min(timeout, 60)) if prefer_nmap else ""
        if nmap:
            bad = [ln for ln in nmap.lower().splitlines() if any(w in ln for w in ["null", "md5", "rc4", "export", "arcfour"])]
            if bad:
                sev76 = "medium"; evid76.append("Cifras fracas/obsoletas listadas: " + " | ".join(bad[:6]))
            else:
                evid76.append("Sem cifras fracas aparentes no nmap ssl-enum-ciphers.")
        else:
            evid76.append("nmap ssl-enum-ciphers indisponível/não conclusivo (fallback openssl).")

        # Certificado (validades, CN/SAN, Key size, Signature)
        cert_pem = _extract_first_cert(cli)
        if cert_pem:
            x509 = _openssl_x509(cert_pem, timeout)
            lowx = x509.lower()
            # validade
            if "not after" in x509:
                evid77.append(re.findall(r"Not After\s*:\s*(.*)", x509)[0][:60])
            if "issuer:" in x509:
                evid77.append(re.findall(r"Issuer:\s*(.*)", x509)[0][:80])
            if "subject:" in x509:
                evid77.append(re.findall(r"Subject:\s*(.*)", x509)[0][:80])
            # tamanho da chave
            m = re.search(r"Public-Key:\s*\((\d+)\s*bit", x509)
            if m:
                bits = int(m.group(1))
                if bits < 2048:
                    sev78 = "medium"; evid78.append(f"Chave RSA fraca ({bits} bits).")
                else:
                    evid78.append(f"Chave pública ≈ {bits} bits.")
            # assinatura
            if "sha1" in lowx or "md5" in lowx:
                sev78 = "medium"; evid78.append("Assinatura fraca/obsoleta (SHA-1/MD5).")
        else:
            evid77.append("Não foi possível extrair o certificado no handshake.")

    res75 = "\n".join(f"- {e}" for e in evid75) if evid75 else "Sem dados sobre versões TLS"
    res76 = "\n".join(f"- {e}" for e in evid76) if evid76 else "Sem dados sobre cifras"
    res77 = "\n".join(f"- {e}" for e in evid77) if evid77 else "Sem dados de certificado"
    res78 = "\n".join(f"- {e}" for e in evid78) if evid78 else "Sem dados de assinatura/chave"

    return {
        "plugin": "TLSCryptoInspector",
        "result": [
            {"plugin_uuid": UUID_075, "scan_item_uuid": UUID_075, "result": res75, "analysis_ai": ai_fn("TLSCryptoInspector", UUID_075, res75), "severity": sev75, "duration": t.duration, "auto": True},
            {"plugin_uuid": UUID_076, "scan_item_uuid": UUID_076, "result": res76, "analysis_ai": ai_fn("TLSCryptoInspector", UUID_076, res76), "severity": sev76, "duration": t.duration, "auto": True},
            {"plugin_uuid": UUID_077, "scan_item_uuid": UUID_077, "result": res77, "analysis_ai": ai_fn("TLSCryptoInspector", UUID_077, res77), "severity": sev77, "duration": t.duration, "auto": True},
            {"plugin_uuid": UUID_078, "scan_item_uuid": UUID_078, "result": res78, "analysis_ai": ai_fn("TLSCryptoInspector", UUID_078, res78), "severity": sev78, "duration": t.duration, "auto": True}
        ]
    }
