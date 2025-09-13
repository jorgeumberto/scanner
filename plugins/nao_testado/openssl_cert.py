# plugins/openssl_cert.py
import re
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer, extract_host

PLUGIN_CONFIG_NAME = "openssl_cert"
PLUGIN_CONFIG_ALIASES = ["openssl_tls", "openssl_fallback"]

UUID_077 = "uuid-077"  # Item 77 — Certificado válido
UUID_078 = "uuid-078"  # Item 78 — Assinatura/chave fortes

def _sclient(host: str, port: int, timeout: int) -> str:
    # -servername para SNI, -showcerts para cadeia
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts", "-verify", "5", "-brief"]
    return run_cmd(cmd, timeout=timeout)

def _x509_text(pem: str, timeout: int) -> str:
    # Converte PEM -> texto para extrair CN/SAN/algoritmo/validade/bitlength
    return run_cmd(["openssl", "x509", "-noout", "-text"], timeout=timeout,)

def _extract_leaf_cert(op_out: str) -> str:
    """
    Extrai primeiro certificado PEM do output do s_client.
    """
    start = op_out.find("-----BEGIN CERTIFICATE-----")
    end   = op_out.find("-----END CERTIFICATE-----")
    if start != -1 and end != -1:
        return op_out[start:end+len("-----END CERTIFICATE-----")]
    return ""

def _parse_x509_text(x509_text: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    # Subject CN
    m = re.search(r"Subject:.*?CN\s*=\s*([^,\n]+)", x509_text)
    if m:
        info["subject_cn"] = m.group(1).strip()
    # SAN
    m = re.search(r"X509v3 Subject Alternative Name:\s*([^\n]+)", x509_text)
    if m:
        info["san"] = m.group(1).strip()
    # Signature Algorithm
    m = re.search(r"Signature Algorithm:\s*([A-Za-z0-9\-]+)", x509_text)
    if m:
        info["sig_alg"] = m.group(1).upper()
    # Public-Key bits
    m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", x509_text)
    if m:
        info["key_bits"] = int(m.group(1))
    # Validity
    m = re.search(r"Not After\s*:\s*([^\n]+)", x509_text)
    if m:
        info["not_after"] = m.group(1).strip()
    return info

def _is_weak_key(info: Dict[str, Any]) -> bool:
    bits = int(info.get("key_bits") or 0)
    if bits and bits < 2048:
        return True
    return False

def _is_weak_sig(info: Dict[str, Any]) -> bool:
    sig = (info.get("sig_alg") or "").upper()
    return ("SHA1" in sig) or ("MD5" in sig)

def _summarize(lines: List[str], checklist_name: str) -> str:
    if not lines:
        return f"Nenhum achado para {checklist_name}"
    return "\n".join(f"- {l}" for l in lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/openssl_cert.json):
    {
      "timeout": 25,
      "port": 443
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 25))
    port = int(cfg.get("port", 443))
    host = extract_host(target)

    with Timer() as t:
        sraw = _sclient(host, port, timeout)
        pem  = _extract_leaf_cert(sraw)
        x509 = ""
        info = {}
        if pem:
            # alimenta openssl x509 por stdin
            x509 = run_cmd(["bash", "-lc", "cat <<'EOF' | openssl x509 -noout -text\n" + pem + "\nEOF\n"], timeout=timeout)
            info = _parse_x509_text(x509)
    duration = t.duration

    # Item 77 — Certificado válido: aqui focamos no “texto” (CN/SAN/validade). Não validamos cadeia OCSP/CA.
    lines77: List[str] = []
    if info:
        lines77.append(f"CN: {info.get('subject_cn','?')}")
        if info.get("san"):
            lines77.append(f"SAN: {info['san']}")
        if info.get("not_after"):
            lines77.append(f"Validade até: {info['not_after']}")
    res77 = _summarize(lines77, "Certificado válido (CA, CN/SAN, expiração)")
    sev77 = "info" if info else "low"

    # Item 78 — Assinatura/chave fortes
    lines78: List[str] = []
    if info:
        if "key_bits" in info:
            lines78.append(f"Chave pública: {info['key_bits']} bits")
        if "sig_alg" in info:
            lines78.append(f"Assinatura: {info['sig_alg']}")
    res78 = _summarize(lines78, "Assinatura/chave fortes (SHA-256+, RSA≥2048/ECDSA)")
    sev78 = "medium" if (_is_weak_key(info) or _is_weak_sig(info)) else ("info" if info else "low")

    result_items = [
        {
            "plugin_uuid": UUID_077,
            "scan_item_uuid": UUID_077,
            "result": res77,
            "analysis_ai": ai_fn("OpenSSL", UUID_077, res77),
            "severity": sev77,
            "duration": duration,
            "auto": True
        },
        {
            "plugin_uuid": UUID_078,
            "scan_item_uuid": UUID_078,
            "result": res78,
            "analysis_ai": ai_fn("OpenSSL", UUID_078, res78),
            "severity": sev78,
            "duration": duration,
            "auto": True
        }
    ]
    return {"plugin": "OpenSSL", "result": result_items}
