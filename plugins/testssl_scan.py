# plugins/testssl_scan.py
import shutil
import re
from typing import Dict, Any, List, Tuple

from utils import run_cmd, Timer, extract_host

# Deixe o main achar configs/testssl.json automaticamente
PLUGIN_CONFIG_NAME = "testssl"

# UUIDs placeholders — troque pelos reais (IDs 75–79)
UUIDS = {
    75: "uuid-075",  # TLS 1.2+ only
    76: "uuid-076",  # Ciphers weak disabled
    77: "uuid-077",  # Certificate valid
    78: "uuid-078",  # Strong signature/key
    79: "uuid-079",  # HSTS includeSubDomains/preload
}

def _ensure_testssl_available() -> bool:
    return shutil.which("testssl.sh") is not None

def _run_testssl(host: str, port: int, timeout: int) -> str:
    """
    Rodamos com flags rápidas/silenciosas:
      -U (service), --sneaky (menos ruidoso), --quiet, --fast
    """
    target = f"{host}:{port}"
    cmd = ["testssl.sh", "--fast", "-U", "--sneaky", "--quiet", target]
    return run_cmd(cmd, timeout=timeout)

# ---------- Parsers (heurísticos para saída de texto do testssl.sh) ----------

PROTO_OK = {"TLSv1.2", "TLSv1.3"}
PROTO_BAD = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

WEAK_CIPHER_TOKENS = [
    "RC4", "NULL", "EXP", "EXPORT", "DES", "3DES", "MD5", "aNULL", "eNULL"
]

def _parse_protocols(out: str) -> Tuple[List[str], List[str]]:
    """
    Retorna (protocols_enabled, protocols_disabled)
    Procura linhas tipo:
      "TLSv1.2  offered" / "not offered"
    """
    enabled, disabled = [], []
    for line in out.splitlines():
        m = re.search(r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(\w+)", line)
        if m:
            proto, status = m.group(1), m.group(2).lower()
            if "offered" in status or "yes" in status or "enabled" in status:
                enabled.append(proto)
            else:
                disabled.append(proto)
    return sorted(set(enabled)), sorted(set(disabled))

def _parse_weak_ciphers(out: str) -> List[str]:
    """
    Heurística: varre linhas com 'cipher' e procura tokens fracos.
    """
    bad = set()
    for line in out.splitlines():
        if "cipher" in line.lower():
            for t in WEAK_CIPHER_TOKENS:
                if t.lower() in line.lower():
                    bad.add(t.upper())
    return sorted(bad)

def _parse_cert_block(out: str) -> Dict[str, str]:
    """
    Extrai info do certificado:
      - subject/CN
      - issuer
      - validity (notBefore/notAfter)
      - key size / algo
      - signature algorithm
    """
    info = {}
    # Subject
    m = re.search(r"Subject:\s*(.*)", out, re.I)
    if m: info["subject"] = m.group(1).strip()
    # Issuer
    m = re.search(r"Issuer:\s*(.*)", out, re.I)
    if m: info["issuer"] = m.group(1).strip()
    # Validity dates
    m = re.search(r"not\s*Before\s*:\s*(.*)", out, re.I)
    if m: info["not_before"] = m.group(1).strip()
    m = re.search(r"not\s*After\s*:\s*(.*)", out, re.I)
    if m: info["not_after"] = m.group(1).strip()
    # Key size/algorithm
    m = re.search(r"(RSA|ECDSA)\s*key\s*size\s*[:=]\s*(\d+)", out, re.I)
    if m:
        info["key_algo"] = m.group(1).upper()
        info["key_bits"] = m.group(2)
    else:
        # Às vezes aparece como "Server public key is 2048 bit"
        m = re.search(r"public key is\s*(\d+)\s*bit", out, re.I)
        if m:
            info["key_bits"] = m.group(1)
    # Signature algorithm
    m = re.search(r"Signature Algorithm:\s*([A-Za-z0-9\-]+)", out, re.I)
    if m:
        info["sig_alg"] = m.group(1).upper()
    else:
        # Outra forma (testssl às vezes sumariza):
        m = re.search(r"Signature\s*Algo\s*[:=]\s*([A-Za-z0-9\-]+)", out, re.I)
        if m:
            info["sig_alg"] = m.group(1).upper()
    return info

def _parse_hsts_from_headers(host: str, timeout: int) -> str:
    """
    HSTS (Strict-Transport-Security) via cabeçalho HTTP (porta 443).
    Usamos curl direto pra capturar includeSubDomains/preload.
    """
    url = f"https://{host}"
    raw = run_cmd(["curl", "-sSI", url], timeout=timeout)
    hsts = ""
    for line in raw.splitlines():
        if line.lower().startswith("strict-transport-security:"):
            hsts = line.split(":", 1)[1].strip()
            break
    return hsts

# ------------------ Plugin principal ------------------

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/testssl.json:
    {
      "timeout": 300,
      "port": 443,
      "check_hsts": true
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 300))
    port = int(cfg.get("port", 443))
    check_hsts = bool(cfg.get("check_hsts", True))

    host = extract_host(target)
    items: List[Dict[str, Any]] = []

    # testssl disponível?
    if not _ensure_testssl_available():
        msg = "testssl.sh não encontrado no PATH. Instale: https://github.com/drwetter/testssl.sh"
        # consolidamos em um item info
        items.append({
            "plugin_uuid": "uuid-testssl-missing",
            "scan_item_uuid": "uuid-testssl-missing",
            "result": msg,
            "analysis_ai": ai_fn("TestSSL", "uuid-testssl-missing", msg),
            "severity": "info",
            "duration": 0.0,
            "auto": True
        })
        return {"plugin": "TestSSL", "result": items}

    # -------------- roda testssl --------------
    with Timer() as t:
        out = _run_testssl(host, port, timeout=timeout)
    duration = t.duration

    # 75) Protocolos
    prot_enabled, prot_disabled = _parse_protocols(out)
    bad_enabled = sorted(set(prot_enabled).intersection(PROTO_BAD))
    res75 = f"Ativos: {', '.join(prot_enabled) or 'nenhum'} | Desativados: {', '.join(prot_disabled) or 'nenhum'}"
    sev75 = "high" if bad_enabled else ("info" if set(prot_enabled).issubset(PROTO_OK) else "low")
    items.append({
        "plugin_uuid": UUIDS[75],
        "scan_item_uuid": UUIDS[75],
        "result": res75,
        "analysis_ai": ai_fn("TestSSL", UUIDS[75], res75),
        "severity": sev75,
        "duration": duration,
        "auto": True
    })

    # 76) Cifras fracas
    weak = _parse_weak_ciphers(out)
    if weak:
        res76 = "Cifras fracas detectadas: " + ", ".join(weak)
        sev76 = "medium"
    else:
        res76 = "Nenhuma cifra fraca típica detectada"
        sev76 = "info"
    items.append({
        "plugin_uuid": UUIDS[76],
        "scan_item_uuid": UUIDS[76],
        "result": res76,
        "analysis_ai": ai_fn("TestSSL", UUIDS[76], res76),
        "severity": sev76,
        "duration": duration,
        "auto": True
    })

    # 77/78) Cert
    cert = _parse_cert_block(out)
    # 77 validade (heurística: se tem not_after e subject, assumimos válido; o testssl detalha erro também, mas manter simples)
    if cert.get("not_after"):
        res77 = f"Issuer: {cert.get('issuer','?')} | Subject: {cert.get('subject','?')} | Validade até: {cert['not_after']}"
        sev77 = "info"
    else:
        res77 = "Não foi possível extrair validade do certificado"
        sev77 = "low"
    items.append({
        "plugin_uuid": UUIDS[77],
        "scan_item_uuid": UUIDS[77],
        "result": res77,
        "analysis_ai": ai_fn("TestSSL", UUIDS[77], res77),
        "severity": sev77,
        "duration": duration,
        "auto": True
    })

    # 78 assinatura/chave
    bits = int(cert.get("key_bits") or 0)
    sig  = cert.get("sig_alg", "")
    # critérios simples:
    #   RSA >= 2048 OK; ECDSA geralmente OK; SHA1 ruim, SHA256+ OK
    if bits and bits < 2048:
        sev78 = "medium"
    elif "SHA1" in sig:
        sev78 = "medium"
    else:
        sev78 = "info"
    res78 = f"Chave: {bits or '?'} bits | Assinatura: {sig or '?'}"
    items.append({
        "plugin_uuid": UUIDS[78],
        "scan_item_uuid": UUIDS[78],
        "result": res78,
        "analysis_ai": ai_fn("TestSSL", UUIDS[78], res78),
        "severity": sev78,
        "duration": duration,
        "auto": True
    })

    # 79) HSTS includeSubDomains/preload (via header)
    if check_hsts:
        with Timer() as th:
            hsts = _parse_hsts_from_headers(host, timeout=20)
        sev79 = "info"
        if not hsts:
            res79 = "HSTS ausente"
            sev79 = "low"
        else:
            flags = hsts.lower()
            missing = []
            if "includesubdomains" not in flags:
                missing.append("includeSubDomains")
            if "preload" not in flags:
                missing.append("preload")
            if missing:
                res79 = f"HSTS presente porém sem: {', '.join(missing)} | Valor: {hsts}"
                sev79 = "low"
            else:
                res79 = f"HSTS completo | Valor: {hsts}"
        items.append({
            "plugin_uuid": UUIDS[79],
            "scan_item_uuid": UUIDS[79],
            "result": res79,
            "analysis_ai": ai_fn("TestSSL", UUIDS[79], res79),
            "severity": sev79,
            "duration": th.duration,
            "auto": True
        })

    return {"plugin": "TestSSL", "result": items}
