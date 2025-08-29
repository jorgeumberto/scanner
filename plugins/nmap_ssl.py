# plugins/nmap_ssl.py
from typing import Dict, Any, List, Tuple
import re
from datetime import datetime

from utils import run_cmd, Timer, extract_host

# UUIDs placeholders — substitua pelos UUIDs reais (IDs 75–78)
UUIDS = {
    75: "uuid-075",  # Somente TLS 1.2+ habilitado (SSLv2/3/TLS1.0/1.1 off)
    76: "uuid-076",  # Cifras fracas desabilitadas (RC4/NULL/EXPORT)
    77: "uuid-077",  # Certificado válido (CA, CN/SAN, expiração)
    78: "uuid-078",  # Assinatura/chave fortes (SHA-256+, RSA≥2048/ECDSA)
}

# ---------------- Parsers ----------------

PROTO_RE = re.compile(r"^\|\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s*:", re.I)
NOT_SUP_RE = re.compile(r"^\|\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+not\s+supported", re.I)

WEAK_TOKENS_DEFAULT = ["RC4", "NULL", "EXP", "EXPORT", "DES", "3DES", "MD5", "aNULL", "eNULL"]

def _parse_protocols(nmap_out: str) -> Tuple[List[str], List[str]]:
    """
    A partir do output do ssl-enum-ciphers, retorna (enabled, mentioned_as_not_supported).
    Considera linhas:
      |  TLSv1.2:
      |  SSLv3 not supported
    """
    enabled = set()
    not_supported = set()
    for line in nmap_out.splitlines():
        line = line.rstrip()
        m = PROTO_RE.match(line)
        if m:
            enabled.add(m.group(1))
            continue
        m2 = NOT_SUP_RE.match(line)
        if m2:
            not_supported.add(m2.group(1))
    return sorted(enabled), sorted(not_supported)

def _parse_weak_ciphers(nmap_out: str, weak_tokens: List[str]) -> List[str]:
    """
    Heurística: qualquer linha com 'cipher' ou lista de cifras,
    se contém um token fraco conhecido, marca.
    """
    found = set()
    for line in nmap_out.splitlines():
        low = line.lower()
        if "cipher" in low or "ciphers:" in low:
            for t in weak_tokens:
                if t.lower() in low:
                    found.add(t.upper())
    return sorted(found)

# ssl-cert parsers (heurísticos)
def _extract_cert_section(nmap_out: str) -> str:
    """
    Extrai apenas a seção do script ssl-cert (texto após 'ssl-cert:').
    """
    buff = []
    capture = False
    for line in nmap_out.splitlines():
        if "ssl-cert:" in line:
            capture = True
            buff.append(line)
            continue
        if capture:
            if line.startswith("|_") or line.startswith("| ") or line.startswith("|"):
                buff.append(line)
            else:
                # saiu do bloco
                break
    return "\n".join(buff)

def _parse_cert_info(cert_block: str) -> Dict[str, Any]:
    """
    Tenta extrair:
      - subject / CN
      - issuer
      - not_before / not_after
      - key bits (RSA/ECDSA)
      - signature algorithm
    """
    info: Dict[str, Any] = {}

    # Subject / CN
    m = re.search(r"Subject:\s*(.*)", cert_block, re.I)
    if m:
        info["subject"] = m.group(1).strip()

    # Issuer
    m = re.search(r"Issuer:\s*(.*)", cert_block, re.I)
    if m:
        info["issuer"] = m.group(1).strip()

    # Validity
    m = re.search(r"Not valid before:\s*([^\n]+)", cert_block, re.I)
    if m:
        info["not_before"] = m.group(1).strip()
    m = re.search(r"Not valid after\s*:?\s*([^\n]+)", cert_block, re.I)
    if m:
        info["not_after"] = m.group(1).strip()

    # Public key bits
    m = re.search(r"Public Key bits:\s*(\d+)", cert_block, re.I)
    if m:
        info["key_bits"] = m.group(1)
    else:
        m = re.search(r"(\d+)\s*bit", cert_block, re.I)
        if m:
            info["key_bits"] = m.group(1)

    # Signature Algorithm
    m = re.search(r"Signature Algorithm:\s*([A-Za-z0-9\-]+)", cert_block, re.I)
    if m:
        info["sig_alg"] = m.group(1).upper()

    return info

def _is_expired(not_after: str) -> bool:
    """
    Tenta inferir expiração. Formatos comuns do nmap ssl-cert:
      2026-07-19T12:34:56
      2026-07-19 12:34:56
      Jul 19 12:34:56 2026 GMT
    Se falhar parsing, retorna False (não acusa expirado por incerteza).
    """
    if not not_after:
        return False
    s = not_after.strip()
    fmts = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S %Y %Z",
        "%Y-%m-%d",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            return dt < datetime.utcnow()
        except Exception:
            continue
    return False

# ---------------- Plugin ----------------

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/nmap_ssl.json:
    {
      "timeout": 180,
      "ports": [443],
      "danger_protocols": ["SSLv2","SSLv3","TLSv1.0","TLSv1.1"],
      "weak_tokens": ["RC4","NULL","EXP","EXPORT","DES","3DES","MD5","aNULL","eNULL"]
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 180))
    ports = cfg.get("ports") or [443]
    danger_protocols = set(cfg.get("danger_protocols") or ["SSLv2","SSLv3","TLSv1.0","TLSv1.1"])
    weak_tokens = cfg.get("weak_tokens") or WEAK_TOKENS_DEFAULT

    host = extract_host(target)
    items: List[Dict[str, Any]] = []

    # Executa nmap uma vez para cada porta e agrega
    prot_enabled_all: Dict[int, List[str]] = {}
    weak_all: Dict[int, List[str]] = {}
    cert_info_any: Dict[str, Any] = {}

    # Rodamos ssl-enum-ciphers e ssl-cert juntos para cada porta
    for p in ports:
        with Timer() as t:
            out = run_cmd(
                ["nmap", "-Pn", "-p", str(p), "--script", "ssl-enum-ciphers,ssl-cert", host],
                timeout=timeout
            )
        duration = t.duration

        # protocols + weak ciphers
        enabled, not_sup = _parse_protocols(out)
        prot_enabled_all[p] = enabled
        weak = _parse_weak_ciphers(out, weak_tokens)
        weak_all[p] = weak

        # cert (pegamos da primeira porta que tiver)
        if not cert_info_any:
            cert_block = _extract_cert_section(out)
            if cert_block:
                cert_info_any = _parse_cert_info(cert_block)

    # ---------- 75) Protocolos ----------
    # Consolida por porta
    sections = []
    any_danger = False
    for p in ports:
        en = prot_enabled_all.get(p, [])
        if not en:
            sections.append(f"[{p}] protocolos: (não identificado)")
            continue
        en_txt = ", ".join(en)
        sections.append(f"[{p}] protocolos: {en_txt}")
        if set(en).intersection(danger_protocols):
            any_danger = True

    res75 = "\n".join(sections) if sections else "Sem dados de protocolos"
    sev75 = "high" if any_danger else ("info" if sections else "low")
    items.append({
        "plugin_uuid": UUIDS[75],
        "scan_item_uuid": UUIDS[75],
        "result": res75,
        "analysis_ai": ai_fn("NmapSSL", UUIDS[75], res75),
        "severity": sev75,
        "duration": duration if ports else 0.0,
        "auto": True
    })

    # ---------- 76) Cifras fracas ----------
    weak_sections = []
    has_weak = False
    for p in ports:
        w = weak_all.get(p, [])
        if w:
            has_weak = True
            weak_sections.append(f"[{p}] fracas: {', '.join(w)}")
    if has_weak:
        res76 = "\n".join(weak_sections)
        sev76 = "medium"
    else:
        res76 = "Nenhuma cifra fraca típica detectada"
        sev76 = "info"
    items.append({
        "plugin_uuid": UUIDS[76],
        "scan_item_uuid": UUIDS[76],
        "result": res76,
        "analysis_ai": ai_fn("NmapSSL", UUIDS[76], res76),
        "severity": sev76,
        "duration": duration if ports else 0.0,
        "auto": True
    })

    # ---------- 77) Certificado válido ----------
    if cert_info_any:
        not_after = cert_info_any.get("not_after", "")
        expired = _is_expired(not_after)
        issuer  = cert_info_any.get("issuer", "?")
        subject = cert_info_any.get("subject", "?")
        if expired:
            res77 = f"Certificado EXPIRADO | Issuer: {issuer} | Subject: {subject} | NotAfter: {not_after}"
            sev77 = "high"
        else:
            res77 = f"Issuer: {issuer} | Subject: {subject} | Validade até: {not_after or '?'}"
            sev77 = "info" if not_after else "low"
    else:
        res77 = "Não foi possível extrair informações do certificado"
        sev77 = "low"
    items.append({
        "plugin_uuid": UUIDS[77],
        "scan_item_uuid": UUIDS[77],
        "result": res77,
        "analysis_ai": ai_fn("NmapSSL", UUIDS[77], res77),
        "severity": sev77,
        "duration": duration if ports else 0.0,
        "auto": True
    })

    # ---------- 78) Assinatura/chave ----------
    bits_s = cert_info_any.get("key_bits")
    try:
        bits = int(bits_s) if bits_s else 0
    except Exception:
        bits = 0
    sig = (cert_info_any.get("sig_alg") or "").upper()
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
        "analysis_ai": ai_fn("NmapSSL", UUIDS[78], res78),
        "severity": sev78,
        "duration": duration if ports else 0.0,
        "auto": True
    })

    return {"plugin": "NmapSSL", "result": items}
