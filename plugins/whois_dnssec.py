# plugins/whois_dnssec.py
import re
from typing import Dict, Any, List
from utils import run_cmd, Timer, extract_host

# Ajuda o main dinâmico a achar configs/whois_dnssec.json
PLUGIN_CONFIG_NAME = "whois_dnssec"
PLUGIN_CONFIG_ALIASES = ["whois", "dnssec"]

# UUID placeholder — troque pelo UUID real do item 9
UUID_9 = "uuid-009"

def _parse_whois(raw: str) -> Dict[str, Any]:
    """
    Extrai dados relevantes do WHOIS: registrar, creation date, expiration, org/email.
    """
    data = {}
    if not raw:
        return data
    for line in raw.splitlines():
        low = line.lower()
        if "registrar:" in low and "registrar whois server" not in low:
            data["registrar"] = line.split(":",1)[1].strip()
        elif "creation date:" in low:
            data["creation_date"] = line.split(":",1)[1].strip()
        elif "expiry date:" in low or "expiration date:" in low:
            data["expiration_date"] = line.split(":",1)[1].strip()
        elif "org:" in low or "organization:" in low:
            data["organization"] = line.split(":",1)[1].strip()
        elif "email:" in low:
            data["email"] = line.split(":",1)[1].strip()
    return data

def _parse_dnssec(raw: str) -> str:
    """
    Verifica se DNSSEC está habilitado via dig +dnssec.
    """
    if not raw:
        return "DNSSEC não detectado"
    if "ad" in raw.lower() or "dnssec" in raw.lower():
        return "DNSSEC possivelmente habilitado"
    return "DNSSEC não detectado"

def _summarize(whois_data: Dict[str, Any], dnssec_status: str) -> str:
    if not whois_data and "não" in dnssec_status.lower():
        return "Nenhum achado para WHOIS/DNSSEC"
    lines = []
    if whois_data:
        if "registrar" in whois_data:
            lines.append(f"Registrar: {whois_data['registrar']}")
        if "organization" in whois_data:
            lines.append(f"Org: {whois_data['organization']}")
        if "email" in whois_data:
            lines.append(f"Email: {whois_data['email']}")
        if "creation_date" in whois_data:
            lines.append(f"Criado em: {whois_data['creation_date']}")
        if "expiration_date" in whois_data:
            lines.append(f"Expira em: {whois_data['expiration_date']}")
    lines.append(dnssec_status)
    return "\n".join(lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/whois_dnssec.json:
    {
      "timeout": 60
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 60))
    domain = extract_host(target)

    with Timer() as t:
        whois_raw = run_cmd(["whois", domain], timeout=timeout)
        dnssec_raw = run_cmd(["dig", domain, "+dnssec"], timeout=timeout)
    duration = t.duration

    whois_data = _parse_whois(whois_raw)
    dnssec_status = _parse_dnssec(dnssec_raw)
    summary = _summarize(whois_data, dnssec_status)

    severity = "info"
    if not whois_data and "não" in dnssec_status.lower():
        severity = "info"

    items: List[Dict[str, Any]] = []
    items.append({
        "plugin_uuid": UUID_9,
        "scan_item_uuid": UUID_9,
        "result": summary,
        "analysis_ai": ai_fn("WhoisDNSSEC", UUID_9, summary),
        "severity": severity,
        "duration": duration,
        "auto": True
    })

    return {"plugin": "WhoisDNSSEC", "result": items}
