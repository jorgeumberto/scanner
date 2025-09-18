# plugins/whois_dnssec.py
from typing import Dict, Any, List
from utils import run_cmd, Timer, extrair_host

PLUGIN_CONFIG_NAME = "whois_dnssec"
PLUGIN_CONFIG_ALIASES = ["whois", "dnssec"]

UUID_009 = "uuid-009-whois_dnssec"  # (9) WHOIS / DNSSEC

def _pick(lines: List[str], keys: List[str]) -> List[str]:
    out = []
    for k in keys:
        for ln in lines:
            if k.lower() in ln.lower():
                out.append(ln.strip()); break
    return out

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    host = extrair_host(target)

    evid: List[str] = []
    with Timer() as t:
        who = run_cmd(["whois", host], timeout=timeout)
        lines = who.splitlines()
        evid += _pick(lines, [
            "Registrar", "Creation Date", "Registry Expiry Date",
            "Registrant Organization", "Registrant Country"
        ])

        dig = run_cmd(["dig", "+dnssec", host], timeout=timeout)
        has_ad = any(" flags:" in ln and " ad;" in ln for ln in dig.splitlines())
        evid.append("DNSSEC: validação AD presente" if has_ad else "DNSSEC: sem flag AD")

    sev = "info" if has_ad else "low"
    summary = "\n".join(f"- {e}" for e in evid) if evid else "Nenhum achado para WHOIS / DNSSEC"

    item = {

        "scan_item_uuid": UUID_009,
        "result": summary,
        "analysis_ai": ai_fn("WhoisDNSSEC", UUID_009, summary),
        "severity": sev,
        "duration": t.duration,
        "auto": True,
        "reference": "https://en.wikipedia.org/wiki/WHOIS",
        "item_name": "WHOIS and DNSSEC Information",
    }

    return {
        "plugin": "WhoisDNSSEC", 
        "file_name": "whois_dnssec.py",
        "description": "Consulta informações WHOIS e verifica se DNSSEC está habilitado.",
        "category": "Information Gathering",        
        "result": [item]}
