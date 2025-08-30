# plugins/dkim_check.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer, extract_host

PLUGIN_CONFIG_NAME = "dkim_check"
PLUGIN_CONFIG_ALIASES = ["dkim", "dns_dkim"]

# UUID placeholder — troque pelo UUID real do item 14
UUID_014 = "uuid-014"

COMMON_SELECTORS = [
    "default", "selector1", "selector2", "google", "mail", "mandrill", "k1", "s1", "s2",
    "smtp", "postfix", "dkim", "mailgun", "sendgrid", "amazonses", "sparkpost", "zoho"
]

def _dig_txt(name: str, timeout: int) -> str:
    return run_cmd(["dig", "+short", name, "TXT"], timeout=timeout)

def _summarize(lines: List[str], checklist_name: str, max_lines: int = 10) -> str:
    if not lines:
        return f"Nenhum achado para {checklist_name}"
    body = [f"- {l}" for l in lines[:max_lines]]
    extra = len(lines) - len(body)
    if extra > 0:
        body.append(f"... +{extra} registros DKIM")
    return "\n".join(body)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/dkim_check.json):
    {
      "timeout": 15,
      "selectors": ["default","selector1","selector2"]
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    sels = cfg.get("selectors") or COMMON_SELECTORS

    domain = extract_host(target)
    found: List[str] = []

    with Timer() as t:
        for sel in sels:
            qname = f"{sel}._domainkey.{domain}"
            out = _dig_txt(qname, timeout)
            if out and out.strip():
                # junta em linha única
                out_clean = out.replace('" "', '').replace('"', '').replace("\n", " ").strip()
                found.append(f"{qname} :: {out_clean[:300]}")
    duration = t.duration

    # severidade: se nenhum DKIM encontrado nos selectors testados -> medium
    severity = "info" if found else "medium"
    result = _summarize(found, "DKIM publicado")

    return {
        "plugin": "DKIMCheck",
        "result": [{
            "plugin_uuid": UUID_014,
            "scan_item_uuid": UUID_014,
            "result": result,
            "analysis_ai": ai_fn("DKIMCheck", UUID_014, result),
            "severity": severity,
            "duration": duration,
            "auto": True
        }]
    }
