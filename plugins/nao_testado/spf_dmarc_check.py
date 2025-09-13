# plugins/spf_dmarc_check.py
from typing import Dict, Any, List
from utils import run_cmd, Timer, extrair_host

PLUGIN_CONFIG_NAME = "spf_dmarc_check"
PLUGIN_CONFIG_ALIASES = ["spf_dmarc", "dns_spf_dmarc"]

UUID_012 = "uuid-012"  # (12) SPF presente
UUID_013 = "uuid-013"  # (13) DMARC presente

def _dig_txt(name: str, timeout: int) -> str:
    return run_cmd(["dig", "+short", name, "TXT"], timeout=timeout)

def _has_spf(txt: str) -> bool:
    return "v=spf1" in txt.lower()

def _has_dmarc(txt: str) -> bool:
    return "v=dmarc1" in txt.lower()

def _summarize(lines: List[str], checklist_name: str, max_lines: int = 10) -> str:
    if not lines:
        return f"Nenhum achado para {checklist_name}"
    body = [f"- {l}" for l in lines[:max_lines]]
    extra = len(lines) - len(body)
    if extra > 0:
        body.append(f"... +{extra} registros")
    return "\n".join(body)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    domain = extrair_host(target)

    evid_spf: List[str] = []
    evid_dmarc: List[str] = []

    with Timer() as t:
        # SPF no apex
        spf = _dig_txt(domain, timeout)
        spf_clean = spf.replace('" "', '').replace('"', '').replace("\n", " ").strip()
        if spf_clean:
            evid_spf.append(f"{domain} :: {spf_clean}")
        # DMARC em _dmarc.domain
        dname = f"_dmarc.{domain}"
        dmarc = _dig_txt(dname, timeout)
        dmarc_clean = dmarc.replace('" "', '').replace('"', '').replace("\n", " ").strip()
        if dmarc_clean:
            evid_dmarc.append(f"{dname} :: {dmarc_clean}")

    duration = t.duration

    has_spf = _has_spf(spf_clean) if spf_clean else False
    has_dmarc = _has_dmarc(dmarc_clean) if dmarc_clean else False

    res_spf = _summarize(evid_spf, "SPF (TXT v=spf1)")
    res_dmarc = _summarize(evid_dmarc, "DMARC (TXT v=DMARC1)")

    # severidade: ausência de SPF/DMARC = medium
    sev_spf = "info" if has_spf else "medium"
    sev_dmarc = "info" if has_dmarc else "medium"

    return {
        "plugin": "SPF_DMARC_Check",
        "result": [
            {
                "plugin_uuid": UUID_012,
                "scan_item_uuid": UUID_012,
                "result": res_spf,
                "analysis_ai": ai_fn("SPF_DMARC_Check", UUID_012, res_spf),
                "severity": sev_spf,
                "duration": duration,
                "auto": True
            },
            {
                "plugin_uuid": UUID_013,
                "scan_item_uuid": UUID_013,
                "result": res_dmarc,
                "analysis_ai": ai_fn("SPF_DMARC_Check", UUID_013, res_dmarc),
                "severity": sev_dmarc,
                "duration": duration,
                "auto": True
            }
        ]
    }
