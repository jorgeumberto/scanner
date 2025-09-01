# plugins/wfuzz_open_redirect.py
from typing import Dict, Any, List
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "wfuzz_open_redirect"
PLUGIN_CONFIG_ALIASES = ["openredirect", "redir"]

UUID_035 = "uuid-035"  # (35) open redirect

# payloads típicos
DEFAULT_PAYLOADS = [
  "https://google.com",
  "https://example.com",
  "//google.com",
  "////google.com",
  "http://google.com",
  "///example.com/%2f%2e%2e",
  "https://evil.com"
]

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/wfuzz_open_redirect.json):
    {
      "param": "next",             # parâmetro para fuzz
      "payloads": ["https://google.com", "//google.com"],
      "timeout": 30,
      "filter_code": "302,301,300", # HTTP que consideramos redirect
      "extra_args": []
    }
    """
    cfg = cfg or {}
    param = cfg.get("param", "next")
    payloads = cfg.get("payloads") or DEFAULT_PAYLOADS
    timeout = int(cfg.get("timeout", 30))
    filt = cfg.get("filter_code", "302,301")
    extra = cfg.get("extra_args") or []

    hits: List[str] = []
    with Timer() as t:
        # wfuzz -z list,PA1,PA2 --hc 404 --hl 0 http://site/?next=FUZZ
        # aqui filtramos por códigos de redirect (–sc) quando possível; simplificado:
        base = ["wfuzz", "-z", "list," + ",".join(payloads), target + (("&" if "?" in target else "?") + f"{param}=FUZZ")]
        base = base[:-1] + extra + base[-1:]
        out = run_cmd(base, timeout=timeout)

        # parser simples: linhas com "C=301" ou "C=302"
        for ln in out.splitlines():
            ln = ln.strip()
            if "C=30" in ln or "code: 30" in ln.lower():
                hits.append(ln)

    sev = "medium" if hits else "info"
    summary = "\n".join(f"- {h}" for h in hits) if hits else "Nenhum achado para Open Redirect"

    item = {
        "plugin_uuid": UUID_035,
        "scan_item_uuid": UUID_035,
        "result": summary,
        "analysis_ai": ai_fn("WfuzzOpenRedirect", UUID_035, summary),
        "severity": sev,
        "duration": t.duration,
        "auto": True
    }
    return {
        "plugin": "WfuzzOpenRedirect",
        "result": [item]
    }
