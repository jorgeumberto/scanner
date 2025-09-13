# plugins/rate_limit_check.py
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "rate_limit_check"
PLUGIN_CONFIG_ALIASES = ["rate_limit", "rl_check"]

UUID_084 = "uuid-084"  # (84) Rate limiting aplicado a endpoints sensíveis

def _one_request(url: str, timeout: int) -> str:
    # mostra apenas status line + tempo total
    cmd = ["bash","-lc", f'/usr/bin/time -f "%es" curl -o /dev/null -sS -w "%{{http_code}}" -m {timeout} "{url}"']
    return run_cmd(cmd, timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg:
    { "timeout": 10, "path": "/login", "bursts": 3, "reqs_per_burst": 8, "sleep_s": 1 }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 10))
    path    = cfg.get("path", "/")
    bursts  = int(cfg.get("bursts", 3))
    rpb     = int(cfg.get("reqs_per_burst", 8))
    sleep_s = int(cfg.get("sleep_s", 1))

    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    evid: List[str] = []
    all_codes: List[str] = []
    all_times: List[float] = []

    with Timer() as t:
        for b in range(bursts):
            evid.append(f"Burst {b+1}:")
            for i in range(rpb):
                out = _one_request(url, timeout)  # exemplo de saida: "200\n0.12s"
                # parse simples (codigo + segunda linha tempo)
                parts = [p for p in out.strip().splitlines() if p.strip()]
                code = parts[0][-3:] if parts else "???"
                secs = 0.0
                if len(parts) > 1 and parts[1].endswith("s"):
                    try: secs = float(parts[1][:-1])
                    except: pass
                all_codes.append(code); all_times.append(secs)
                evid.append(f"  - {code} em {secs:.2f}s")
            run_cmd(["bash","-lc", f"sleep {sleep_s}"], timeout=sleep_s+1)

    # heurística: sem 429/403/401 e tempos estáveis => possivelmente sem rate limit
    has_429 = any(c == "429" for c in all_codes)
    has_403 = any(c == "403" for c in all_codes)
    has_401 = any(c == "401" for c in all_codes)
    sev = "low" if (has_429 or has_403 or has_401) else "info"
    if has_429:
        evid.append("Sinal: HTTP 429 detectado — rate limit aparente.")
    elif has_403 or has_401:
        evid.append("Sinal: HTTP 403/401 em bursts — pode haver controle de abuso.")
    else:
        evid.append("Nenhum sinal claro de rate limiting (checagem leve).")

    summary = "\n".join(f"- {e}" for e in evid)
    item = {
        "plugin_uuid": UUID_084,
        "scan_item_uuid": UUID_084,
        "result": summary,
        "analysis_ai": ai_fn("RateLimitCheck", UUID_084, summary),
        "severity": sev,
        "duration": t.duration,
        "auto": True
    }
    return {"plugin": "RateLimitCheck", "result": [item]}
