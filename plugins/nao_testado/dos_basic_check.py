# plugins/dos_basic_check.py
from typing import Dict, Any, List
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "dos_basic_check"
PLUGIN_CONFIG_ALIASES = ["dos", "loadcheck"]

UUID_085 = "uuid-085"  # (85) Proteção básica contra DoS (app/infra)

def _tool_exists(tool: str) -> bool:
    out = run_cmd(["bash", "-lc", f"command -v {tool} >/dev/null 2>&1 && echo OK || true"], timeout=5)
    return "OK" in out

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/dos_basic_check.json):
    {
      "tool": "ab",        # "ab" (ApacheBench) | "slowloris"
      "requests": 100,     # para ab: -n
      "concurrency": 10,   # para ab: -c
      "timeout": 20
    }
    """
    cfg = cfg or {}
    tool = cfg.get("tool", "ab")
    n    = str(cfg.get("requests", 100))
    c    = str(cfg.get("concurrency", 10))
    timeout = int(cfg.get("timeout", 20))

    evid: List[str] = []
    with Timer() as t:
        if tool == "ab" and _tool_exists("ab"):
            # ab -n 100 -c 10 http://site/
            out = run_cmd(["ab", "-n", n, "-c", c, target], timeout=timeout)
            for ln in out.splitlines():
                if any(k in ln for k in ["Requests per second", "Failed requests", "Non-2xx responses", "Time per request"]):
                    evid.append(ln.strip())
        elif tool == "slowloris" and _tool_exists("slowloris"):
            # slowloris test "dry": apenas verifica execução básica (não roda ataque prolongado)
            evid.append("slowloris disponível; teste prolongado NÃO executado por segurança")
        else:
            evid.append("Ferramenta não encontrada; considere instalar 'ab' (apache2-utils) ou 'slowloris'.")

    sev = "info"
    summary = "\n".join(f"- {e}" for e in evid) if evid else "Nenhum achado para DoS básico (checagem leve)"

    item = {
        "plugin_uuid": UUID_085,
        "scan_item_uuid": UUID_085,
        "result": summary,
        "analysis_ai": ai_fn("DosBasicCheck", UUID_085, summary),
        "severity": sev,
        "duration": t.duration,
        "auto": True
    }
    return {"plugin": "DosBasicCheck", "result": [item]}
