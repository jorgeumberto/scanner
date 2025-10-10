# plugins/dos_basic_check.py
from typing import Dict, Any, List
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "dos_basic_check"
PLUGIN_CONFIG_ALIASES = ["dos", "loadcheck"]

UUID_085 = "uuid-085-dos"  # (85) Proteção básica contra DoS (app/infra)

REFERENCE_URL = "https://owasp.org/www-community/attacks/Denial_of_Service"

def _tool_exists(tool: str) -> bool:
    return "OK" in out

def _run_ab(target: str, n: int, c: int, timeout: int) -> List[str]:
    """
    Executa 'ab' e retorna apenas linhas de interesse resumidas.
    """
    try:
        out = run_cmd(["ab", "-n", str(n), "-c", str(c), target], timeout=timeout)
    except Exception as e:
        return [f"Falha ao executar ab: {e}"]
    lines: List[str] = []
    keys = ["Requests per second", "Failed requests", "Non-2xx responses", "Time per request"]
    for ln in out.splitlines():
        if any(k in ln for k in keys):
            lines.append(ln.strip())
    if not lines:
        lines.append("ab executado, porém sem métricas padrão detectadas (ver saída completa no console).")
    return lines

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
    tool = str(cfg.get("tool", "ab")).lower()
    n = int(cfg.get("requests", 100))
    c = int(cfg.get("concurrency", 10))
    timeout = int(cfg.get("timeout", 20))

    evid: List[str] = []
    command = ""

    with Timer() as t:
        if tool == "ab":
            if _tool_exists("ab"):
                command = f"ab -n {n} -c {c} {target}"
                evid.extend(_run_ab(target, n, c, timeout))
            else:
                evid.append("Ferramenta 'ab' não encontrada; instale 'apache2-utils' (ou equivalente).")
        elif tool == "slowloris":
            if _tool_exists("slowloris"):
                command = "slowloris <host> --test (não executado: modo dry por segurança)"
                evid.append("slowloris disponível; teste prolongado NÃO executado por segurança.")
            else:
                evid.append("Ferramenta 'slowloris' não encontrada; considere instalar para testes controlados.")
        else:
            evid.append(f"Ferramenta não suportada: {tool}. Use 'ab' ou 'slowloris'.")

    sev = "info"
    summary = "\n".join(f"- {e}" for e in evid) if evid else "Nenhum achado para DoS básico (checagem leve)"

    item = {
        "plugin_uuid": UUID_085,
        "scan_item_uuid": UUID_085,
        "result": summary,
        "analysis_ai": ai_fn("DosBasicCheck", UUID_085, summary),
        "severity": sev,
        "duration": t.duration,
        "auto": True,
        "reference": REFERENCE_URL,
        "item_name": "Basic DoS/Load Handling Check",
        "command": command
    }

    return {
        "plugin": "DosBasicCheck",
        "plugin_uuid": UUID_085,
        "file_name": "dos_basic_check.py",
        "description": "Checagem leve de resiliência a DoS com ferramentas de carga (ab) ou verificação de disponibilidade de slowloris (modo seguro).",
        "category": "Availability & Resilience",
        "result": [item]
    }