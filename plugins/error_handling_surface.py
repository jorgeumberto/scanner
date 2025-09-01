# plugins/error_handling_surface.py
from typing import Dict, Any, List
from urllib.parse import urljoin, quote_plus
from utils import run_cmd, Timer
import re, random, string

PLUGIN_CONFIG_NAME = "error_handling_surface"
PLUGIN_CONFIG_ALIASES = ["error_surface","errors_probe"]
UUID_072 = "uuid-072"  # (72) Stack traces/mensagens detalhadas
UUID_073 = "uuid-073"  # (73) Páginas de erro personalizadas
UUID_074 = "uuid-074"  # (74) Erros não vazam dados sensíveis

STACK_TOKENS = [
    "traceback", "stack trace", "exception", "fatal error", "nullreference",
    "referenceerror", "undefined index", "notice: ", "warning:", "stacktrace", "at "
]
SENSITIVE_TOKENS = ["password", "apikey", "secret", "dsn=", "jdbc:", "aws_access_key_id", "Authorization:"]
ERROR_PATHS = ["/this/definitely/does/not/exist", "/?q='\"><script", "/%00", "/../../../../etc/passwd"]

def _get(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}"'], timeout=timeout+2)

def _head(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -I -L -m {timeout} "{url}"'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any] = None):
    """
    cfg: { "timeout": 15, "paths": [ ... ] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    paths = cfg.get("paths") or ERROR_PATHS

    evid72: List[str] = []
    evid73: List[str] = []
    evid74: List[str] = []
    s_hits = 0
    v_hits = 0

    with Timer() as t:
        for p in paths:
            url = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            body = _get(url, timeout)
            head = _head(url, timeout)
            low  = body.lower()

            if any(tok in low for tok in STACK_TOKENS):
                s_hits += 1
                evid72.append(f"{p}: stack/exception visível (amostra): {body[:160].replace('\\n',' ')}")

            if "404" in head or "403" in head or "500" in head:
                # heurística simples de “página personalizada” se título/estilo presente
                if re.search(r"<html|<title|class=|style=", body, re.I):
                    evid73.append(f"{p}: página de erro com HTML estruturado (parece custom).")
                else:
                    evid73.append(f"{p}: resposta de erro sem HTML estruturado (padrão do servidor?).")

            if any(tok in low for tok in SENSITIVE_TOKENS):
                v_hits += 1
                evid74.append(f"{p}: termos sensíveis aparentes (trecho suprimido).")

    sev72 = "medium" if s_hits else "info"
    sev74 = "medium" if v_hits else "info"

    res72 = "\n".join(f"- {e}" for e in evid72) if evid72 else "Sem stacktraces aparentes na superfície"
    res73 = "\n".join(f"- {e}" for e in evid73) if evid73 else "Não foi possível inferir página de erro personalizada"
    res74 = "\n".join(f"- {e}" for e in evid74) if evid74 else "Sem vazamentos textuais óbvios em erros"

    return {
        "plugin": "ErrorHandlingSurface",
        "result": [
            {
                "plugin_uuid": UUID_072, "scan_item_uuid": UUID_072,
                "result": res72,
                "analysis_ai": ai_fn("ErrorHandlingSurface", UUID_072, res72),
                "severity": sev72, "duration": t.duration, "auto": True
            },
            {
                "plugin_uuid": UUID_073, "scan_item_uuid": UUID_073,
                "result": res73,
                "analysis_ai": ai_fn("ErrorHandlingSurface", UUID_073, res73),
                "severity": "info", "duration": t.duration, "auto": True
            },
            {
                "plugin_uuid": UUID_074, "scan_item_uuid": UUID_074,
                "result": res74,
                "analysis_ai": ai_fn("ErrorHandlingSurface", UUID_074, res74),
                "severity": sev74, "duration": t.duration, "auto": True
            }
        ]
    }
