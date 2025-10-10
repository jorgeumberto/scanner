# plugins/error_handling_surface.py
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import run_cmd, Timer
import re

PLUGIN_CONFIG_NAME = "error_handling_surface"
PLUGIN_CONFIG_ALIASES = ["error_surface","errors_probe"]

UUID_072 = "uuid-072-stacktrace"        # (72) Stack traces/mensagens detalhadas
UUID_073 = "uuid-073-custom-errors"             # (73) Páginas de erro personalizadas
UUID_074 = "uuid-074-sensitive-errors"     # (74) Erros não vazam dados sensíveis

# Referências úteis
REFERENCE_072 = "https://owasp.org/www-community/Improper_Error_Handling"
REFERENCE_073 = "https://cheatsheetseries.owasp.org/cheatsheets/Improper_Error_Handling_Cheat_Sheet.html"
REFERENCE_074 = "https://owasp.org/www-community/attacks/Information_disclosure_through_error_messages"

STACK_TOKENS = [
    "traceback", "stack trace", "exception", "fatal error", "nullreference",
    "referenceerror", "undefined index", "notice: ", "warning:", "stacktrace", "at "
]
SENSITIVE_TOKENS = ["password", "apikey", "secret", "dsn=", "jdbc:", "aws_access_key_id", "authorization:"]
ERROR_PATHS = ["/this/definitely/does/not/exist", "/?q='\"><script", "/%00", "/../../../../etc/passwd"]

MAX_SNIPPET = 160

def _get(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}"'], timeout=timeout+2)

def _head(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sS -I -L -m {timeout} "{url}"'], timeout=timeout+2)

def _sanitize_snippet(s: str, limit: int = MAX_SNIPPET) -> str:
    if not s:
        return ""
    s = s.replace("\r", " ").replace("\n", " ")
    return s[:limit]

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
            base = target.rstrip("/") + "/"
            url = urljoin(base, p.lstrip("/"))
            body = _get(url, timeout)
            head = _head(url, timeout)
            low  = body.lower()

            # 72: Stack traces / mensagens detalhadas
            if any(tok in low for tok in STACK_TOKENS):
                s_hits += 1
                evid72.append(f"{p}: stack/exception visível (amostra): { _sanitize_snippet(body) }")
                evid73.append(f"{p}: página de erro com HTML estruturado (parece custom).")
            else:
                evid73.append(f"{p}: resposta de erro sem HTML estruturado (padrão do servidor?).")

            # 74: Vazamentos textuais em erros
            if any(tok in low for tok in SENSITIVE_TOKENS):
                v_hits += 1
                evid74.append(f"{p}: termos sensíveis aparentes (trecho suprimido).")

    # Severidades
    sev72 = "medium" if s_hits else "info"
    sev73 = "info"  # mantido informativo; pode ser elevado conforme política
    sev74 = "medium" if v_hits else "info"

    # Resultados formatados
    res72 = "\n".join(f"- {e}" for e in evid72) if evid72 else "Sem stacktraces aparentes na superfície"
    res73 = "\n".join(f"- {e}" for e in evid73) if evid73 else "Não foi possível inferir página de erro personalizada"
    res74 = "\n".join(f"- {e}" for e in evid74) if evid74 else "Sem vazamentos textuais óbvios em erros"

    # Comandos reproduzíveis (templates concatenados por ; para o primeiro path)
    path_example = (paths[0] if paths else "/")
    url_example = urljoin(target.rstrip("/") + "/", path_example.lstrip("/"))
    command_example = f'curl -sS -L -m {timeout} "{url_example}"; curl -sS -I -L -m {timeout} "{url_example}"'

    items = [
        {
            "plugin_uuid": UUID_072,
            "scan_item_uuid": UUID_072,
            "result": res72,
            "analysis_ai": ai_fn("ErrorHandlingSurface", UUID_072, res72),
            "severity": sev72,
            "duration": t.duration,
            "auto": True,
            "reference": REFERENCE_072,
            "item_name": "Stack Traces / Detailed Errors Exposure",
            "command": command_example
        },
        {
            "plugin_uuid": UUID_073,
            "scan_item_uuid": UUID_073,
            "result": res73,
            "analysis_ai": ai_fn("ErrorHandlingSurface", UUID_073, res73),
            "severity": sev73,
            "duration": t.duration,
            "auto": True,
            "reference": REFERENCE_073,
            "item_name": "Custom Error Pages Detection",
            "command": command_example
        },
        {
            "plugin_uuid": UUID_074,
            "scan_item_uuid": UUID_074,
            "result": res74,
            "analysis_ai": ai_fn("ErrorHandlingSurface", UUID_074, res74),
            "severity": sev74,
            "duration": t.duration,
            "auto": True,
            "reference": REFERENCE_074,
            "item_name": "Sensitive Data Exposure in Error Responses",
            "command": command_example
        }
    ]

    return {
        "plugin": "ErrorHandlingSurface",
        "plugin_uuid": UUID_072,  # usa o principal como identificador do plugin
        "file_name": "error_handling_surface.py",
        "description": "Probes common error surfaces for stack traces, custom error pages, and sensitive data leakage.",
        "category": "Server-Side Testing",
        "result": items
    }