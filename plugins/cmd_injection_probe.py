# plugins/cmd_injection_probe.py
from typing import Dict, Any
from utils import run_cmd, Timer
from urllib.parse import urljoin, quote_plus

PLUGIN_CONFIG_NAME = "cmd_injection_probe"
PLUGIN_CONFIG_ALIASES = ["cmdi"]
UUID_053 = "uuid-053-cmdinj"  # (53)

REFERENCE_URL = "https://owasp.org/www-community/attacks/Command_Injection"

def _curl(url: str, timeout: int) -> str:
    # Retorna corpo; sem -i para reduzir ruído. TIME_OK é marcador para evitar buffering.
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}" -w "\\nTIME_OK"'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: {
      "enabled": false,
      "timeout": 12,
      "path": "/ping?host=",
      "param": "host",
      "sleep_seconds": 2,
      "benign_value": "127.0.0.1"
    }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoint seguro)."
        item = {
            "plugin_uuid": UUID_053,
            "scan_item_uuid": UUID_053,
            "result": txt,
            "analysis_ai": ai_fn("CmdInjectionProbe", UUID_053, txt),
            "severity": "info",
            "duration": 0.0,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": "Command Injection (Time-based) Probe",
            "command": ""
        }
        return {
            "plugin": "CmdInjectionProbe",
            "plugin_uuid": UUID_053,
            "file_name": "cmd_injection_probe.py",
            "description": "Heurística time-based para detectar possível command injection (comparando latência baseline vs. payload com sleep).",
            "category": "Server-Side Testing",
            "result": [item]
        }

    timeout = int(cfg.get("timeout", 12))
    path    = cfg.get("path","/ping")
    param   = cfg.get("param","host")
    sleep_s = int(cfg.get("sleep_seconds", 2))
    benign  = cfg.get("benign_value", "127.0.0.1")

    base = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    sep = "&" if "?" in base else "?"
    url_baseline = base + f"{sep}{param}={quote_plus(benign)}"
    url_payload  = base + f"{sep}{param}={quote_plus(f'{benign}; sleep {sleep_s}')}"

    # Mede baseline
    with Timer() as t_base:
        _ = _curl(url_baseline, timeout)
    baseline = t_base.duration

    # Mede payload com sleep
    with Timer() as t_pay:
        _ = _curl(url_payload, timeout + sleep_s + 2)  # concede margem ao sleep
    payload_time = t_pay.duration

    delta = max(0.0, payload_time - baseline)

    # Heurística de severidade baseada no delta e no parâmetro sleep
    # - high: delta >= 0.8 * sleep_s (forte indício)
    # - medium: delta >= 0.4 * sleep_s (indício moderado)
    # - info: abaixo disso
    if delta >= 0.8 * sleep_s:
        sev = "high"
    elif delta >= 0.4 * sleep_s:
        sev = "medium"
    else:
        sev = "info"

    # Resultado textual
    txt = (
        f"Baseline ≈ {baseline:.2f}s; Payload(sleep={sleep_s}) ≈ {payload_time:.2f}s; "
        f"Δ ≈ {delta:.2f}s"
    )

    # Comando reproduzível (dois comandos separados por ';')
    command = (
        f'curl -sS -L -m {timeout} "{url_baseline}" -w "\\nTIME_OK"'
        f' ; '
        f'curl -sS -L -m {timeout + sleep_s + 2} "{url_payload}" -w "\\nTIME_OK"'
    )

    item = {
        "plugin_uuid": UUID_053,
        "scan_item_uuid": UUID_053,
        "result": txt,
        "analysis_ai": ai_fn("CmdInjectionProbe", UUID_053, txt),
        "severity": sev,
        "duration": payload_time,  # duração do teste principal; baseline já foi medido separadamente
        "auto": True,
        "reference": REFERENCE_URL,
        "item_name": "Command Injection (Time-based) Probe",
        "command": command
    }

    return {
        "plugin": "CmdInjectionProbe",
        "plugin_uuid": UUID_053,
        "file_name": "cmd_injection_probe.py",
        "description": "Heurística time-based para detectar possível command injection (comparando latência baseline vs. payload com sleep).",
        "category": "Server-Side Testing",
        "result": [item]
    }