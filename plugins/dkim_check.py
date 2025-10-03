# plugins/dkim_check.py
"""
Plugin: dkim_check
Objetivo:
  - Consultar registros TXT de selectors DKIM comuns para o domínio alvo.
  - Retorna item(es) apenas quando encontrar registros DKIM.
Config (opcional): configs/dkim_check.json
{
  "timeout": 15,
  "selectors": ["default","selector1","selector2"]
}
"""

import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

PLUGIN_CONFIG_NAME = "dkim_check"
PLUGIN_CONFIG_ALIASES = ["dkim", "dns_dkim"]

UUID_014 = "uuid-014-dkim"

COMMON_SELECTORS = [
    "default", "selector1", "selector2", "google", "mail", "mandrill", "k1", "s1", "s2",
    "smtp", "postfix", "dkim", "mailgun", "sendgrid", "amazonses", "sparkpost", "zoho"
]

# === injected: capture executed shell commands for tagging ===
try:
    from utils import run_cmd as __run_cmd_orig, Timer as __Timer_orig, extract_host as __extract_host_orig
except Exception:
    __run_cmd_orig = None
    __Timer_orig = None
    __extract_host_orig = None

EXEC_CMDS: List[str] = []

def run_cmd(cmd, timeout=None):
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    EXEC_CMDS.append(cmd_str)
    if __run_cmd_orig is None:
        # fallback para executar com subprocess
        import subprocess
        try:
            p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=(timeout or 30))
            return (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return f"[ERRO run_cmd-fallback] {e}"
    return __run_cmd_orig(cmd, timeout=timeout)

# Fallback Timer simples caso utils.Timer não exista
class _SimpleTimer:
    def __enter__(self):
        self._t0 = time.time()
        return self
    def __exit__(self, exc_type, exc, tb):
        self.duration = time.time() - self._t0

Timer = __Timer_orig or _SimpleTimer

# Fallback extract_host
def _extract_host_fallback(target: str) -> str:
    try:
        p = urlparse(target if "://" in target else ("//" + target), allow_fragments=False)
        host = p.hostname or target
        # remove possível :port
        return host.split(":")[0]
    except Exception:
        return target

extract_host = __extract_host_orig or _extract_host_fallback
# === end injected ===

def _dig_txt(name: str, timeout: int) -> str:
    # usa run_cmd para gravar comando em EXEC_CMDS
    return run_cmd(["dig", "+short", name, "TXT"], timeout=timeout)

def _summarize(lines: List[str], checklist_name: str, max_lines: int = 10) -> str:
    if not lines:
        return f"Nenhum registro DKIM encontrado para {checklist_name}"
    body = [f"- {l}" for l in lines[:max_lines]]
    extra = len(lines) - len(body)
    if extra > 0:
        body.append(f"... +{extra} registros DKIM")
    return "\n".join(body)

def build_item(uuid: str, result_text: str, severity: str, duration: float, ai_fn, item_name: str) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": result_text,
        "analysis_ai": ai_fn(PLUGIN_CONFIG_NAME, uuid, result_text) if callable(ai_fn) else None,
        "severity": severity,
        "duration": duration,
        "auto": True,
        "item_name": item_name,
        "command": EXEC_CMDS[-1] if EXEC_CMDS else ""
    }

def run_plugin(target: str, ai_fn, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    run_plugin(target, ai_fn, cfg)
    cfg:
      - timeout: int
      - selectors: list[str]
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
                out_clean = out.replace('" "', '').replace('"', '').replace("\n", " ").strip()
                found.append(f"{qname} :: {out_clean[:1000]}")  # truncar grandezas
    duration = getattr(t, "duration", 0.0)

    items: List[Dict[str, Any]] = []
    if found:
        result_text = _summarize(found, domain)
        severity = "low"
        items.append(build_item(UUID_014, result_text, severity, duration, ai_fn, f"DKIM records for {domain}"))
    # se nada encontrado, retorna result vazio (padronizando com seu pedido anterior)
    return {
        "plugin": PLUGIN_CONFIG_NAME,
        "plugin_uuid": "uuid-dkim-check",
        "file_name": "dkim_check.py",
        "description": "Consulta registros DKIM (TXT) para selectors comuns do domínio alvo. Gera item apenas quando encontra registros.",
        "category": "Mail/DNS",
        "result": items
    }
