# plugins/session_id_entropy.py
"""
Plugin: session_id_entropy
Objetivo:
  - Coletar valores de cookies de sessão (Set-Cookie) em respostas HTTP
    e calcular a entropia Shannon média dos identificadores de sessão.
  - Entropia baixa pode indicar previsibilidade.
  - Registra os comandos executados em `command`.
  - Adiciona campo `references` com links úteis.
Config (opcional): configs/session_id_entropy.json
{
  "timeout": 12,
  "samples": 6
}
"""

import re
import math
import time
from typing import Dict, Any, List, Optional

PLUGIN_CONFIG_NAME = "session_id_entropy"
PLUGIN_CONFIG_ALIASES = ["sess_entropy"]
UUID_041 = "uuid-041"  # (41) Baixa entropia em Session ID

COOKIE_RE = re.compile(r"^set-cookie:\s*([^=]+)=([^;]+);", re.I)

# referências padrão para inclusão em cada item
DEFAULT_REFERENCES = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "https://owasp.org/www-project-top-ten/",
    "https://en.wikipedia.org/wiki/Entropy_(information_theory)"
]

# === injected: capture executed shell commands for tagging ===
try:
    from utils import run_cmd as __run_cmd_orig, Timer as __Timer_orig
except Exception:
    __run_cmd_orig = None
    __Timer_orig = None

EXEC_CMDS: List[str] = []

def run_cmd(cmd, timeout=None):
    """
    Wrapper para capturar o comando usado em EXEC_CMDS.
    Usa utils.run_cmd se disponível; caso contrário, subprocess.
    """
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    EXEC_CMDS.append(cmd_str)
    if __run_cmd_orig is None:
        import subprocess
        try:
            p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=(timeout or 30))
            return (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return f"[ERRO run_cmd-fallback] {e}"
    return __run_cmd_orig(cmd, timeout=timeout)

# Timer fallback
class _SimpleTimer:
    def __enter__(self): self._t0=time.time(); return self
    def __exit__(self, exc_type, exc, tb): self.duration=time.time()-self._t0

Timer = __Timer_orig or _SimpleTimer
# === end injected ===

def _headers(url: str, timeout: int) -> List[str]:
    """
    Executa um HEAD request com curl (-I) e retorna lista de linhas de header.
    """
    raw = run_cmd(["bash","-lc", f'curl -sSI -m {timeout} "{url}"'], timeout=timeout+2)
    return [ln.strip() for ln in (raw or "").splitlines() if ln.strip()]

def _shannon(s: str) -> float:
    """
    Calcula entropia de Shannon (bits/char) da string fornecida.
    """
    if not s:
        return 0.0
    from collections import Counter
    N = len(s)
    c = Counter(s)
    return -sum((n/N) * math.log2(n/N) for n in c.values())

def build_item(uuid: str,
               msg: str,
               severity: str,
               duration: float,
               ai_fn,
               item_name: str,
               references: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    build_item padronizado — agora inclui 'references' e 'command' (histórico).
    """
    return {
        "scan_item_uuid": uuid,
        "result": msg,
        "analysis_ai": ai_fn(PLUGIN_CONFIG_NAME, uuid, msg) if callable(ai_fn) else None,
        "severity": severity,
        "duration": duration,
        "auto": True,
        "item_name": item_name,
        "command": EXEC_CMDS[:],  # histórico completo
        "references": references or DEFAULT_REFERENCES
    }

def run_plugin(target: str, ai_fn, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Executa o plugin de entropia de sessão.
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    samples = int(cfg.get("samples", 6))
    references_cfg = cfg.get("references")  # permite sobrescrever referências via cfg

    vals: List[str] = []
    with Timer() as t:
        for _ in range(max(2, samples)):
            for h in _headers(target, timeout):
                m = COOKIE_RE.search(h)
                if m:
                    vals.append(m.group(2))
                    break

    ent = [_shannon(v) for v in vals if v]
    avg = (sum(ent) / len(ent)) if ent else 0.0

    if vals:
        msg_lines = [f"Sessões coletadas: {len(vals)}", f"Entropia média ≈ {avg:.2f} bits/char"]
        txt = "\n".join(f"- {m}" for m in msg_lines)
        sev = "info" if avg >= 3.5 else ("low" if avg >= 2.5 else "medium")
    else:
        txt = "Nenhum Set-Cookie coletado (não foi possível avaliar entropia)."
        sev = "info"

    refs = references_cfg if isinstance(references_cfg, list) else DEFAULT_REFERENCES
    item = build_item(UUID_041, txt, sev, getattr(t, "duration", 0.0), ai_fn, "Session ID entropy", references=refs)

    return {
        "plugin": PLUGIN_CONFIG_NAME,
        "plugin_uuid": UUID_041,
        "file_name": "session_id_entropy.py",
        "description": "Calcula a entropia média dos valores de Session ID retornados em Set-Cookie. Entropia baixa indica previsibilidade.",
        "category": "Session Management",
        "result": [item]
    }
