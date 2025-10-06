# plugins/session_timeout_probe.py
"""
Plugin: session_timeout_probe
Objetivo:
  - Detectar configurações de expiração de cookies de sessão.
  - Verifica, em paths configuráveis, headers Set-Cookie cujos nomes contenham
    palavras da lista `look_cookies` (ex.: session, sid) e identifica se possuem
    expiração explícita (`Max-Age` ou `Expires`).
  - Registra comandos executados em `command` e inclui `references`.
Config (configs/session_timeout_probe.json):
{
  "timeout": 12,
  "paths": ["/"],
  "look_cookies": ["session","sid"],
  "references": []
}
"""
import re
import time
from typing import Dict, Any, List, Optional

PLUGIN_CONFIG_NAME = "session_timeout_probe"
PLUGIN_CONFIG_ALIASES = ["sess_timeout"]
UUID_043 = "uuid-043"  # (43) Session timeout / cookie expiration

# referências padrão úteis para este check
DEFAULT_REFERENCES = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "https://datatracker.ietf.org/doc/html/rfc6265"
]

# regex para capturar Set-Cookie header (capture tudo após 'Set-Cookie:')
SETCOOKIE_RE = re.compile(r"^set-cookie:\s*(.+)$", re.I)

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
    Usa utils.run_cmd quando disponível; caso contrário, usa subprocess como fallback.
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
    def __enter__(self):
        self._t0 = time.time()
        return self
    def __exit__(self, exc_type, exc, tb):
        self.duration = time.time() - self._t0

Timer = __Timer_orig or _SimpleTimer
# === end injected ===

def _parse_setcookie_lines(raw: str) -> List[str]:
    """
    Retorna lista de valores do header Set-Cookie (a parte depois de 'Set-Cookie:').
    """
    out = []
    if not raw:
        return out
    for ln in (raw or "").splitlines():
        m = SETCOOKIE_RE.match(ln.strip())
        if m:
            out.append(m.group(1).strip())
    return out

def build_item(uuid: str,
               msg: str,
               severity: str,
               duration: float,
               ai_fn,
               item_name: str,
               references: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    build_item padronizado — inclui histórico de comandos em 'command' e 'references'.
    """
    return {
        "scan_item_uuid": uuid,
        "result": msg,
        "analysis_ai": ai_fn(PLUGIN_CONFIG_NAME, uuid, msg) if callable(ai_fn) else None,
        "severity": severity,
        "duration": duration,
        "auto": True,
        "item_name": item_name,
        "command": EXEC_CMDS[:],  # histórico completo dos run_cmd nesta execução
        "references": references or DEFAULT_REFERENCES
    }

def run_plugin(target: str, ai_fn, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    run_plugin(target, ai_fn, cfg)
    cfg:
      - timeout: int (segundos)
      - paths: list[str] (paths a testar, ex: ["/", "/login"])
      - look_cookies: list[str] (substrings de nomes de cookie a procurar, ex: ["session","sid"])
      - references: list[str] (substitui referências padrão)
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    paths = cfg.get("paths") or ["/"]
    look = [s.lower() for s in (cfg.get("look_cookies") or ["session", "sid"])]
    references_cfg = cfg.get("references")

    evid: List[str] = []
    hits = 0

    with Timer() as t:
        for p in paths:
            # garantir barra inicial
            path = p if p.startswith("/") else "/" + p
            url = target.rstrip("/") + path
            # montar e executar curl -sSI
            cmd = ["bash", "-lc", f'curl -sSI -m {int(timeout)} "{url}"']
            raw = run_cmd(cmd, timeout=timeout + 2) or ""
            setcookies = _parse_setcookie_lines(raw)
            for sc in setcookies:
                # extrair nome=value
                nv = sc.split(";", 1)[0].strip()
                name = nv.split("=", 1)[0].lower() if "=" in nv else nv.lower()
                # verificar se nome contém qualquer substring de interesse
                if any(n in name for n in look):
                    if ("max-age" in sc.lower()) or ("expires=" in sc.lower()):
                        evid.append(f"{path}: cookie {name} possui expiração explícita -> {nv}; attrs: {sc}")
                        hits += 1
                    else:
                        evid.append(f"{path}: cookie {name} sem expiração explícita -> {nv}; attrs: {sc}")

    # seguindo a lógica original: se houve hits (cookies com expiração explícita), marcar info; caso contrário low
    severity = "info" if hits else "low"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Nenhum Set-Cookie observado"
    item = build_item(UUID_043, txt, severity, getattr(t, "duration", 0.0), ai_fn, "Session timeout probe", references_cfg)

    return {
        "plugin": PLUGIN_CONFIG_NAME,
        "plugin_uuid": UUID_043,
        "file_name": "session_timeout_probe.py",
        "description": "Verifica expiração de cookies de sessão (Max-Age/Expires) em paths configuráveis. Cookies sem expiração explícita podem indicar sessões muito longas/permanentes.",
        "category": "Session Management",
        "result": [item]
    }
