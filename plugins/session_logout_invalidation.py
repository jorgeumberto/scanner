# plugins/session_logout_invalidation.py
"""
Plugin: session_logout_invalidation
Objetivo:
  - Verificar se o logout invalida efetivamente a sessão do usuário.
  - Realiza login, acessa área restrita, executa logout e tenta acessar novamente.
  - Se o acesso pós-logout ainda retornar 200 OK, indica sessão não invalidada.
  - Registra comandos executados em 'command' e inclui referências.
Config (configs/session_logout_invalidation.json):
{
  "enabled": false,
  "timeout": 20,
  "login_url": "https://example.com/login",
  "logout_url": "https://example.com/logout",
  "check_url": "https://example.com/profile",
  "user_field": "username",
  "pass_field": "password",
  "username": "testuser",
  "password": "testpass",
  "references": []
}
"""
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlencode

PLUGIN_CONFIG_NAME = "session_logout_invalidation"
PLUGIN_CONFIG_ALIASES = ["sess_logout"]
UUID_044 = "uuid-044"  # (44) Session logout not invalidating session

# Referências padrão
DEFAULT_REFERENCES = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "https://owasp.org/www-project-top-ten/",
    "https://datatracker.ietf.org/doc/html/rfc6265"
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
    Usa utils.run_cmd quando disponível; caso contrário, subprocess como fallback.
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

def _post(url: str, data: Dict[str, str], timeout: int) -> str:
    """Executa POST usando curl e retorna cabeçalhos + body (-i)."""
    form = urlencode(data)
    return run_cmd(["bash", "-lc", f'curl -sS -i -L -m {timeout} -X POST --data "{form}" "{url}"'], timeout=timeout + 2)

def _extract_cookie(raw: str) -> str:
    """Retorna o primeiro header Set-Cookie encontrado no conteúdo bruto."""
    for ln in (raw or "").splitlines():
        if ln.lower().startswith("set-cookie:"):
            return ln.split(":", 1)[1].strip()
    return ""

def build_item(uuid: str,
               msg: str,
               severity: str,
               duration: float,
               ai_fn,
               item_name: str,
               references: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    build_item padronizado — inclui 'command' (histórico) e 'references'.
    """
    return {
        "scan_item_uuid": uuid,
        "result": msg,
        "analysis_ai": ai_fn(PLUGIN_CONFIG_NAME, uuid, msg) if callable(ai_fn) else None,
        "severity": severity,
        "duration": duration,
        "auto": True,
        "item_name": item_name,
        "command": EXEC_CMDS[:],
        "references": references or DEFAULT_REFERENCES
    }

def run_plugin(target: str, ai_fn, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Executa o plugin que testa invalidação de sessão via logout.
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoints de login/logout)."
        return {
            "plugin": PLUGIN_CONFIG_NAME,
            "plugin_uuid": UUID_044,
            "file_name": "session_logout_invalidation.py",
            "description": "Verifica se o logout invalida efetivamente a sessão do usuário.",
            "category": "Session Management",
            "result": [build_item(UUID_044, txt, "info", 0.0, ai_fn, "Session logout invalidation probe", cfg.get("references"))]
        }

    timeout = int(cfg.get("timeout", 20))
    login = cfg.get("login_url", "")
    logout = cfg.get("logout_url", "")
    check = cfg.get("check_url", "/")
    uf = cfg.get("user_field", "username")
    pf = cfg.get("pass_field", "password")
    user = cfg.get("username", "")
    pwd = cfg.get("password", "")
    references_cfg = cfg.get("references")

    with Timer() as t:
        # 1) login e captura de cookie
        raw = _post(login, {uf: user, pf: pwd}, timeout)
        cookie = _extract_cookie(raw)

        if not cookie:
            msg = "Não foi possível obter cookie pós-login. Verifique se o login_url está correto."
            severity = "low"
        else:
            # 2) acessar área restrita com cookie ativo
            priv = run_cmd(["bash", "-lc", f'curl -sS -L -m {timeout} -H "Cookie: {cookie}" "{check}" -i'], timeout=timeout + 2)
            # 3) logout usando o mesmo cookie
            _ = run_cmd(["bash", "-lc", f'curl -sS -L -m {timeout} -H "Cookie: {cookie}" "{logout}" -i'], timeout=timeout + 2)
            # 4) tentar acessar novamente área restrita
            priv2 = run_cmd(["bash", "-lc", f'curl -sS -L -m {timeout} -H "Cookie: {cookie}" "{check}" -i'], timeout=timeout + 2)

            if "200 ok" in priv2.lower():
                msg = f"Acesso com cookie após logout retornou 200 OK — sessão não invalidada corretamente.\n\nCookie utilizado:\n{cookie}"
                severity = "medium"
            else:
                msg = "Sessão invalidada com sucesso — requisição pós-logout não retornou 200 OK."
                severity = "info"

    item = build_item(UUID_044, msg, severity, getattr(t, "duration", 0.0), ai_fn, "Session logout invalidation probe", references_cfg)

    return {
        "plugin": PLUGIN_CONFIG_NAME,
        "plugin_uuid": UUID_044,
        "file_name": "session_logout_invalidation.py",
        "description": "Verifica se o logout invalida efetivamente a sessão do usuário. Caso o cookie permaneça válido após logout, pode indicar risco de Session Hijacking.",
        "category": "Session Management",
        "result": [item]
    }
