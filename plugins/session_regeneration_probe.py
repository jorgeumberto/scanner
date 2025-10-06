# plugins/session_regeneration_probe.py
"""
Plugin: session_regeneration_probe
Objetivo:
  - Verificar se o identificador de sessão (cookie) é regenerado após autenticação (login).
  - Captura Set-Cookie antes e após o POST de login e compara 'name=value'.
  - Se não regenerar, indica possível Session Fixation.
Config (configs/session_regeneration_probe.json):
{
  "enabled": false,
  "timeout": 20,
  "login_url": "https://example.com/login",
  "user_field": "username",
  "pass_field": "password",
  "username": "testuser",
  "password": "testpass",
  "headers": {},
  "references": []
}
"""
from utils import run_cmd, Timer
from typing import Dict, Any, List, Optional
from urllib.parse import urlencode
import re

PLUGIN_CONFIG_NAME = "session_regeneration_probe"
PLUGIN_CONFIG_ALIASES = ["sess_regen"]
UUID_042 = "uuid-042"  # (42) Session regeneration missing

# referências padrão
DEFAULT_REFERENCES = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    "https://datatracker.ietf.org/doc/html/rfc6265"
]

COOKIE_HDR_RE = re.compile(r"^set-cookie:\s*(.+)$", re.I)

def _cookie_from_headers(raw: str) -> str:
    """
    Retorna o primeiro header Set-Cookie completo encontrado (string após 'Set-Cookie:').
    Se não encontrar, retorna string vazia.
    """
    if not raw:
        return ""
    for ln in raw.splitlines():
        m = COOKIE_HDR_RE.match(ln.strip())
        if m:
            return m.group(1).strip()
    return ""

def _cookie_name_value(cookie_hdr: str) -> str:
    """Extrai 'name=value' (primeira parte) do header Set-Cookie."""
    if not cookie_hdr:
        return ""
    return cookie_hdr.split(";", 1)[0].strip()

def _post(url: str, data: Dict[str, str], headers: Dict[str, str], timeout: int, cookie: str = "") -> str:
    """
    Executa POST usando curl e retorna cabeçalhos + body (-i).
    headers: dict de cabeçalhos adicionais.
    cookie: string completa de cookie a ser enviada (ex.: "SESSIONID=abcd; ...")
    """
    hdr_params = []
    for k, v in (headers or {}).items():
        hdr_params += ["-H", f"{k}: {v}"]
    if cookie:
        hdr_params += ["-H", f"Cookie: {cookie}"]
    form = urlencode(data or {})
    # montar comando para exibição/registro no campo 'command'
    cmd_str = f'curl -sS -i -L -m {int(timeout)} {" ".join(shlex_quote_list(hdr_params))} -X POST --data "{form}" "{url}"'
    # executar com run_cmd via bash -lc para preservar composição
    return run_cmd(["bash", "-lc", cmd_str], timeout=timeout + 2)

def shlex_quote_list(items: List[str]) -> List[str]:
    """
    Garante que cada argumento contendo espaços/quotes fique corretamente entre aspas
    para exibição no campo 'command' (apenas para montar string legível).
    """
    out = []
    for it in items:
        if any(c.isspace() for c in it) or '"' in it or "'" in it:
            # usar aspas simples e escapar apóstrofos internos
            out.append("'" + it.replace("'", "'\"'\"'") + "'")
        else:
            out.append(it)
    return out

def make_item(uuid: str,
              result: str,
              severity: str,
              item_name: str,
              command: str,
              references: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": result,
        "analysis_ai": None,  # será preenchido pelo ai_fn na chamada
        "severity": severity,
        "duration": _current_duration(),
        "auto": True,
        "item_name": item_name,
        "command": command,
        "references": references or DEFAULT_REFERENCES
    }

# helper para duração (preenchida dentro do Timer block)
_duration_state = {"last": 0.0}
def _current_duration() -> float:
    return _duration_state.get("last", 0.0)

def run_plugin(target: str, ai_fn) -> Dict[str, Any]:
    """
    run_plugin espera que o 'target' seja o login_url ou host; cfg deve ser lido externamente
    (o main geralmente injeta cfg por outro mecanismo). Para compatibilidade com seu modelo,
    aqui lemos cfg via uma convenção: target pode incluir query JSON? Se seu runner passar cfg,
    ajuste conforme necessário.
    """
    # Para manter compatibilidade com o modelo que você enviou, assumimos
    # que o runner passa as configurações via environment/config externo.
    # Aqui vamos buscar um cfg padronizado (caso seu runner não passe, use defaults).
    # -> O main que chama run_plugin deve ajustar se quiser passar cfg.
    cfg: Dict[str, Any] = getattr(run_plugin, "cfg", {}) or {}

    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e credenciais em cfg)."
        base_cmd = f'curl -sSI {target}'
        item = make_item(UUID_042, txt, "info", "Session regeneration probe (disabled)", base_cmd, cfg.get("references"))
        item["analysis_ai"] = ai_fn("SessionRegenerationProbe", UUID_042, txt)
        return {
            "plugin": "SessionRegenerationProbe",
            "plugin_uuid": UUID_042,
            "file_name": "session_regeneration_probe.py",
            "description": "Verifica se o identificador de sessão (cookie) é regenerado após autenticação (Session Fixation probe).",
            "category": "Session Management",
            "result": [item]
        }

    timeout = int(cfg.get("timeout", 20))
    url = target
    user_field = cfg.get("user_field", "username")
    pass_field = cfg.get("pass_field", "password")
    username = cfg.get("username", "")
    password = cfg.get("password", "")
    headers_cfg = cfg.get("headers") or {}
    references_cfg = cfg.get("references")

    with Timer() as t:
        # 1) GET headers para capturar cookie anônimo
        pre_cmd = f'curl -sSI -m {int(timeout)} "{url}"'
        pre_raw = run_cmd(["bash", "-lc", pre_cmd], timeout=timeout + 2) or ""
        cookie_pre = _cookie_from_headers(pre_raw)
        cookie_pre_nv = _cookie_name_value(cookie_pre)

        # 2) POST login (envia cookie_pre se existir)
        # montar form e headers para o comando exibido
        hdr_params = []
        for k, v in headers_cfg.items():
            hdr_params += ["-H", f"{k}: {v}"]
        if cookie_pre:
            hdr_params += ["-H", f"Cookie: {cookie_pre}"]

        form = urlencode({user_field: username, pass_field: password})
        # comando exibido (legível)
        cmd_show = f'curl -sS -i -L -m {int(timeout)} {" ".join(shlex_quote_list(hdr_params))} -X POST --data "{form}" "{url}"'
        # executar
        post_raw = run_cmd(["bash", "-lc", cmd_show], timeout=timeout + 2) or ""
        cookie_post = _cookie_from_headers(post_raw)
        cookie_post_nv = _cookie_name_value(cookie_post)

        # atualizar duration state
        _duration_state["last"] = getattr(t, "duration", 0.0)

    # avaliar se houve regeneração
    regenerated = False
    if cookie_pre_nv and cookie_post_nv:
        regenerated = (cookie_pre_nv != cookie_post_nv)
    elif cookie_pre_nv and not cookie_post_nv:
        regenerated = True
    elif not cookie_pre_nv and cookie_post_nv:
        regenerated = True
    else:
        regenerated = False

    # montar mensagem de resultado
    msg_lines = [
        f"URL testada: {url}",
        f"Cookie antes do login: {cookie_pre or '<nenhum>'}",
        f"Cookie após o login: {cookie_post or '<nenhum>'}",
        f"Resultado: {'regenerou' if regenerated else 'NÃO regenerou'}"
    ]
    if not cookie_pre and not cookie_post:
        msg_lines.append("Observação: não foram encontrados headers Set-Cookie — verifique fluxo de login ou se o endpoint emite cookies.")
    msg = "\n".join(msg_lines)

    severity = "info" if regenerated else "medium"
    final_cmd = cmd_show if 'cmd_show' in locals() else pre_cmd

    item = make_item(UUID_042, msg, severity, "Session regeneration probe", final_cmd, references_cfg)
    item["analysis_ai"] = ai_fn("SessionRegenerationProbe", UUID_042, msg)

    return {
        "plugin": "SessionRegenerationProbe",
        "plugin_uuid": UUID_042,
        "file_name": "session_regeneration_probe.py",
        "description": "Verifica se o identificador de sessão (cookie) é regenerado após autenticação. Não regenerar pode indicar risco de Session Fixation.",
        "category": "Session Management",
        "result": [item]
    }
