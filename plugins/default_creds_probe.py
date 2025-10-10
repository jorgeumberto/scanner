# plugins/default_creds_probe.py
from typing import Dict, Any, List, Tuple, Optional
from utils import run_cmd, Timer
from urllib.parse import urlencode, urlparse
import tempfile
import os
import shlex

PLUGIN_CONFIG_NAME = "default_creds_probe"
PLUGIN_CONFIG_ALIASES = ["default_creds","weak_login"]

UUID_060 = "uuid-060"  # (60) Credenciais padrão/óbvias

REFERENCE_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"

COMMON = [
    ("admin","admin"), ("admin","password"), ("admin","123456"),
    ("root","root"), ("test","test"), ("user","user"), ("administrator","admin")
]

def _which(tool: str) -> Optional[str]:
    try:
        return tool if out and "OK" in out else None
    except Exception:
        return None

def _write_temp_lines(lines: List[str]) -> str:
    fd, path = tempfile.mkstemp(prefix="hydra_", suffix=".lst")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln.rstrip("\n") + "\n")
    return path

def _url_to_hydra_target(login_url: str) -> Tuple[str, int, str, str]:
    """
    Retorna (host, port, path, module)
    module: http-post-form | https-post-form
    """
    p = urlparse(login_url)
    scheme = (p.scheme or "http").lower()
    host = p.hostname or ""
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    port = p.port or (443 if scheme == "https" else 80)
    module = "https-post-form" if scheme == "https" else "http-post-form"
    return host, port, path, module

def _build_hydra_form(path: str, user_field: str, pass_field: str,
                      fail_markers: List[str], success_markers: List[str], headers: Dict[str, str]) -> str:
    """
    Constrói a parte FORM do hydra:
      /path:USER_FMT&PASS_FMT:F=...;S=...;H=...
    - F (falha) é obrigatório; se não vier em cfg, usa um padrão conservador (ex.: 'invalid', 'incorrect', 'failed').
    - S (sucesso) é opcional; se informado, ajuda a reduzir falso-positivo.
    - H (headers) é opcional e pode repetir (Hydra aceita múltiplos H=)
    """
    form_body = f"{user_field}=^USER^&{pass_field}=^PASS^"
    # F (falha)
    fail = fail_markers[:] if fail_markers else ["invalid", "incorrect", "failed", "unauthorized"]
    # Escape de ":" e ";" é feito implicitamente por não inserirmos esses chars nos marcadores
    F = f"F={fail[0]}"
    # S (sucesso) opcional
    S = f";S={success_markers[0]}" if success_markers else ""
    # Headers opcionais
    H = ""
    for k, v in (headers or {}).items():
        # Ex.: H=User-Agent: Mozilla/5.0
        H += f";H={k}: {v}"
    return f"{path}:{form_body}:{F}{S}{H}"

def _build_hydra_command(host: str, port: int, module: str, form: str,
                         users_file: Optional[str], passes_file: Optional[str],
                         combo_file: Optional[str], tasks: int, timeout: int, tls_sni: Optional[str]) -> str:
    """
    Monta o comando hydra:
      hydra -s <port> -t <tasks> [-L users] [-P passes] [-C combos] <host> <module> "<form>" -I -W <timeout>
    -I: ignore restore
    -W: waittime/timeout por tentativa (não confundir com timeout do run_cmd)
    -SNI/TLS: hydra usa SNI por padrão; opcionalmente podemos adicionar -S (SSL) automaticamente pelo módulo https.
    """
    parts = ["hydra", "-I", "-s", str(port), "-t", str(tasks), "-W", str(timeout)]
    if combo_file:
        parts += ["-C", combo_file]
    else:
        if users_file:
            parts += ["-L", users_file]
        if passes_file:
            parts += ["-P", passes_file]
    # host, module e form
    parts += [host, module, form]
    return " ".join(shlex.quote(x) for x in parts)

def _parse_hydra_output(out: str) -> List[Tuple[str, str]]:
    """
    Extrai pares (user, pass) de linhas típicas de sucesso do hydra:
      [80][http-post-form] host -> login: X   password: Y
    Retorna lista de (user, pass).
    """
    hits: List[Tuple[str, str]] = []
    if not out:
        return hits
    for ln in out.splitlines():
        ln_low = ln.lower()
        if "login:" in ln_low and "password:" in ln_low:
            # Tenta extrair por split simples
            try:
                # ... login: <USER>   password: <PASS>
                after_login = ln.split("login:", 1)[1].strip()
                user_part, after_user = after_login.split("password:", 1)
                user = user_part.strip()
                password = after_user.strip()
                hits.append((user, password))
            except Exception:
                continue
    return hits

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg:
    {
      "enabled": false,
      "timeout": 20,
      "login_url": "http://site/login",
      "user_field": "username",
      "pass_field": "password",
      "headers": {},

      "tool": "hydra",               # ativa modo hydra
      "hydra_tasks": 4,              # -t (concorrência)
      "hydra_wait": 5,               # -W (timeout por tentativa)
      "hydra_fail_like": ["invalid","incorrect","failed"],  # F=
      "hydra_success_like": ["dashboard","logout","bem-vindo"], # S= (opcional)
      "pairs": [["admin","admin"], ["test","test"]],         # se fornecido, usa -C
      "users": ["admin","test"],     # opcional, se sem pairs
      "passwords": ["admin","test"], # opcional, se sem pairs
      "mask_passwords": false        # se true, mascara senhas no report
    }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Probe desabilitado por padrão (defina enabled=true no config)."
        item = {
            "plugin_uuid": UUID_060,
            "scan_item_uuid": UUID_060,
            "result": txt,
            "analysis_ai": ai_fn("DefaultCredsProbe", UUID_060, txt),
            "severity": "info",
            "duration": 0.0,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": "Default Credentials Probe (Hydra)",
            "command": ""
        }
        return {
            "plugin": "DefaultCredsProbe",
            "plugin_uuid": UUID_060,
            "file_name": "default_creds_probe.py",
            "description": "Testa credenciais padrão/óbvias via Hydra (http(s)-post-form).",
            "category": "Authentication",
            "result": [item]
        }

    # Verifica hydra no Kali
    if not _which("hydra"):
        txt = "Hydra não encontrado no PATH. Instale: apt-get install hydra"
        item = {
            "plugin_uuid": UUID_060,
            "scan_item_uuid": UUID_060,
            "result": txt,
            "analysis_ai": ai_fn("DefaultCredsProbe", UUID_060, txt),
            "severity": "info",
            "duration": 0.0,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": "Default Credentials Probe (Hydra)",
            "command": ""
        }
        return {
            "plugin": "DefaultCredsProbe",
            "plugin_uuid": UUID_060,
            "file_name": "default_creds_probe.py",
            "description": "Testa credenciais padrão/óbvias via Hydra (http(s)-post-form).",
            "category": "Authentication",
            "result": [item]
        }

    timeout = int(cfg.get("timeout", 20))
    login_url = cfg.get("login_url", "")
    if not login_url:
        txt = "Config ausente: login_url."
        item = {
            "plugin_uuid": UUID_060,
            "scan_item_uuid": UUID_060,
            "result": txt,
            "analysis_ai": ai_fn("DefaultCredsProbe", UUID_060, txt),
            "severity": "info",
            "duration": 0.0,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": "Default Credentials Probe (Hydra)",
            "command": ""
        }
        return {
            "plugin": "DefaultCredsProbe",
            "plugin_uuid": UUID_060,
            "file_name": "default_creds_probe.py",
            "description": "Testa credenciais padrão/óbvias via Hydra (http(s)-post-form).",
            "category": "Authentication",
            "result": [item]
        }

    uf = cfg.get("user_field", "username")
    pf = cfg.get("pass_field", "password")
    headers = cfg.get("headers") or {}
    pairs = cfg.get("pairs")  # lista de pares OU users+passwords
    users = cfg.get("users")
    passwords = cfg.get("passwords")
    mask_pw = bool(cfg.get("mask_passwords", False))

    hydra_tasks = int(cfg.get("hydra_tasks", 4))
    hydra_wait = int(cfg.get("hydra_wait", 5))
    fail_like = [s.strip() for s in (cfg.get("hydra_fail_like") or ["invalid","incorrect","failed"])]
    success_like = [s.strip() for s in (cfg.get("hydra_success_like") or [])]

    host, port, path, module = _url_to_hydra_target(login_url)
    form = _build_hydra_form(path, uf, pf, fail_like, success_like, headers)

    # Prepara arquivos temporários
    users_file = passes_file = combo_file = None
    cleanup: List[str] = []
    try:
        if pairs:
            # Usa -C (combo file) "user:pass" por linha
            combo_lines = [f"{u}:{p}" for u, p in pairs]
            combo_file = _write_temp_lines(combo_lines); cleanup.append(combo_file)
        else:
            # Usa -L e -P a partir de listas
            if not users:
                users = [u for u,_ in COMMON]
            if not passwords:
                passwords = [p for _,p in COMMON]
            users_file = _write_temp_lines(users); cleanup.append(users_file)
            passes_file = _write_temp_lines(passwords); cleanup.append(passes_file)

        cmd = _build_hydra_command(host, port, module, form, users_file, passes_file, combo_file, hydra_tasks, hydra_wait, tls_sni=None)

        with Timer() as t:
            out = run_cmd(["bash", "-lc", cmd], timeout=timeout + max(10, hydra_wait*2))

        hits = _parse_hydra_output(out or "")
        hits_count = len(hits)

        def mask(s: str) -> str:
            if not mask_pw or len(s) <= 2:
                return s
            return s[0] + "*" * (len(s)-2) + s[-1]

        if hits:
            evid_lines = [f"possível sucesso: {u}:{mask(p)}" for (u, p) in hits]
            sev = "high"
        else:
            evid_lines = ["nenhuma credencial padrão/óbvia confirmou sucesso"]
            sev = "info"

        txt = "\n".join(f"- {ln}" for ln in evid_lines)

        item = {
            "plugin_uuid": UUID_060,
            "scan_item_uuid": UUID_060,
            "result": txt,
            "analysis_ai": ai_fn("DefaultCredsProbe", UUID_060, txt),
            "severity": sev,
            "duration": t.duration,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": "Default Credentials Probe (Hydra)",
            "command": cmd
        }

        return {
            "plugin": "DefaultCredsProbe",
            "plugin_uuid": UUID_060,
            "file_name": "default_creds_probe.py",
            "description": "Testa credenciais padrão/óbvias via Hydra (http(s)-post-form).",
            "category": "Authentication",
            "result": [item]
        }
    finally:
        for p in cleanup:
            try:
                os.remove(p)
            except Exception:
                pass