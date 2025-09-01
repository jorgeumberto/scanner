# plugins/password_reset_security.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
import re, urllib.parse

PLUGIN_CONFIG_NAME = "password_reset_security"
PLUGIN_CONFIG_ALIASES = ["pwd_reset_sec"]
UUID_065 = "uuid-065"
UUID_066 = "uuid-066"

OK_HINTS = ["link expira", "token expira", "expires", "we sent a link", "verifique seu email", "rate limit", "limite de tentativas"]
WEAK_HINTS = ["token=", "reset?token=", "reset-password?token="]

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "timeout": 12, "urls": ["/password/reset","/forgot-password"] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    urls = [target.rstrip("/") + p for p in (cfg.get("urls") or ["/password/reset","/forgot-password"])]

    evid65: List[str] = []
    evid66: List[str] = []
    with Timer() as t:
        for u in urls:
            html = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{u}"'], timeout=timeout+2)
            low = html.lower()
            if any(x in low for x in OK_HINTS):
                evid65.append(f"{u}: mensagens de expiração/fluxo seguro detectadas.")
            if any(x in low for x in WEAK_HINTS):
                # extrai tamanho típico do token na página (se houver)
                m = re.search(r"token=([A-Za-z0-9\-\._]+)", html)
                if m:
                    evid66.append(f"{u}: token visível em URL (comprimento {len(m.group(1))})")
                else:
                    evid66.append(f"{u}: referência a token em URL.")
    res65 = "\n".join(f"- {e}" for e in evid65) if evid65 else "Sem sinais textuais claros do fluxo seguro de reset"
    res66 = "\n".join(f"- {e}" for e in evid66) if evid66 else "Sem referência clara a token em URL"
    return {
        "plugin":"PasswordResetSecurity",
        "result":[
            {"plugin_uuid":UUID_065,"scan_item_uuid":UUID_065,"result":res65,"analysis_ai":ai_fn("PasswordResetSecurity",UUID_065,res65),"severity":"info","duration":t.duration,"auto":True},
            {"plugin_uuid":UUID_066,"scan_item_uuid":UUID_066,"result":res66,"analysis_ai":ai_fn("PasswordResetSecurity",UUID_066,res66),"severity":"low" if evid66 else "info","duration":t.duration,"auto":True}
        ]
    }
