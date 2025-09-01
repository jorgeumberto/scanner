# plugins/verification_signals.py
from typing import Dict, Any, List
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "verification_signals"
PLUGIN_CONFIG_ALIASES = ["verify_signals"]
UUID_067 = "uuid-067"  # (67)

TOKENS = ["verifique seu e-mail","email verification","verify your email","phone verification","sms code","verification code","confirme seu e-mail","confirme o email"]

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "timeout": 12, "urls": ["/register","/account","/settings/security"] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    urls = [target.rstrip("/") + p for p in (cfg.get("urls") or ["/register","/account","/settings/security"])]

    evid: List[str] = []
    with Timer() as t:
        for u in urls:
            html = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{u}"'], timeout=timeout+2).lower()
            hits = [tok for tok in TOKENS if tok in html]
            if hits:
                evid.append(f"{u}: " + ", ".join(sorted(set(hits))))
    sev = "info" if evid else "low"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem sinais de verificação de e-mail/telefone"
    item = {"plugin_uuid":UUID_067,"scan_item_uuid":UUID_067,"result":txt,"analysis_ai":ai_fn("VerificationSignals",UUID_067,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"VerificationSignals","result":[item]}
