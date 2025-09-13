# plugins/mfa_presence_scanner.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
import re

PLUGIN_CONFIG_NAME = "mfa_presence_scanner"
PLUGIN_CONFIG_ALIASES = ["mfa_presence"]
UUID_064 = "uuid-064"  # (64)

TOKENS = ["2fa","two-factor","duo","otp","one-time password","authenticator", "mfa","senha de uso único","google authenticator","totp","u2f","webauthn"]

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "timeout": 12, "urls": ["/login","/settings","/security"] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    urls = [target.rstrip("/") + p for p in (cfg.get("urls") or ["/login","/settings","/security"])]

    evid: List[str] = []
    with Timer() as t:
        for u in urls:
            html = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{u}"'], timeout=timeout+2).lower()
            found = [tok for tok in TOKENS if tok in html]
            if found: evid.append(f"{u}: " + ", ".join(sorted(set(found))))
    sev = "info" if evid else "low"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem menções claras a MFA/2FA nas páginas amostradas"
    item = {"plugin_uuid":UUID_064,"scan_item_uuid":UUID_064,"result":txt,"analysis_ai":ai_fn("MFAPresenceScanner",UUID_064,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"MFAPresenceScanner","result":[item]}
