# plugins/password_policy_inspector.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
import re

PLUGIN_CONFIG_NAME = "password_policy_inspector"
PLUGIN_CONFIG_ALIASES = ["pwd_policy"]
UUID_062 = "uuid-062"  # (62)

PAT = re.compile(r"(?i)(min(?:imum)?\s*length\s*\d+|[0-9]{8,}|uppercase|lowercase|special|character|senha\s+forte|complexidade)", re.I)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "timeout": 12, "urls": ["https://example.com/register","/password-policy"] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    urls = cfg.get("urls") or [target.rstrip("/") + "/register"]

    evid: List[str] = []
    with Timer() as t:
        for u in urls:
            html = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{u}"'], timeout=timeout+2)
            hits = PAT.findall(html or "")
            if hits:
                evid.append(f"{u}: " + ", ".join(sorted(set([h if isinstance(h,str) else h[0] for h in hits]))))
    sev = "info"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Sem pistas textuais de política de senha"
    item = {"plugin_uuid":UUID_062,"scan_item_uuid":UUID_062,"result":txt,"analysis_ai":ai_fn("PasswordPolicyInspector",UUID_062,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"PasswordPolicyInspector","result":[item]}
