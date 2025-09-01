# plugins/ssrf_probe.py
from typing import Dict, Any
from utils import run_cmd, Timer
from urllib.parse import urljoin, quote_plus

PLUGIN_CONFIG_NAME = "ssrf_probe"
PLUGIN_CONFIG_ALIASES = ["ssrf"]
UUID_056 = "uuid-056"  # (56)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "enabled": false, "timeout": 12, "path": "/fetch?url=", "param":"url", "collaborator":"http://example.org" }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoint de fetch)."
        return {"plugin":"SSRFProbe","result":[{"plugin_uuid":UUID_056,"scan_item_uuid":UUID_056,"result":txt,"analysis_ai":ai_fn("SSRFProbe",UUID_056,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 12))
    path = cfg.get("path","/fetch")
    param= cfg.get("param","url")
    coll = cfg.get("collaborator","http://example.org")
    base = urljoin(target.rstrip("/") + "/", path.lstrip("/"))

    with Timer() as t:
        url = base + (("&" if "?" in base else "?") + f"{param}={quote_plus(coll)}")
        body = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} "{url}" -i'], timeout=timeout+2).lower()
    sev = "medium" if "http/1.1 200" in body or "content-type" in body else "info"
    item = {"plugin_uuid":UUID_056,"scan_item_uuid":UUID_056,"result":body[:300] or "Sem resposta clara","analysis_ai":ai_fn("SSRFProbe",UUID_056,body[:300]),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"SSRFProbe","result":[item]}
