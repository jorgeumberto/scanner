# plugins/deserialization_probe.py
from typing import Dict, Any
from utils import run_cmd, Timer
import base64

PLUGIN_CONFIG_NAME = "deserialization_probe"
PLUGIN_CONFIG_ALIASES = ["insecure_deser"]
UUID_057 = "uuid-057"  # (57)

POC = base64.b64encode(b"test-object").decode()

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: { "enabled": false, "timeout": 12, "endpoint": "/api/deserialize", "header_name": "X-Serialized" }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoint de desserialização)."
        return {"plugin":"DeserializationProbe","result":[{"plugin_uuid":UUID_057,"scan_item_uuid":UUID_057,"result":txt,"analysis_ai":ai_fn("DeserializationProbe",UUID_057,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 12))
    url = target.rstrip("/") + cfg.get("endpoint","/api/deserialize")
    h   = cfg.get("header_name","X-Serialized")

    with Timer() as t:
        raw = run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} -H "{h}: {POC}" "{url}" -i'], timeout=timeout+2)
    sev = "low" if "200" in raw else "info"
    item = {"plugin_uuid":UUID_057,"scan_item_uuid":UUID_057,"result":raw[:300] or "Sem indício claro","analysis_ai":ai_fn("DeserializationProbe",UUID_057,raw[:300]),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"DeserializationProbe","result":[item]}
