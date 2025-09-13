# plugins/storage_bucket_probe.py
from typing import Dict, Any, List
from utils import run_cmd, Timer, extrair_host
import re

PLUGIN_CONFIG_NAME = "storage_bucket_probe"
PLUGIN_CONFIG_ALIASES = ["bucket_probe","obj_storage"]
UUID_018 = "uuid-018"  # (18) Buckets/storage expostos

def _try(url: str, timeout: int) -> str:
    return run_cmd(["bash","-lc", f'curl -sSL -m {timeout} "{url}" | head -n 60'], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any] = None):
    """
    cfg:
    {
      "timeout": 15,
      "candidates": ["media","static","assets","uploads"],
      "providers": ["s3","gcs","azure"],   // s3.amazonaws.com, storage.googleapis.com, blob.core.windows.net
      "extra": []
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    cands   = cfg.get("candidates") or ["media","static","assets","uploads"]
    provs   = cfg.get("providers") or ["s3","gcs","azure"]
    extra   = cfg.get("extra") or []
    domain  = extrair_host(target)

    patterns: List[str] = []
    for c in cands:
        if "s3" in provs:
            patterns += [f"https://{c}.{domain}.s3.amazonaws.com/", f"http://{c}.{domain}.s3.amazonaws.com/"]
        if "gcs" in provs:
            patterns += [f"https://storage.googleapis.com/{c}.{domain}/", f"https://{c}.{domain}.storage.googleapis.com/"]
        if "azure" in provs:
            patterns += [f"https://{c}{domain.replace('.','')}.blob.core.windows.net/", f"https://{c}.blob.core.windows.net/"]
    patterns += extra

    evid: List[str] = []
    hits  = 0
    with Timer() as t:
        for u in patterns[:50]:
            body = _try(u, timeout).lower()
            if not body: continue
            if any(k in body for k in ["<listbucketresult", "xml", "accessdenied", "allaccessdisabled", "blobserviceclient"]):
                hits += 1
                evid.append(f"{u} :: {body[:200].replace('\\n',' ')}")

    sev = "low" if hits else "info"
    txt = "\n".join(f"- {e}" for e in evid) if evid else "Nenhum bucket público aparente nas heurísticas"
    item = {
        "plugin_uuid": UUID_018,
        "scan_item_uuid": UUID_018,
        "result": txt,
        "analysis_ai": ai_fn("StorageBucketProbe", UUID_018, txt),
        "severity": sev,
        "duration": t.duration,
        "auto": True
    }
    return {"plugin": "StorageBucketProbe", "result": [item]}
