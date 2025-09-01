# plugins/sqli_probe.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urljoin, urlencode, quote_plus

PLUGIN_CONFIG_NAME = "sqli_probe"
PLUGIN_CONFIG_ALIASES = ["sqli_basic"]
UUID_049 = "uuid-049"  # GET
UUID_050 = "uuid-050"  # POST
UUID_051 = "uuid-051"  # headers

ERROR_SIGS = ["you have an error in your sql syntax", "sqlstate", "warning: mysql", "unclosed quotation mark", "odbc sql", "postgresql", "sqlite error"]

def _get(url: str, timeout: int, headers: Dict[str,str]=None) -> str:
    hdrs = []
    for k,v in (headers or {}).items(): hdrs += ["-H", f"{k}: {v}"]
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} {" ".join(hdrs)} "{url}"'], timeout=timeout+2).lower()

def _post(url: str, data: Dict[str,str], timeout: int, headers: Dict[str,str]=None) -> str:
    hdrs = []
    for k,v in (headers or {}).items(): hdrs += ["-H", f"{k}: {v}"]
    form = urlencode(data)
    return run_cmd(["bash","-lc", f'curl -sS -L -m {timeout} {" ".join(hdrs)} -X POST --data "{form}" "{url}"'], timeout=timeout+2).lower()

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg: {
      "timeout": 15,
      "get_paths": ["/products?id=1"],
      "post_paths": [{"url":"/login","data":{"user":"a","pass":"b"}}],
      "header_path": "/",
      "headers_name": "X-Test",
      "enabled": true
    }
    """
    cfg = cfg or {}
    if not bool(cfg.get("enabled", True)):
        txt = "Desabilitado por configuração."
        return {"plugin":"SQLiProbe","result":[{"plugin_uuid":UUID_049,"scan_item_uuid":UUID_049,"result":txt,"analysis_ai":ai_fn("SQLiProbe",UUID_049,txt),"severity":"info","duration":0.0,"auto":True}]}

    timeout = int(cfg.get("timeout", 15))
    gpaths = cfg.get("get_paths") or []
    ppaths = cfg.get("post_paths") or []
    hpath  = cfg.get("header_path","/")
    hname  = cfg.get("headers_name","X-Test")

    evid_get, evid_post, evid_head = [], [], []
    sev_get = sev_post = sev_head = "info"

    with Timer() as t:
        # GET
        for p in gpaths:
            base = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            inj  = "'"  # simples
            u = base + ("&" if "?" in base else "?") + f"poc={quote_plus(inj)}"
            body = _get(u, timeout)
            if any(x in body for x in ERROR_SIGS):
                evid_get.append(f"{p}: possíveis erros SQL")
                sev_get = "medium"
        # POST
        for pp in ppaths:
            u = urljoin(target.rstrip("/") + "/", pp.get("url","/").lstrip("/"))
            data = pp.get("data",{})
            data = {k:(v+"'") for k,v in data.items()}
            body = _post(u, data, timeout)
            if any(x in body for x in ERROR_SIGS):
                evid_post.append(f"{pp.get('url')}: possíveis erros SQL")
                sev_post = "medium"
        # headers
        u = urljoin(target.rstrip("/") + "/", hpath.lstrip("/"))
        body = _get(u, timeout, headers={hname:"'"})
        if any(x in body for x in ERROR_SIGS):
            evid_head.append(f"{hpath}: possíveis erros SQL via header {hname}")
            sev_head = "medium"

    def pack(uuid, text, sev):
        return {"plugin_uuid":uuid,"scan_item_uuid":uuid,"result":text,"analysis_ai":ai_fn("SQLiProbe",uuid,text),"severity":sev,"duration":t.duration,"auto":True}

    return {"plugin":"SQLiProbe","result":[
        pack(UUID_049, "\n".join(f"- {e}" for e in evid_get) if evid_get else "Sem indícios via GET", sev_get),
        pack(UUID_050, "\n".join(f"- {e}" for e in evid_post) if evid_post else "Sem indícios via POST", sev_post),
        pack(UUID_051, "\n".join(f"- {e}" for e in evid_head) if evid_head else "Sem indícios via headers", sev_head)
    ]}
