# plugins/dir_listing_check.py
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "dir_listing_check"
PLUGIN_CONFIG_ALIASES = ["dirlisting", "listing"]

UUID_006 = "uuid-006-dir-list"  # (6) Listagem de diretórios habilitada

SIGNALS = [
    "Index of /", "Parent Directory", "Directory listing for", "<title>Index of", "Directory Listing Denied"  # último indica bloqueio (evidência útil)
]

def _curl_body(url: str, timeout: int) -> str:
    # baixa HTML (segue redirects), limita tempo
    return run_cmd(["curl", "-sS", "-L", "-m", str(timeout), url], timeout=timeout+2)

def _is_listing(html: str) -> bool:
    low = html.lower()
    return ("index of /".lower() in low) or ("parent directory".lower() in low) or ("directory listing for".lower() in low)

def _summarize(lines: List[str], checklist_name: str, max_lines: int = 20) -> str:
    if not lines:
        return f"Nenhum achado para {checklist_name}"
    body = [f"- {l}" for l in lines[:max_lines]]
    extra = len(lines) - len(body)
    if extra > 0:
        body.append(f"... +{extra} evidências")
    return "\n".join(body)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg:
    {
      "timeout": 15,
      "paths": ["/", "/uploads/", "/static/", "/.git/"],
      "extra_urls": []
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    paths = cfg.get("paths") or ["/", "/uploads/", "/static/", "/.well-known/"]
    extra = cfg.get("extra_urls") or []

    urls: List[str] = [urljoin(target.rstrip("/") + "/", p.lstrip("/")) for p in paths]
    urls += [u for u in extra if u.startswith("http")]

    evid: List[str] = []
    worst = "info"

    with Timer() as t:
        for u in urls:
            html = _curl_body(u, timeout)
            if not html:
                continue
            if _is_listing(html):
                evid.append(f"{u} :: directory listing aparente")
                worst = "medium"  # pode expor estrutura/arquivos
            else:
                # também registramos evidência de bloqueio explícito
                if any(sig.lower() in html.lower() for sig in ["directory listing denied"]):
                    evid.append(f"{u} :: listing negado (bloqueado)")

    duration = t.duration
    result = _summarize(evid, "Listagem de diretórios habilitada")

    return {
        "plugin": "DirListingCheck",
        "result": [{
            "plugin_uuid": UUID_006,
            "scan_item_uuid": UUID_006,
            "result": result,
            "analysis_ai": ai_fn("DirListingCheck", UUID_006, result),
            "severity": worst,
            "duration": duration,
            "auto": True
        }]
    }
