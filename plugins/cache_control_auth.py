# plugins/cache_control_auth.py
from typing import Dict, Any, List, Tuple
from urllib.parse import urljoin
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "cache_control_auth"
PLUGIN_CONFIG_ALIASES = ["cache_auth", "cachecontrol"]

UUID_021 = "uuid-021"  # (21) Cache-Control/Pragma para conteúdo sensível (reforço)

def _curl_head(url: str, timeout: int) -> List[str]:
    raw = run_cmd(["curl", "-sS", "-I", "-L", "-m", str(timeout), url], timeout=timeout+2)
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]

def _get_header(lines: List[str], name: str) -> str:
    name_low = name.lower() + ":"
    for ln in lines:
        if ln.lower().startswith(name_low):
            return ln.split(":",1)[1].strip()
    return ""

def _score(url: str, lines: List[str]) -> Tuple[str, List[str]]:
    cc     = _get_header(lines, "Cache-Control")
    pragma = _get_header(lines, "Pragma")
    cookie = _get_header(lines, "Set-Cookie")
    evid   = [f"URL: {url}"]
    sev    = "info"

    if cookie:
        evid.append(f"Set-Cookie: {cookie[:120]}{'...' if len(cookie)>120 else ''}")
        if not cc and not pragma:
            sev = "medium"
            evid.append("Ausente: Cache-Control/Pragma em resposta com cookie")
        else:
            evid.append(f"Cache-Control: {cc or '—'} | Pragma: {pragma or '—'}")
            low = (cc or "").lower()
            if not any(k in low for k in ["no-store","no-cache","private"]):
                sev = "low"
                evid.append("Sugestão: usar 'no-store' (e/ou 'no-cache', 'private') para respostas autenticadas")
    else:
        evid.append("Sem Set-Cookie nesta resposta — verificação informacional")
        if cc:
            evid.append(f"Cache-Control: {cc}")

    return sev, evid

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg:
    {
      "timeout": 15,
      "paths": ["/", "/dashboard", "/account", "/profile"]
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    paths   = cfg.get("paths") or ["/", "/dashboard", "/account", "/profile"]

    items = []
    with Timer() as t:
        for p in paths:
            url = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            lines = _curl_head(url, timeout)
            sev, evid = _score(url, lines)
            text = "\n".join(f"- {e}" for e in evid)
            items.append({
                "plugin_uuid": UUID_021,
                "scan_item_uuid": UUID_021,
                "result": text,
                "analysis_ai": ai_fn("CacheControlAuth", UUID_021, text),
                "severity": sev,
                "duration": t.duration,
                "auto": True
            })

    return {"plugin": "CacheControlAuth", "result": items}
