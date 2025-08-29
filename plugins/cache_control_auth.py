# plugins/cache_control_auth.py
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "cache_control_auth"
PLUGIN_CONFIG_ALIASES = ["cache_auth", "cache_sensitive_auth"]

UUID_021 = "uuid-021"  # Item 21 (mesmo ID da versão não-autenticada)

SENSITIVE_HINTS = [
    "login", "signin", "account", "profile", "checkout", "cart", "payment",
    "admin", "reset", "2fa", "mfa", "settings", "invoice", "token"
]

def _curl_head(url: str, timeout: int, headers: List[str]) -> str:
    cmd = ["curl", "-sS", "-I", "-L", "-m", str(timeout), url]
    for h in headers or []:
        cmd += ["-H", h]
    return run_cmd(cmd, timeout=timeout+2)

def _parse_header(raw: str, name: str) -> str:
    for ln in raw.splitlines():
        if ln.lower().startswith(name.lower() + ":"):
            return ln.split(":", 1)[1].strip()
    return ""

def _is_sensitive_path(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in SENSITIVE_HINTS)

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
    cfg (configs/cache_control_auth.json):
    {
      "timeout": 20,
      "paths": ["/account", "/checkout", "/settings"],
      "extra_urls": [],
      "headers": ["Cookie: session=...", "Authorization: Bearer ..."],
      "treat_all_as_sensitive": true
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    paths = cfg.get("paths") or ["/account", "/settings"]
    extra_urls = cfg.get("extra_urls") or []
    headers = cfg.get("headers") or []
    treat_all = bool(cfg.get("treat_all_as_sensitive", True))

    urls: List[str] = [urljoin(target.rstrip("/") + "/", p.lstrip("/")) for p in paths]
    urls += extra_urls

    evid_cache: List[str] = []
    with Timer() as t:
        for u in urls:
            try:
                hdrs = _curl_head(u, timeout, headers)
            except Exception:
                continue

            cc  = _parse_header(hdrs, "Cache-Control")
            pg  = _parse_header(hdrs, "Pragma")

            is_sensitive = treat_all or _is_sensitive_path(u)
            if not is_sensitive:
                continue

            miss = []
            if not cc:
                miss.append("Cache-Control ausente")
            else:
                low = cc.lower()
                if "no-store" not in low:
                    miss.append("no-store ausente")
                if "no-cache" not in low:
                    miss.append("no-cache ausente")
                if "must-revalidate" not in low and "private" not in low:
                    miss.append("must-revalidate/private ausente")
            if not pg:
                miss.append("Pragma ausente (no-cache)")

            if miss:
                evid_cache.append(f"{u} :: {', '.join(miss)}")
            else:
                evid_cache.append(f"{u} :: cache adequado ({cc}; Pragma: {pg or '—'})")

    duration = t.duration
    sev = "medium" if any("ausente" in e for e in evid_cache) else "info"
    result = _summarize(evid_cache, "Cache-Control/Pragma em páginas autenticadas")

    return {
        "plugin": "CacheControlAuth",
        "result": [{
            "plugin_uuid": UUID_021,
            "scan_item_uuid": UUID_021,
            "result": result,
            "analysis_ai": ai_fn("CacheControlAuth", UUID_021, result),
            "severity": sev,
            "duration": duration,
            "auto": True
        }]
    }
