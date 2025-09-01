# plugins/crawler_endpoints.py
from typing import Dict, Any, List
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "crawler_endpoints"
PLUGIN_CONFIG_ALIASES = ["crawler", "hakrawler", "gospider"]

UUID_008 = "uuid-008"  # (8) Spider/crawler para endpoints públicos

def _tool_exists(tool: str) -> bool:
    out = run_cmd(["bash", "-lc", f"command -v {tool} >/dev/null 2>&1 && echo OK || true"], timeout=5)
    return "OK" in out

def _run_hakrawler(url: str, depth: int, timeout: int) -> List[str]:
    if not _tool_exists("hakrawler"): return []
    cmd = ["bash", "-lc", f"echo {url} | hakrawler -plain -depth {depth} -insecure 2>/dev/null"]
    out = run_cmd(cmd, timeout=timeout)
    return [l.strip() for l in out.splitlines() if l.strip().startswith(("http://","https://"))]

def _run_gospider(url: str, depth: int, timeout: int) -> List[str]:
    if not _tool_exists("gospider"): return []
    cmd = ["gospider", "-s", url, "-d", str(depth), "-q", "--other-source=false", "--include-subs=false"]
    out = run_cmd(cmd, timeout=timeout)
    # linhas costumam vir com prefixos; simplificação:
    hits = []
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("[" ) and "] " in ln:
            ln = ln.split("] ",1)[1]
        if ln.startswith(("http://","https://")):
            hits.append(ln)
    return hits

def _fallback_grep(url: str, timeout: int) -> List[str]:
    # baixa home e extrai href/src bem simples (fallback)
    html = run_cmd(["curl", "-sS", "-L", "-m", str(timeout), url], timeout=timeout+2)
    hits = []
    for tok in html.replace("'",'"').split('"'):
        tok = tok.strip()
        if tok.startswith(("http://","https://")) and not tok.endswith((".css",".png",".jpg",".jpeg",".gif",".webp",".ico",".svg")):
            hits.append(tok)
    return hits

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/crawler_endpoints.json):
    { "timeout": 60, "depth": 2, "max_urls": 100 }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 60))
    depth   = int(cfg.get("depth", 2))
    max_urls= int(cfg.get("max_urls", 100))

    all_urls: List[str] = []
    with Timer() as t:
        all_urls += _run_hakrawler(target, depth, timeout)
        if not all_urls:
            all_urls += _run_gospider(target, depth, timeout)
        if not all_urls:
            all_urls += _fallback_grep(target, timeout=15)

    # dedup + limit
    seen = set()
    out = []
    for u in all_urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= max_urls: break

    summary = "\n".join(f"- {u}" for u in out) if out else "Nenhum achado para Crawler de endpoints públicos"
    sev = "info"  # coleta informacional

    item = {
        "plugin_uuid": UUID_008,
        "scan_item_uuid": UUID_008,
        "result": summary,
        "analysis_ai": ai_fn("CrawlerEndpoints", UUID_008, summary),
        "severity": sev,
        "duration": t.duration,
        "auto": True
    }
    return {"plugin": "CrawlerEndpoints", "result": [item]}
