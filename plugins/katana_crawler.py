# plugins/katana_crawler.py
import shutil
import json
import re
from typing import Dict, Any, List, Set

from utils import run_cmd, Timer, extract_host

PLUGIN_CONFIG_NAME = "katana"
PLUGIN_CONFIG_ALIASES = ["crawler", "gospider", "hakrawler"]

UUID_8 = "uuid-008"  # Spider/crawler para endpoints públicos

def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def _norm(url: str) -> str:
    return url.strip()

def _run_katana(target: str, timeout: int, depth: int, concurrency: int, js_crawl: bool, uniq: bool, jsonl: bool, extra_args: List[str]) -> List[str]:
    cmd = ["katana", "-u", target, "-d", str(depth), "-c", str(concurrency)]
    if js_crawl:
        cmd += ["-jc"]
    if uniq:
        cmd += ["-silent"]
    if jsonl:
        cmd += ["-jsonl"]
    if extra_args:
        cmd += extra_args
    out = run_cmd(cmd, timeout=timeout)
    urls: Set[str] = set()
    if jsonl:
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
                u = obj.get("request", {}).get("url") or obj.get("url")
                if u:
                    urls.add(_norm(u))
            except Exception:
                continue
    else:
        for ln in out.splitlines():
            if ln.strip().startswith("http"):
                urls.add(_norm(ln.strip()))
    return sorted(urls)

def _run_gospider(target: str, timeout: int, depth: int, threads: int, extra_args: List[str]) -> List[str]:
    cmd = ["gospider", "-s", target, "-d", str(depth), "-t", str(threads), "--silent"]
    if extra_args:
        cmd += extra_args
    out = run_cmd(cmd, timeout=timeout)
    urls = []
    for ln in out.splitlines():
        s = ln.strip()
        m = re.search(r"(https?://[^\s]+)", s)
        if m:
            urls.append(_norm(m.group(1)))
    return sorted(set(urls))

def _summarize(urls: List[str], checklist_name: str, max_lines: int = 30) -> str:
    if not urls:
        return f"Nenhum achado para {checklist_name}"
    lines = [f"- {u}" for u in urls[:max_lines]]
    extra = len(urls) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} endpoints")
    return "\n".join(lines)

def _heuristic_severity(urls: List[str]) -> str:
    # crawler é informativo; se encontrar /admin, /debug, /api/internal, sobe para low
    if not urls:
        return "info"
    hot = ["/admin", "/debug", "/.git", "/.env", "/api/internal", "/wp-admin"]
    for u in urls:
        if any(tok in u.lower() for tok in hot):
            return "low"
    return "info"

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/katana.json):
    {
      "timeout": 600,
      "depth": 3,
      "concurrency": 10,
      "use_jsonl": true,
      "js_crawl": true,
      "uniq": true,
      "prefer": ["katana","gospider"],
      "extra_args_katana": [],
      "extra_args_gospider": [],
      "limit_results": 0
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 600))
    depth = int(cfg.get("depth", 3))
    concurrency = int(cfg.get("concurrency", 10))
    jsonl = bool(cfg.get("use_jsonl", True))
    js_crawl = bool(cfg.get("js_crawl", True))
    uniq = bool(cfg.get("uniq", True))
    prefer = cfg.get("prefer") or ["katana", "gospider"]
    extra_katana = cfg.get("extra_args_katana") or []
    extra_gospider = cfg.get("extra_args_gospider") or []
    limit = int(cfg.get("limit_results", 0))

    urls: List[str] = []

    with Timer() as t:
        for tool in prefer:
            try:
                if tool == "katana" and _has("katana"):
                    urls = _run_katana(target, timeout, depth, concurrency, js_crawl, uniq, jsonl, extra_katana)
                    if urls:
                        break
                elif tool == "gospider" and _has("gospider"):
                    urls = _run_gospider(target, timeout, depth, concurrency, extra_gospider)
                    if urls:
                        break
            except Exception:
                continue
    duration = t.duration

    if limit and len(urls) > limit:
        urls = urls[:limit]

    checklist = "Spider/crawler para endpoints públicos"
    result = _summarize(urls, checklist)
    severity = _heuristic_severity(urls)

    return {
        "plugin": "KatanaCrawler",
        "result": [{
            "plugin_uuid": UUID_8,
            "scan_item_uuid": UUID_8,
            "result": result,
            "analysis_ai": ai_fn("KatanaCrawler", UUID_8, result),
            "severity": severity,
            "duration": duration,
            "auto": True
        }]
    }
