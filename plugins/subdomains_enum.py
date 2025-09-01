# plugins/subdomain_enum.py
from typing import Dict, Any, List, Set
from utils import run_cmd, Timer, extrair_host

PLUGIN_CONFIG_NAME = "subdomain_enum"
PLUGIN_CONFIG_ALIASES = ["subs", "subdomains", "enum_subs"]

UUID_015 = "uuid-015"  # (15) Enumeração de subdomínios

def _tool_exists(tool: str) -> bool:
    out = run_cmd(["bash", "-lc", f"command -v {tool} >/dev/null 2>&1 && echo OK || true"], timeout=5)
    return "OK" in out

def _run_assetfinder(domain: str, timeout: int) -> List[str]:
    if not _tool_exists("assetfinder"): return []
    out = run_cmd(["assetfinder", "--subs-only", domain], timeout=timeout)
    return [l.strip() for l in out.splitlines() if l.strip().endswith(domain)]

def _run_subfinder(domain: str, timeout: int) -> List[str]:
    if not _tool_exists("subfinder"): return []
    out = run_cmd(["subfinder", "-silent", "-d", domain, "-timeout", str(timeout)], timeout=timeout+2)
    return [l.strip() for l in out.splitlines() if l.strip().endswith(domain)]

def _run_sublist3r(domain: str, timeout: int) -> List[str]:
    if not _tool_exists("sublist3r"): return []
    out = run_cmd(["sublist3r", "-d", domain, "-o", "-"], timeout=timeout+5)
    return [l.strip() for l in out.splitlines() if domain in l]

def _resolve(host: str) -> str:
    a = run_cmd(["dig", "+short", host, "A"], timeout=3).strip().replace("\n", ", ")
    c = run_cmd(["dig", "+short", host, "CNAME"], timeout=3).strip().replace("\n", ", ")
    info = host
    if c: info += f" [CNAME: {c}]"
    if a: info += f" [A: {a}]"
    return info

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/subdomain_enum.json):
    { "timeout": 60, "resolve_dns": true }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 60))
    resolve = bool(cfg.get("resolve_dns", True))
    domain = extrair_host(target)

    found: Set[str] = set()
    with Timer() as t:
        for fn in (_run_assetfinder, _run_subfinder, _run_sublist3r):
            try:
                for s in fn(domain, timeout):
                    found.add(s.lower())
            except Exception:
                pass

    subs = sorted(found)
    lines = [_resolve(s) for s in subs] if resolve else subs
    sev = "info" if len(subs) < 50 else "low"
    summary = "\n".join(f"- {l}" for l in lines) if lines else "Nenhum achado para Enumeração de subdomínios"

    item = {
        "plugin_uuid": UUID_015,
        "scan_item_uuid": UUID_015,
        "result": summary,
        "analysis_ai": ai_fn("SubdomainEnum", UUID_015, summary),
        "severity": sev,
        "duration": t.duration,
        "auto": True
    }
    return {"plugin": "SubdomainEnum", "result": [item]}
