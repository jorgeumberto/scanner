# plugins/gobuster_dir.py
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "gobuster_dir"
PLUGIN_CONFIG_ALIASES = ["dirb", "dirbuster", "dir"]

UUID_005 = "uuid-005"  # (5) brute de diretórios/arquivos
UUID_006 = "uuid-006"  # (6) listagem de diretórios (opcional)

def _parse_gobuster(out: str) -> List[str]:
    hits = []
    for ln in out.splitlines():
        ln = ln.strip()
        # formatos comuns: /admin (Status: 301) [Size: ...]
        if ln.startswith("/") and ("Status:" in ln or "FOUND:" in ln):
            hits.append(ln)
    return hits

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/gobuster_dir.json):
    {
      "wordlist": "/usr/share/wordlists/dirb/common.txt",
      "extensions": "php,txt,html",
      "status-codes": "200,204,301,302,307,401,403",
      "threads": 50,
      "timeout": 30,
      "add_paths_check": ["/", "/uploads/", "/static/"]  # checagem simples de "Index of"
    }
    """
    cfg = cfg or {}
    wl = cfg.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    exts = cfg.get("extensions", "")
    codes = cfg.get("status-codes", "200,204,301,302,307,401,403")
    threads = str(cfg.get("threads", 50))
    timeout = int(cfg.get("timeout", 30))
    add_paths = cfg.get("add_paths_check") or ["/"]

    cmd = ["gobuster", "dir", "-u", target, "-w", wl, "-q", "-t", threads, "-s", codes]
    if exts:
        cmd += ["-x", exts]

    findings = []
    list_evid = []

    with Timer() as t:
        out = run_cmd(cmd, timeout=timeout)
        findings = _parse_gobuster(out)

        # checagem rápida de "Index of" (item 6)
        for p in add_paths:
            body = run_cmd(["curl", "-sS", "-L", "-m", "10", urljoin(target.rstrip("/") + "/", p.lstrip("/"))], timeout=12)
            if "Index of /" in body or "<title>Index of" in body or "Parent Directory" in body:
                list_evid.append(f"{p} :: directory listing aparente")

    # severidade: achados de paths => low; se listar diretórios => medium
    sev = "info"
    if findings:
        sev = "low"
    if list_evid:
        sev = "medium"

    txt_hits = "\n".join(f"- {h}" for h in findings) if findings else "Nenhum achado para brute force de diretórios/arquivos"
    txt_list = "\n".join(f"- {e}" for e in list_evid) if list_evid else "Nenhum achado para listagem de diretórios (extra)"

    res_items = [{
        "plugin_uuid": UUID_005,
        "scan_item_uuid": UUID_005,
        "result": txt_hits,
        "analysis_ai": ai_fn("GobusterDir", UUID_005, txt_hits),
        "severity": "low" if findings else "info",
        "duration": t.duration,
        "auto": True
    }]

    # opcional: reportar também o item 6 a partir daqui
    res_items.append({
        "plugin_uuid": UUID_006,
        "scan_item_uuid": UUID_006,
        "result": txt_list,
        "analysis_ai": ai_fn("GobusterDir", UUID_006, txt_list),
        "severity": "medium" if list_evid else "info",
        "duration": t.duration,
        "auto": True
    })

    return {
        "plugin": "GobusterDir",
        "result": res_items
    }
