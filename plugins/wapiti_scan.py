# plugins/wapiti_scan.py
import json
import tempfile
import os
from typing import Dict, Any, List, Tuple

from utils import run_cmd, Timer

# ajuda o main a achar configs/wapiti.json
PLUGIN_CONFIG_NAME = "wapiti"

# UUIDs placeholders — troque pelos reais (IDs 47,48,49,50,55,53,56)
UUIDS = {
    47: "uuid-047",  # XSS refletido
    48: "uuid-048",  # XSS armazenado
    49: "uuid-049",  # SQL Injection (GET)
    50: "uuid-050",  # SQL Injection (POST)
    55: "uuid-055",  # LFI/RFI/Traversal
    53: "uuid-053",  # Command Injection
    56: "uuid-056"   # SSRF (cobertura parcial)
}

# mapeia categorias do Wapiti -> (id_relatorio, severidade se houver findings, label amigável)
WAPITI_MAP = {
    "xss":             (47, "medium", "XSS refletido"),
    "permanentxss":    (48, "high",   "XSS armazenado"),
    "sql":             (49, "high",   "SQL Injection (GET/POST)"),
    "file":            (55, "high",   "Path Traversal / LFI/RFI"),
    "commandinj":      (53, "high",   "Command Injection"),
    "ssrf":            (56, "high",   "SSRF")
}

def _run_wapiti(target: str, timeout: int, modules: List[str], max_depth: int, max_links_per_page: int, headers: List[str]) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        out_dir = td
        cmd = ["wapiti", "-u", target, "-f", "json", "-o", out_dir, "-m", ",".join(modules)]
        if max_depth:
            cmd += ["--max-depth", str(max_depth)]
        if max_links_per_page:
            cmd += ["--max-links-per-page", str(max_links_per_page)]
        for h in headers or []:
            cmd += ["-H", h]

        _ = run_cmd(cmd, timeout=timeout)

        report_path = os.path.join(out_dir, "report.json")
        if not os.path.exists(report_path):
            for f in os.listdir(out_dir):
                if f.endswith(".json"):
                    report_path = os.path.join(out_dir, f)
                    break

        try:
            with open(report_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

def _collect_findings(wjson: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    vulns = wjson.get("vulnerabilities") or []
    for v in vulns:
        name = (v.get("name") or "").lower().replace(" ", "")
        if "xss" in name and "permanent" in name:
            key = "permanentxss"
        elif "xss" in name:
            key = "xss"
        elif "sql" in name:
            key = "sql"
        elif "file" in name or "pathtraversal" in name or "lfi" in name or "rfi" in name:
            key = "file"
        elif "command" in name:
            key = "commandinj"
        elif "ssrf" in name:
            key = "ssrf"
        else:
            key = name or "misc"

        out.setdefault(key, [])
        details = v.get("detail") or []
        for d in details:
            url = d.get("url") or d.get("path") or ""
            info = d.get("info") or d.get("parameter") or ""
            method = (d.get("method") or "").upper()
            out[key].append({"url": url, "info": info, "method": method})
    return out

def _summarize(entries: List[Dict[str, Any]], checklist_name: str, max_lines: int = 6) -> str:
    """Resumo com mensagem contextual."""
    if not entries:
        return f"Nenhum achado para {checklist_name}"
    lines = []
    for e in entries[:max_lines]:
        m = e.get("method", "")
        lines.append(f"- {e.get('url','?')} [{m}] :: {e.get('info','')[:160]}")
    extra = len(entries) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} achados")
    return "\n".join(lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/wapiti.json:
    {
      "timeout": 1800,
      "modules": ["xss","sql","file","commandinj","ssrf"],
      "max_depth": 4,
      "max_links_per_page": 100,
      "headers": [],
      "severity_overrides": { "xss": "medium", "sql": "high", "file": "high", "commandinj": "high", "ssrf": "high" }
    }
    """
    cfg = cfg or {}
    timeout  = int(cfg.get("timeout", 1800))
    modules  = cfg.get("modules") or ["xss", "sql", "file", "commandinj", "ssrf"]
    max_depth = int(cfg.get("max_depth", 4))
    max_links_per_page = int(cfg.get("max_links_per_page", 100))
    headers  = cfg.get("headers") or []
    sev_over = cfg.get("severity_overrides") or {}

    with Timer() as t:
        data = _run_wapiti(target, timeout, modules, max_depth, max_links_per_page, headers)
    duration = t.duration

    grouped = _collect_findings(data)
    items: List[Dict[str, Any]] = []

    # Para cada categoria mapeada, gera item com uuid/severidade
    for key, (rid, sev_on_find, label) in WAPITI_MAP.items():
        entries = grouped.get(key, [])
        uuid = UUIDS[rid]
        res = _summarize(entries, label)
        severity = sev_over.get(key, sev_on_find) if entries else "info"
        items.append({
            "plugin_uuid": uuid,
            "scan_item_uuid": uuid,
            "result": res,
            "analysis_ai": ai_fn("Wapiti", uuid, res),
            "severity": severity,
            "duration": duration,
            "auto": True
        })

    return {"plugin": "Wapiti", "result": items}
