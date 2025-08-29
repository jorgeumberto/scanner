# plugins/nikto_scan.py
import json
import tempfile
import os
from typing import Dict, Any, List

from utils import run_cmd, Timer

# ajuda o main dinâmico a achar configs/nikto.json
PLUGIN_CONFIG_NAME = "nikto"

# UUIDs placeholders — troque pelos reais (IDs 4, 6, 28 e um agregado)
UUIDS = {
    4:  "uuid-004",        # Arquivos sensíveis expostos
    6:  "uuid-006",        # Listagem de diretórios habilitada
    28: "uuid-028",        # Logs sensíveis acessíveis publicamente
    900: "uuid-900-misc"   # Agregado (misconfigurações/versões/etc.)
}

def _run_nikto_json(target: str, timeout: int, plugins: List[str], useragent: str, ssl: bool, root_only: bool) -> Dict[str, Any]:
    """
    Executa Nikto com saída JSON. Nikto geralmente precisa escrever em arquivo.
    """
    with tempfile.TemporaryDirectory() as td:
        out_path = os.path.join(td, "nikto.json")
        cmd = ["nikto", "-h", target, "-Format", "json", "-o", out_path, "-nointeractive"]
        if useragent:
            cmd += ["-useragent", useragent]
        if plugins:
            cmd += ["-Plugins", ",".join(plugins)]
        if ssl:
            cmd += ["-ssl"]
        if root_only:
            cmd += ["-rootonly"]

        _ = run_cmd(cmd, timeout=timeout)
        try:
            with open(out_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

def _classify_findings(nikto_json: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Separa findings em grupos de interesse:
      - sensitive_files (id=4)
      - dir_listing (id=6)
      - logs_exposed (id=28)
      - misc (id=900)
    """
    groups = {"sensitive_files": [], "dir_listing": [], "logs_exposed": [], "misc": []}
    if not nikto_json:
        return groups

    vulns = nikto_json.get("vulnerabilities") or nikto_json.get("vuln") or []
    for v in vulns:
        msg = (v.get("msg") or v.get("message") or "").lower()
        url = v.get("url") or v.get("uri") or ""
        entry = {"url": url, "msg": v.get("msg") or v.get("message") or ""}

        if any(x in url for x in [".env", ".git", ".svn", ".bak", ".old"]) or "backup" in msg or "config" in msg:
            groups["sensitive_files"].append(entry)
        elif "directory indexing" in msg or "directory listing" in msg:
            groups["dir_listing"].append(entry)
        elif "log" in url or "log" in msg:
            groups["logs_exposed"].append(entry)
        else:
            groups["misc"].append(entry)
    return groups

def _summarize(entries: List[Dict[str, Any]], checklist_name: str, max_lines: int = 6) -> str:
    """Resumo com mensagem contextual."""
    if not entries:
        return f"Nenhum achado para {checklist_name}"
    lines = []
    for e in entries[:max_lines]:
        lines.append(f"- {e.get('url','?')} :: {e.get('msg','').strip()[:160]}")
    extra = len(entries) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} achados")
    return "\n".join(lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/nikto.json:
    {
      "timeout": 600,
      "plugins": [],
      "useragent": "Pentest-Auto/1.0",
      "ssl": false,
      "root_only": false,
      "severity_map": {
        "sensitive_files": "high",
        "dir_listing": "medium",
        "logs_exposed": "medium",
        "misc": "info"
      }
    }
    """
    cfg = cfg or {}
    timeout    = int(cfg.get("timeout", 600))
    plugins    = cfg.get("plugins") or []
    useragent  = cfg.get("useragent", "Pentest-Auto/1.0")
    ssl        = bool(cfg.get("ssl", False))
    root_only  = bool(cfg.get("root_only", False))
    sev_map    = cfg.get("severity_map") or {
        "sensitive_files": "high",
        "dir_listing": "medium",
        "logs_exposed": "medium",
        "misc": "info"
    }

    with Timer() as t:
        data = _run_nikto_json(target, timeout, plugins, useragent, ssl, root_only)
    duration = t.duration

    groups = _classify_findings(data)

    items: List[Dict[str, Any]] = []

    # ID 4: Arquivos sensíveis expostos
    uuid4 = UUIDS[4]
    g4 = groups["sensitive_files"]
    res4 = _summarize(g4, "Arquivos sensíveis expostos")
    items.append({
        "plugin_uuid": uuid4,
        "scan_item_uuid": uuid4,
        "result": res4,
        "analysis_ai": ai_fn("Nikto", uuid4, res4),
        "severity": sev_map.get("sensitive_files", "high") if g4 else "info",
        "duration": duration,
        "auto": True
    })

    # ID 6: Listagem de diretórios habilitada
    uuid6 = UUIDS[6]
    g6 = groups["dir_listing"]
    res6 = _summarize(g6, "Listagem de diretórios habilitada")
    items.append({
        "plugin_uuid": uuid6,
        "scan_item_uuid": uuid6,
        "result": res6,
        "analysis_ai": ai_fn("Nikto", uuid6, res6),
        "severity": sev_map.get("dir_listing", "medium") if g6 else "info",
        "duration": duration,
        "auto": True
    })

    # ID 28: Logs sensíveis acessíveis publicamente
    uuid28 = UUIDS[28]
    g28 = groups["logs_exposed"]
    res28 = _summarize(g28, "Logs sensíveis acessíveis publicamente")
    items.append({
        "plugin_uuid": uuid28,
        "scan_item_uuid": uuid28,
        "result": res28,
        "analysis_ai": ai_fn("Nikto", uuid28, res28),
        "severity": sev_map.get("logs_exposed", "medium") if g28 else "info",
        "duration": duration,
        "auto": True
    })

    # Agregado (outros achados do Nikto)
    uuid_misc = UUIDS[900]
    gm = groups["misc"]
    resm = _summarize(gm, "Outros achados de configuração")
    items.append({
        "plugin_uuid": uuid_misc,
        "scan_item_uuid": uuid_misc,
        "result": resm,
        "analysis_ai": ai_fn("Nikto", uuid_misc, resm),
        "severity": sev_map.get("misc", "info") if gm else "info",
        "duration": duration,
        "auto": True
    })

    return {"plugin": "Nikto", "result": items}
