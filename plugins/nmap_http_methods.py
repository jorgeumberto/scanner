# plugins/nmap_http_methods.py
from utils import run_cmd, Timer, extract_host
from typing import Dict, Any, List
import re

# UUID placeholder – troque pelo real (24)
UUID = "uuid-024"

def parse_nmap_http_methods(out: str) -> str:
    """
    Procura por linhas do script http-methods, ex:
      |_  Supported Methods: GET HEAD POST OPTIONS
      |   Allowed Methods: GET, POST, OPTIONS, HEAD
    """
    lines = []
    for line in out.splitlines():
        line = line.strip()
        if re.search(r"(Supported|Allowed)\s+Methods", line, re.I):
            lines.append(re.sub(r"\s+", " ", line))
    return "\n".join(lines) if lines else "(não encontrado)"

def run_plugin(target: str, ai_fn):
    host = extract_host(target)
    items: List[Dict[str, Any]] = []

    with Timer() as t:
        out80  = run_cmd(["nmap", "-Pn", "-p", "80",  "--script", "http-methods", host], timeout=120)
        out443 = run_cmd(["nmap", "-Pn", "-p", "443", "--script", "http-methods", host], timeout=120)

        parsed_sections = []
        p80 = parse_nmap_http_methods(out80)
        if p80 and p80 != "(não encontrado)":
            parsed_sections.append(f"[80]\n{p80}")
        p443 = parse_nmap_http_methods(out443)
        if p443 and p443 != "(não encontrado)":
            parsed_sections.append(f"[443]\n{p443}")

        res = "\n\n".join(parsed_sections) if parsed_sections else "(não encontrado em 80/443)"
    duration_total = t.duration  # <-- fora do with

    # severidade: se achar TRACE/PUT/DELETE/CONNECT em qualquer lista, high
    text_upper = res.upper()
    danger = any(x in text_upper for x in ["TRACE", "PUT", "DELETE", "CONNECT"])
    severity = "high" if danger else ("info" if any(y in text_upper for y in ["GET", "POST", "HEAD", "OPTIONS"]) else "low")

    items.append({
        "plugin_uuid": UUID,
        "scan_item_uuid": UUID,
        "result": res,
        "analysis_ai": ai_fn("NmapHttpMethods", UUID, res),
        "severity": severity,
        "duration": duration_total,
        "auto": True
    })

    return {"plugin": "NmapHttpMethods", "result": items}
