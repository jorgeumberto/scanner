# plugins/nmap_top_ports.py
from utils import run_cmd, Timer, extract_host
from typing import Dict, Any, List
import re

# UUIDs placeholders – troque pelos reais (17 e 25)
UUIDS = {
    17: "uuid-017",  # Varredura de portas comuns (Nmap --top-ports)
    25: "uuid-025",  # Portas/serviços não essenciais fechados/filtrados (na prática: detectar abertas não-essenciais)
}

TOP_PORTS = "1000"  # ajuste se quiser

def parse_open_ports(nmap_output: str) -> List[str]:
    """
    Parsea linhas tipo:
    PORT    STATE SERVICE
    22/tcp  open  ssh
    80/tcp  open  http
    """
    opens = []
    for line in nmap_output.splitlines():
        line = line.strip()
        # formato "NNN/tcp open service"
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            port, svc = m.group(1), m.group(2)
            opens.append(f"{port}/tcp ({svc})")
    return opens

def run_plugin(target: str, ai_fn):
    host = extract_host(target)
    items: List[Dict[str, Any]] = []

    # 17) top ports
    with Timer() as t_top:
        out = run_cmd(["nmap", "-Pn", "-sS", "-T4", f"--top-ports", TOP_PORTS, host], timeout=180)
        open_list = parse_open_ports(out)
        res17 = "Abertas: " + (", ".join(open_list) if open_list else "nenhuma")
        uuid17 = UUIDS[17]
        items.append({
            "plugin_uuid": uuid17,
            "scan_item_uuid": uuid17,
            "result": res17,
            "analysis_ai": ai_fn("NmapTopPorts", uuid17, res17),
            "severity": "info" if not open_list else "low",
            "duration": t_top.duration,
            "auto": True
        })

    # 25) serviços não essenciais — heurística simples: diferentes de 80/443/22/25/53/123 etc.
    essentials = {22, 25, 53, 80, 123, 443, 465, 587, 993, 995}
    non_ess = []
    for e in open_list:
        p = int(e.split("/")[0])
        if p not in essentials:
            non_ess.append(e)
    res25 = "Não essenciais abertos: " + (", ".join(non_ess) if non_ess else "nenhum")
    uuid25 = UUIDS[25]
    items.append({
        "plugin_uuid": uuid25,
        "scan_item_uuid": uuid25,
        "result": res25,
        "analysis_ai": ai_fn("NmapTopPorts", uuid25, res25),
        "severity": "medium" if non_ess else "info",
        "duration": t_top.duration,
        "auto": True
    })

    return {"plugin": "NmapTopPorts", "result": items}
