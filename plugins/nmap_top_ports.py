# plugins/nmap_top_ports.py
from utils import run_cmd, Timer, extract_host
from typing import Dict, Any, List
import re

# UUIDs placeholders – troque pelos reais (17 e 25)
UUIDS = {
    17: "uuid-017",  # Varredura de portas comuns (Nmap --top-ports)
    25: "uuid-025",  # Portas/serviços não essenciais fechados/filtrados
}

TOP_PORTS = "1000"  # ajuste se quiser

def parse_open_ports(nmap_output: str) -> List[str]:
    """
    Encontra linhas 'NNN/tcp  open  service' no output do nmap.
    Ignora open|filtered etc. — foco em 'open'.
    """
    opens = []
    for line in nmap_output.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            port, svc = m.group(1), m.group(2)
            opens.append(f"{port}/tcp ({svc})")
    return opens

def run_plugin(target: str, ai_fn):
    host = extract_host(target)
    items: List[Dict[str, Any]] = []

    # 1) top ports (uma medição de tempo)
    with Timer() as t_top:
        out = run_cmd(
            ["nmap", "-Pn", "-sS", "-T4", "--top-ports", TOP_PORTS, host],
            timeout=180
        )
        open_list = parse_open_ports(out)
    duration_top = t_top.duration  # <-- fora do with

    # ID 17
    uuid17 = UUIDS[17]
    res17 = "Abertas: " + (", ".join(open_list) if open_list else "nenhuma")
    items.append({
        "plugin_uuid": uuid17,
        "scan_item_uuid": uuid17,
        "result": res17,
        "analysis_ai": ai_fn("NmapTopPorts", uuid17, res17),
        "severity": "info" if not open_list else "low",
        "duration": duration_top,
        "auto": True
    })

    # 2) não essenciais (usa o mesmo resultado; mesma duração do scan)
    essentials = {22, 25, 53, 80, 123, 443, 465, 587, 993, 995}
    non_ess = []
    for e in open_list:
        p = int(e.split("/")[0])
        if p not in essentials:
            non_ess.append(e)

    uuid25 = UUIDS[25]
    res25 = "Não essenciais abertos: " + (", ".join(non_ess) if non_ess else "nenhum")
    items.append({
        "plugin_uuid": uuid25,
        "scan_item_uuid": uuid25,
        "result": res25,
        "analysis_ai": ai_fn("NmapTopPorts", uuid25, res25),
        "severity": "medium" if non_ess else "info",
        "duration": duration_top,
        "auto": True
    })

    return {"plugin": "NmapTopPorts", "result": items}
