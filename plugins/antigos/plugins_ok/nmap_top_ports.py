from utils import BasePlugin, run_cmd, extrair_host
import re

class NmapTopPorts(BasePlugin):
    description = "Escaneia as 1000 portas TCP mais comuns (nmap --top-ports 1000)"
    checklist   = "Mapear portas comuns"
    category    = "Configuração e Implantação"
    tags        = ["nmap", "ports", "recon"]

    def run(self, target: str, cfg: dict) -> str:
        host = extrair_host(target)
        if not host:
            return ""
        args = ["nmap", "-Pn", "-sS", "-T4", "--top-ports", str(cfg.get("top_ports", 1000)), host]
        return run_cmd(args, timeout=cfg.get("timeout", 120))

    def parse_output(self, raw: str) -> dict:
        # Extrai linhas tipo: "80/tcp open http"
        services = []
        for line in raw.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)", line.strip())
            if m:
                port, proto, state, svc = m.groups()
                services.append({"port": int(port), "proto": proto, "state": state, "service": svc})
        return {"services": services}

    def build_checklists(self, parsed: dict) -> list:
        items = []
        svcs = parsed.get("services", [])

        # Itens gerais
        open_ports = [s for s in svcs if s["state"].lower() == "open"]
        if not svcs:
            items.append({
                "item": "Varredura de portas executada",
                "status": "FAIL",
                "evidence": "Sem saída parseada do Nmap",
                "category": "Configuração e Implantação",
                "suggestion": "Verifique conectividade/restrições e rode novamente com --top-ports 1000"
            })
            return items

        items.append({
            "item": "Portas abertas identificadas",
            "status": "PASS" if open_ports else "PASS",
            "evidence": ", ".join(f"{s['port']}/{s['proto']}({s['service']})" for s in open_ports) or "Nenhuma porta aberta",
            "category": "Configuração e Implantação",
            "suggestion": "Apenas portas necessárias devem permanecer abertas; feche/filtre as demais (firewall/SG)"
        })

        # Heurística simples: avisar se portas não-web comuns estão abertas
        expected_web = {80, 443}
        unexpected = [s for s in open_ports if s["port"] not in expected_web]
        if unexpected:
            items.append({
                "item": "Somente portas essenciais expostas",
                "status": "FAIL",
                "evidence": ", ".join(f"{s['port']}/{s['proto']}({s['service']})" for s in unexpected),
                "category": "Configuração e Implantação",
                "suggestion": "Restrinja serviços não web (ex.: 21/22/3306) ao mínimo necessário ou redes internas"
            })
        else:
            items.append({
                "item": "Somente portas essenciais expostas",
                "status": "PASS",
                "evidence": "80/443 apenas",
                "category": "Configuração e Implantação",
                "suggestion": "Mantenha exposição mínima de serviços"
            })

        return items

    def _compute_severity(self, checklists):
        for c in checklists:
            if c["item"] == "Somente portas essenciais expostas" and c["status"] == "FAIL":
                return "medium"
        return "info"
