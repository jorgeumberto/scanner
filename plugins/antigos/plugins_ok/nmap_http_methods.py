from utils import BasePlugin, run_cmd, extrair_host
import re

class NmapHttpMethods(BasePlugin):
    description = "Descobre métodos HTTP permitidos via nmap --script http-methods"
    checklist   = "Identificar métodos HTTP permitidos"
    category    = "Configuração e Implantação"
    tags        = ["nmap", "http-methods", "http"]

    def run(self, target: str, cfg: dict) -> str:
        host = extrair_host(target)
        if not host:
            return ""
        port = str(cfg.get("port", 80))
        args = ["nmap", "-Pn", "-p", port, "--script", "http-methods", host]
        return run_cmd(args, timeout=cfg.get("timeout", 120))

    def parse_output(self, raw: str) -> dict:
        # Procura bloco: "Allowed methods: GET, HEAD, POST"
        allowed = None
        for line in raw.splitlines():
            m = re.search(r"Allowed methods:\s*(.+)", line, re.IGNORECASE)
            if m:
                allowed = m.group(1).strip()
                break
        return {"allow": allowed} if allowed else {}

    def build_checklists(self, parsed: dict) -> list:
        items = []
        allow = parsed.get("allow")
        if not allow:
            items.append({
                "item": "Métodos HTTP identificados",
                "status": "FAIL",
                "evidence": "Nenhuma linha 'Allowed methods' encontrada",
                "category": "Configuração e Implantação",
                "suggestion": "Verifique se o alvo/porta estão corretos e se o serviço é HTTP"
            })
            return items

        allowed = [m.strip().upper() for m in allow.split(",")]
        items.append({
            "item": "Métodos HTTP identificados",
            "status": "PASS",
            "evidence": allow,
            "category": "Configuração e Implantação",
            "suggestion": "Mantenha a lista mínima necessária de métodos"
        })

        inseguros = {"PUT", "DELETE", "TRACE", "CONNECT"}
        perigosos = sorted(set(allowed).intersection(inseguros))
        if perigosos:
            items.append({
                "item": "Métodos inseguros não permitidos",
                "status": "FAIL",
                "evidence": ", ".join(perigosos),
                "category": "Configuração e Implantação",
                "suggestion": "Desabilite métodos inseguros no servidor/proxy (Nginx/Apache/IIS)"
            })
        else:
            items.append({
                "item": "Métodos inseguros não permitidos",
                "status": "PASS",
                "evidence": ", ".join(allowed),
                "category": "Configuração e Implantação",
                "suggestion": "Mantenha apenas GET/POST/HEAD (e OPTIONS quando necessário)"
            })

        return items

    def _compute_severity(self, checklists):
        names = {c["item"]: c["status"] for c in checklists}
        if names.get("Métodos inseguros não permitidos") == "FAIL":
            return "high"
        if names.get("Métodos HTTP identificados") == "FAIL":
            return "medium"
        return "info"
