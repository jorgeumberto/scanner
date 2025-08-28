from utils import BasePlugin, run_cmd

class CurlHttpMethods(BasePlugin):
    description = "Verifica métodos HTTP aceitos pelo servidor via curl OPTIONS"
    checklist   = "Identificar métodos HTTP permitidos"
    category    = "Configuração e Implantação"
    tags        = ["curl", "http", "methods"]

    def run(self, target: str, cfg: dict) -> str:
        args = ["curl", "-sS", "-i", "-X", "OPTIONS"]
        if cfg.get("insecure", False):
            args.append("-k")
        args.append(target)
        return run_cmd(args, timeout=cfg.get("timeout", 15))

    def parse_output(self, raw: str) -> dict:
        parsed = {}
        for line in raw.splitlines():
            l = line.strip()
            if l.lower().startswith("allow:"):
                parsed["allow"] = l.split(":", 1)[1].strip()
        return parsed

    def build_checklists(self, parsed: dict) -> list:
        items = []
        allow = parsed.get("allow")
        if not allow:
            items.append({
                "item": "Cabeçalho Allow presente",
                "status": "FAIL",
                "evidence": "Nenhum cabeçalho Allow encontrado (OPTIONS)",
                "category": "Configuração e Implantação",
                "suggestion": "Habilite o suporte adequado ao método OPTIONS ou configure o servidor para responder com 'Allow'"
            })
            return items

        allowed = [m.strip().upper() for m in allow.split(",")]
        items.append({
            "item": "Cabeçalho Allow presente",
            "status": "PASS",
            "evidence": allow,
            "category": "Configuração e Implantação",
            "suggestion": "Mantenha a lista de métodos mínima necessária"
        })

        inseguros = {"PUT", "DELETE", "TRACE", "CONNECT"}
        perigosos = sorted(set(allowed).intersection(inseguros))
        if perigosos:
            items.append({
                "item": "Métodos inseguros não permitidos",
                "status": "FAIL",
                "evidence": ", ".join(perigosos),
                "category": "Configuração e Implantação",
                "suggestion": "Desabilite PUT/DELETE/TRACE/CONNECT no servidor/reverso (ex.: Nginx 'limit_except', Apache <LimitExcept>)"
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
        # Qualquer FAIL em métodos inseguros => HIGH; ausência de Allow => MEDIUM
        names = {c["item"]: c["status"] for c in checklists}
        if names.get("Métodos inseguros não permitidos") == "FAIL":
            return "high"
        if names.get("Cabeçalho Allow presente") == "FAIL":
            return "medium"
        return "info"
