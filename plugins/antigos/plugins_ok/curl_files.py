from utils import BasePlugin, run_cmd, extrair_host

class CurlFiles(BasePlugin):
    description = "Verifica exposição de arquivos comuns (robots.txt, sitemap.xml, humans.txt, security.txt)"
    checklist   = "Verificar exposição de arquivos comuns"
    category    = "Coleta de Informações"
    tags        = ["curl", "files", "http", "recon"]

    DEFAULT_FILES = [
        "robots.txt",
        "sitemap.xml",
        "humans.txt",
        ".well-known/security.txt"
    ]

    def run(self, target: str, cfg: dict) -> str:
        results = []
        files = cfg.get("files", self.DEFAULT_FILES)

        for f in files:
            url = target.rstrip("/") + "/" + f
            out = run_cmd(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", url], timeout=cfg.get("timeout", 10))
            results.append(f"{f} {out.strip()}")
        return "\n".join(results)

    def parse_output(self, raw: str) -> dict:
        parsed = {}
        for line in raw.splitlines():
            parts = line.strip().split()
            if len(parts) == 2:
                fname, code = parts
                parsed[fname] = code
        return parsed

    def build_checklists(self, parsed: dict) -> list:
        items = []
        for fname, code in parsed.items():
            if code == "200":
                items.append({
                    "item": f"{fname} acessível",
                    "status": "FAIL",  # falha, pois arquivo está exposto
                    "evidence": f"HTTP {code}",
                    "category": "Coleta de Informações",
                    "suggestion": f"Remova ou restrinja acesso a {fname} se contiver informações sensíveis"
                })
            elif code == "404":
                items.append({
                    "item": f"{fname} inexistente",
                    "status": "PASS",
                    "evidence": "HTTP 404",
                    "category": "Coleta de Informações",
                    "suggestion": f"Mantenha {fname} ausente caso não seja necessário"
                })
            else:
                items.append({
                    "item": f"{fname} resposta inesperada",
                    "status": "WARN",
                    "evidence": f"HTTP {code}",
                    "category": "Coleta de Informações",
                    "suggestion": f"Verifique configuração de {fname}, resposta {code}"
                })
        return items

    def _compute_severity(self, checklists):
        # Se algum arquivo exposto => MEDIUM
        for c in checklists:
            if c["status"] == "FAIL":
                return "medium"
        return "info"
