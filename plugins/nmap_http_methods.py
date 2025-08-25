from utils import BasePlugin, run_cmd, extrair_host

class NmapHttpMethods(BasePlugin):
    """Verifica métodos HTTP aceitos pelo servidor"""

    def run(self, target: str, cfg: dict) -> str:
        host = extrair_host(target)
        return run_cmd([
            "nmap", "-p", "80,443", "--script", "http-methods", "-Pn", host
        ])

    def parse_output(self, raw: str) -> dict:
        parsed = {"ports": {}}
        lines = raw.splitlines()
        current_port = None

        for line in lines:
            if "/" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 2:
                    current_port = parts[0]
                    parsed["ports"][current_port] = {"methods": []}
            elif current_port and "Allowed methods:" in line:
                methods = line.split(":", 1)[1].strip().split()
                parsed["ports"][current_port]["methods"] = methods

        return parsed

    def summarize_output(self, parsed: dict, raw: str) -> str:
        resumo = []
        for port, info in parsed.get("ports", {}).items():
            if info["methods"]:
                resumo.append(f"{port}: {', '.join(info['methods'])}")
        return "; ".join(resumo) if resumo else "Nenhum método identificado"
