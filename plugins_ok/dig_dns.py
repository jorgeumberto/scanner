from utils import BasePlugin, run_cmd, extrair_host

class Dig(BasePlugin):
    """Consulta DNS usando dig"""

    def run(self, target: str, cfg: dict) -> str:
        host = extrair_host(target)
        return run_cmd(["dig", "+short", host])

    def parse_output(self, raw: str) -> dict:
        parsed = {}
        ips = [line.strip() for line in raw.splitlines() if line.strip()]
        if ips:
            parsed["A"] = ips
        return parsed

    def summarize_output(self, parsed: dict, raw: str) -> str:
        if "A" in parsed:
            return f"IPs encontrados: {', '.join(parsed['A'])}"
        return "Nenhum registro A encontrado"
