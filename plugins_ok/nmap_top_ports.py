from utils import BasePlugin, run_cmd, extrair_host

class NmapTopPorts(BasePlugin):
    """Escaneia as 1000 portas TCP mais comuns"""

    def run(self, target: str, cfg: dict) -> str:
        host = extrair_host(target)
        return run_cmd(["nmap", "--top-ports", "1000", "-Pn", host])

    def parse_output(self, raw: str) -> dict:
        parsed = {}
        lines = raw.splitlines()

        for line in lines:
            if "/" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2]
                    parsed[port] = {"state": state, "service": service}

        return parsed

    def summarize_output(self, parsed: dict, raw: str) -> str:
        if parsed:
            return ", ".join([f"{port}:{info['service']}" for port, info in parsed.items()])
        return "Nenhuma porta aberta encontrada"
