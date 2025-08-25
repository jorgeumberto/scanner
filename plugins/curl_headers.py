from utils import BasePlugin, run_cmd

class CurlHeaders(BasePlugin):
    """Obtém cabeçalhos HTTP com curl -I"""

    description = "Obtém e analisa os cabeçalhos HTTP retornados pelo servidor web do alvo."

    def run(self, target: str, cfg: dict) -> str:
        return run_cmd(["curl", "-i", "-I", target])

    def parse_output(self, raw: str) -> dict:
        parsed = {}
        for line in raw.splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                parsed[k.strip()] = v.strip()
            elif line.startswith("HTTP/"):
                parsed["Status-Line"] = line.strip()
        return parsed

    def summarize_output(self, parsed: dict, raw: str) -> str:
        status = parsed.get("Status-Line", "N/A")
        server = parsed.get("Server", "N/A")
        return f"{status}, Server={server}"
