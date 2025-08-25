from utils import BasePlugin, run_cmd

class CurlFiles(BasePlugin):
    """Verifica arquivos comuns (robots.txt, sitemap.xml)"""

    description = "Verifica a existência de arquivos comuns como robots.txt e sitemap.xml no servidor web do alvo."

    def run(self, target: str, cfg: dict) -> str:
        resultados = []
        for path in ["/robots.txt", "/sitemap.xml"]:
            status = run_cmd([
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}", f"{target}{path}"
            ])
            resultados.append(f"{path}:{status}")
        return "\n".join(resultados)

    def parse_output(self, raw: str) -> dict:
        parsed = {}
        for line in raw.splitlines():
            if ":" in line:
                path, status = line.split(":", 1)
                parsed[path.strip()] = status.strip()
        return parsed

    def summarize_output(self, parsed: dict, raw: str) -> str:
        return ", ".join([f"{k}={v}" for k, v in parsed.items()])
