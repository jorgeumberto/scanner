from utils import BasePlugin, run_cmd, extrair_host

class CurlHeaders(BasePlugin):
    """Obtém cabeçalhos HTTP de um alvo usando curl"""

    description = "Verifica cabeçalhos HTTP do alvo"
    category = "web"
    tags = ["curl", "headers", "http"]

    def run(self, target: str, cfg: dict) -> str:
        host = extrair_host(target)
        if not host:
            return ""
        return run_cmd(["curl", "-I", target])

def parse_output(self, raw: str) -> dict:
    headers = {}
    for line in raw.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers

def summarize_output(self, parsed: dict, raw: str) -> str:
    if not parsed:
        return "Nenhum cabeçalho encontrado"

    findings = []
    severity_score = 0  # soma para calcular severidade

    # --- Informações de servidor
    if "Server" in parsed:
        findings.append(f"Server: {parsed['Server']} (exposto)")
        severity_score += 1
    if "X-Powered-By" in parsed:
        findings.append(f"Powered by: {parsed['X-Powered-By']} (exposto)")
        severity_score += 1

    # --- Cabeçalhos de segurança
    if "Strict-Transport-Security" not in parsed:
        findings.append("⚠️ Sem HSTS")
        severity_score += 2
    if "X-Frame-Options" not in parsed:
        findings.append("⚠️ Sem proteção contra clickjacking")
        severity_score += 2
    if "X-Content-Type-Options" not in parsed:
        findings.append("⚠️ Sem proteção contra MIME-sniffing")
        severity_score += 2
    if "Content-Security-Policy" not in parsed:
        findings.append("⚠️ Sem CSP (alto risco de XSS)")
        severity_score += 3

    if "Access-Control-Allow-Origin" in parsed:
        if parsed["Access-Control-Allow-Origin"] == "*":
            findings.append("⚠️ CORS aberto (alto risco)")
            severity_score += 3
        else:
            findings.append(f"CORS: {parsed['Access-Control-Allow-Origin']}")

    # --- Determinar severidade final
    if severity_score >= 6:
        severity = "high"
    elif severity_score >= 3:
        severity = "medium"
    elif severity_score >= 1:
        severity = "low"
    else:
        severity = "info"

    # armazenar no objeto para o BasePlugin usar
    self._severity = severity
    self._finding_count = len(findings)

    return ", ".join(findings)

