from utils import BasePlugin, run_cmd, extrair_host

class Dig(BasePlugin):
    description = "Consulta DNS do alvo (A/AAAA/MX/TXT)"
    checklist   = "Executar pesquisa de DNS"
    category    = "Coleta de Informações"
    tags        = ["dns", "dig", "recon"]

    def run(self, target: str, cfg: dict) -> str:
        host = extrair_host(target)
        if not host:
            return ""
        parts = []
        for rr in ["A", "AAAA", "MX", "TXT"]:
            out = run_cmd(["dig", "+short", host, rr], timeout=cfg.get("timeout", 10))
            parts.append(f";; {rr}\n{out.strip()}")
        return "\n".join(parts)

    def parse_output(self, raw: str) -> dict:
        parsed = {"A": [], "AAAA": [], "MX": [], "TXT": []}
        current = None
        for line in raw.splitlines():
            if line.startswith(";; "):
                current = line.replace(";;", "").strip()
                continue
            if not line.strip():
                continue
            if current in parsed:
                parsed[current].append(line.strip())
        return parsed

    def build_checklists(self, parsed: dict) -> list:
        items = []

        # A/AAAA
        a_ok = bool(parsed.get("A"))
        items.append({
            "item": "Registro A (IPv4) presente",
            "status": "PASS" if a_ok else "FAIL",
            "evidence": ", ".join(parsed.get("A", [])) or None,
            "category": "Coleta de Informações",
            "suggestion": "Configure registro A apontando para o IP público correto"
        })

        aaaa_ok = bool(parsed.get("AAAA"))
        items.append({
            "item": "Registro AAAA (IPv6) presente",
            "status": "PASS" if aaaa_ok else "WARN",
            "evidence": ", ".join(parsed.get("AAAA", [])) or None,
            "category": "Coleta de Informações",
            "suggestion": "Adicione registro AAAA se suportar IPv6, ou mantenha apenas IPv4"
        })

        # MX/TXT (SPF/DMARC) — útil para 'Outros Testes Comuns'
        mx = parsed.get("MX", [])
        items.append({
            "item": "Registro MX configurado",
            "status": "PASS" if mx else "WARN",
            "evidence": ", ".join(mx) or None,
            "category": "Outros Testes Comuns",
            "suggestion": "Configure MX adequado se o domínio enviar/receber e-mails"
        })

        txt = parsed.get("TXT", [])
        spf = next((t for t in txt if "v=spf1" in t.lower()), None)
        dmarc = next((t for t in txt if "v=dmarc1" in t.lower()), None)
        items.append({
            "item": "SPF configurado (TXT v=spf1)",
            "status": "PASS" if spf else "WARN",
            "evidence": spf,
            "category": "Outros Testes Comuns",
            "suggestion": "Publique TXT com 'v=spf1' restringindo origens de envio"
        })
        items.append({
            "item": "DMARC configurado (TXT v=DMARC1)",
            "status": "PASS" if dmarc else "WARN",
            "evidence": dmarc,
            "category": "Outros Testes Comuns",
            "suggestion": "Publique TXT com 'v=DMARC1; p=reject/quarantine' alinhado ao SPF/DKIM"
        })

        return items

    def _compute_severity(self, checklists):
        # Falha em A => MEDIUM; restante WARN/INFO
        for c in checklists:
            if c["item"] == "Registro A (IPv4) presente" and c["status"] == "FAIL":
                return "medium"
        return "info"
