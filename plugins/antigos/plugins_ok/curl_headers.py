from utils import BasePlugin, run_cmd
from datetime import datetime

def _ensure_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]

class CurlHeaders(BasePlugin):
    """
    Analisa cabeçalhos HTTP com curl e gera CHECKLISTS (PASS/FAIL/WARN).
    Checklist principal: "Verificar cabeçalhos HTTP do alvo"
    """

    description = "Analisa cabeçalhos HTTP do alvo"
    tags        = ["curl", "headers", "http", "security-headers"]

    def run(self, target: str, cfg: dict) -> str:
        """
        -sS  : silencioso mas exibe erros (stderr); run_cmd normalmente retorna stdout
        -I   : HEAD (apenas cabeçalhos)
        -L   : segue redirecionamentos
        -k   : opcional (ignora TLS), via configs/curl_headers.json: {"insecure": true}
        """
        args = ["curl", "-sS", "-I", "-L"]
        if cfg.get("insecure", False):
            args.append("-k")
        extra = cfg.get("extra_args", [])
        if isinstance(extra, list):
            args += extra
        args.append(target)
        return run_cmd(args)

    def parse_output(self, raw: str) -> dict:
        """
        Normaliza header-names em minúsculas.
        Consolida duplicados como lista (ex.: set-cookie).
        Guarda status-lines em _status (lista).
        """
        headers = {}
        status_lines = []
        for line in raw.splitlines():
            line = line.rstrip("\r")
            if not line:
                continue
            if line.startswith("HTTP/"):
                status_lines.append(line)
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                key = k.strip().lower()
                val = v.strip()
                if key in headers:
                    # consolidar duplicados (ex.: set-cookie)
                    if isinstance(headers[key], list):
                        headers[key].append(val)
                    else:
                        headers[key] = [headers[key], val]
                else:
                    headers[key] = val
        if status_lines:
            headers["_status"] = status_lines
        return headers

    def build_checklists(self, headers: dict) -> list:
        """
        Gera sub-checklists categorizados conforme o Relatório de Evidências,
        cada item com 'suggestion' técnico para correção.
        """
        items = []

        # Se nada foi parseado
        if not headers:
            items.append({
                "item": "Cabeçalhos recebidos",
                "status": "FAIL",
                "evidence": "Sem saída (curl -I)",
                "category": "Coleta de Informações",
                "suggestion": "Verifique se o host está acessível e responda com cabeçalhos HTTP válidos"
            })
            return items

        def ev(v):
            if v is None:
                return None
            return ", ".join(v) if isinstance(v, list) else v

        # ---------------------------
        # Coleta de Informações
        # ---------------------------
        server = headers.get("server")
        items.append({
            "item": "Server exposto",
            "status": "FAIL" if server else "PASS",
            "evidence": ev(server),
            "category": "Coleta de Informações",
            "suggestion": "Remova ou minimize o banner 'Server' (ex.: server_tokens off no Nginx, ServerSignature Off no Apache)"
        })

        xpb = headers.get("x-powered-by")
        items.append({
            "item": "X-Powered-By exposto",
            "status": "FAIL" if xpb else "PASS",
            "evidence": ev(xpb),
            "category": "Coleta de Informações",
            "suggestion": "Remova o cabeçalho 'X-Powered-By' para não expor a tecnologia (ex.: PHP remove_header, ASP.NET web.config)"
        })

        # ---------------------------
        # Configuração e Implantação
        # ---------------------------
        hsts = headers.get("strict-transport-security")
        items.append({
            "item": "Strict-Transport-Security presente",
            "status": "PASS" if hsts else "FAIL",
            "evidence": ev(hsts),
            "category": "Configuração e Implantação",
            "suggestion": "Adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains' para forçar HTTPS (HSTS)"
        })

        xcto = headers.get("x-content-type-options")
        items.append({
            "item": "X-Content-Type-Options presente",
            "status": "PASS" if xcto else "FAIL",
            "evidence": ev(xcto),
            "category": "Configuração e Implantação",
            "suggestion": "Inclua 'X-Content-Type-Options: nosniff' para evitar detecção incorreta de MIME"
        })

        # ---------------------------
        # Testes do Lado do Cliente
        # ---------------------------
        xfo = headers.get("x-frame-options")
        items.append({
            "item": "X-Frame-Options presente",
            "status": "PASS" if xfo else "FAIL",
            "evidence": ev(xfo),
            "category": "Testes do Lado do Cliente",
            "suggestion": "Inclua 'X-Frame-Options: DENY' ou 'SAMEORIGIN' para evitar clickjacking"
        })

        csp = headers.get("content-security-policy")
        items.append({
            "item": "Content-Security-Policy presente",
            "status": "PASS" if csp else "FAIL",
            "evidence": ev(csp),
            "category": "Testes do Lado do Cliente",
            "suggestion": "Defina 'Content-Security-Policy' para restringir scripts, previnir XSS e controlar origens confiáveis"
        })

        acao = headers.get("access-control-allow-origin")
        acao_val = acao[0] if isinstance(acao, list) else acao
        if acao_val is None:
            items.append({
                "item": "CORS configurado corretamente",
                "status": "WARN",
                "evidence": None,
                "category": "Testes do Lado do Cliente",
                "suggestion": "Adicione 'Access-Control-Allow-Origin' apenas se necessário, restrito a domínios confiáveis"
            })
        elif str(acao_val).strip() == "*":
            items.append({
                "item": "CORS configurado corretamente",
                "status": "FAIL",
                "evidence": acao_val,
                "category": "Testes do Lado do Cliente",
                "suggestion": "Evite usar '*' em CORS, restrinja a domínios confiáveis"
            })
        else:
            items.append({
                "item": "CORS configurado corretamente",
                "status": "PASS",
                "evidence": acao_val,
                "category": "Testes do Lado do Cliente",
                "suggestion": "Valide que somente domínios confiáveis estejam listados no CORS"
            })

        # ---------------------------
        # Gerenciamento de Sessão
        # ---------------------------
        sc = headers.get("set-cookie")
        sc_list = sc if isinstance(sc, list) else ([sc] if isinstance(sc, str) else [])
        if sc_list:
            joined = " | ".join(sc_list)[:800]
            secure_ok   = all("secure" in s.lower() for s in sc_list)
            httponly_ok = all("httponly" in s.lower() for s in sc_list)
            samesite_ok = all("samesite" in s.lower() for s in sc_list)

            items.append({
                "item": "Cookies com flag Secure",
                "status": "PASS" if secure_ok else "FAIL",
                "evidence": joined,
                "category": "Gerenciamento de Sessão",
                "suggestion": "Adicione a flag 'Secure' nos cookies para que só sejam transmitidos via HTTPS"
            })
            items.append({
                "item": "Cookies com flag HttpOnly",
                "status": "PASS" if httponly_ok else "FAIL",
                "evidence": joined,
                "category": "Gerenciamento de Sessão",
                "suggestion": "Adicione a flag 'HttpOnly' nos cookies para evitar acesso via JavaScript"
            })
            items.append({
                "item": "Cookies com atributo SameSite",
                "status": "PASS" if samesite_ok else "WARN",
                "evidence": joined,
                "category": "Gerenciamento de Sessão",
                "suggestion": "Adicione 'SameSite=Strict' ou 'Lax' para mitigar ataques de CSRF"
            })
        else:
            items.append({
                "item": "Cookies presentes",
                "status": "WARN",
                "evidence": "Nenhum Set-Cookie nos headers de resposta",
                "category": "Gerenciamento de Sessão",
                "suggestion": "Se a aplicação usa autenticação, configure cookies com Secure, HttpOnly e SameSite"
            })

        return items


    # Severidade custom para este plugin
    def _compute_severity(self, checklists: list) -> str:
        fails = {c["item"]: c for c in checklists if c["status"] == "FAIL"}

        # Alto risco: CSP ausente ou CORS '*'
        if "Content-Security-Policy presente" in fails:
            return "high"
        cors = next((c for c in checklists if c["item"] == "CORS configurado corretamente"), None)
        if cors and cors["status"] == "FAIL" and (cors.get("evidence") == "*"):
            return "high"

        # Médio: HSTS/XFO/XCTO ausentes
        medium_keys = {
            "Strict-Transport-Security presente",
            "X-Frame-Options presente",
            "X-Content-Type-Options presente"
        }
        if any(k in fails for k in medium_keys):
            return "medium"

        # Baixo: somente exposição de banner/tecnologia
        if any(k in fails for k in ["Server exposto", "X-Powered-By exposto"]):
            return "low"

        return "info"
