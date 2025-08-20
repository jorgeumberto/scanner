import json
import os
from dotenv import load_dotenv

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

USE_API = False  # <<--- True = usa ChatGPT/Grok, False = análise local fake

def analisar_com_api(tests, target):
    """Usa ChatGPT/Grok (pago)."""
    from openai import OpenAI
    client = OpenAI(api_key=OPENAI_API_KEY)

    prompt = f"""
    Você é um analista de segurança.
    Alvo: {target}
    Resultados dos testes:
    {json.dumps(tests, indent=2, ensure_ascii=False)}

    Gere um relatório em português, com:
    - Vulnerabilidades potenciais
    - Riscos
    - Recomendações
    """

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )
    return resp.choices[0].message.content

def analisar_local(tests, target):
    """Relatório local (sem gastar créditos)."""
    relatorio = [f"# Relatório de Segurança - {target}\n"]
    for k, v in tests.items():
        relatorio.append(f"## {k}\n")
        relatorio.append(f"Saída:\n```\n{v[:600]}...\n```\n")
        if "nmap" in k:
            relatorio.append("- Possível exposição de portas/serviços.\n")
        elif "curl_headers" in k:
            relatorio.append("- Verificação de cabeçalhos HTTP.\n")
        elif "curl_files" in k:
            relatorio.append("- Verificação de arquivos públicos (robots.txt, sitemap, etc).\n")
        elif "dig" in k:
            relatorio.append("- Informações de DNS coletadas.\n")
        elif "sslscan" in k:
            relatorio.append("- Teste de protocolos e cifras SSL/TLS.\n")
    relatorio.append("\n## Recomendações Gerais\n- Restringir serviços expostos\n- Configurar cabeçalhos de segurança\n- Monitorar certificados e CORS\n")
    return "\n".join(relatorio)

def analisar(tests, target):
    return analisar_com_api(tests, target) if USE_API else analisar_local(tests, target)
