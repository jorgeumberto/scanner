from dotenv import load_dotenv
import importlib
import json
import os
from openai import OpenAI  # pip install openai

load_dotenv()

# === Configuração ===
target = "https://psdatab.com.br"
plugins = ["curl_headers", "nmap_top_ports", "dig"]

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("A variável OPENAI_API_KEY não está definida")

client = OpenAI(api_key=api_key)

# === Executar plugins ===
tests = {}
for plugin_name in plugins:
    try:
        print(f"[+] Executando plugin: {plugin_name}")
        module = importlib.import_module(f"plugins.{plugin_name}")
        tests[plugin_name] = module.run(target)
    except Exception as e:
        tests[plugin_name] = f"Erro ao executar plugin: {str(e)}"

# === Enviar resultados para ChatGPT gerar relatório ===
prompt = f"""
Você é um analista de segurança cibernética. 
Recebeu os resultados de testes automatizados contra o alvo: {target}.

Resultados dos testes:
{json.dumps(tests, indent=2)}

Com base nesses dados:
1. Explique de forma clara e organizada o que foi encontrado.
2. Destaque riscos e vulnerabilidades potenciais.
3. Recomende ações de mitigação.
4. Estruture como um relatório técnico para auditoria, em português.

Formato do relatório:
# Relatório de Segurança - {target}

## Sumário
[resumo aqui]

## Resultados dos Testes
[interpretação dos outputs]

## Vulnerabilidades Potenciais
[listagem]

## Recomendações
[sugestões]

"""

try:
    response = client.chat.completions.create(
        model="gpt-4.1",  # pode usar "gpt-4.1" também
        messages=[
            {"role": "system", "content": "Você é um especialista em segurança cibernética."},
            {"role": "user", "content": prompt}
        ],
        temperature=0
    )
    relatorio = response.choices[0].message.content

    with open("relatorio.txt", "w", encoding="utf-8") as f:
        f.write(relatorio)

    print("[+] Relatório salvo em relatorio.txt")

except Exception as e:
    print(f"[!] Erro ao gerar relatório: {e}")
