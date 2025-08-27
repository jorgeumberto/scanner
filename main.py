import importlib
import json
import os
from urllib.parse import urlparse
from datetime import datetime
from api_client import enviar_resultados

# 🔹 Configurações principais
TARGET = "http://testphp.vulnweb.com"
CONFIG_DIR = "configs"
PLUGINS_DIR = "plugins_ok"
RESULTS_DIR = "results"

# 🔹 Ativar/desativar análise com ChatGPT
USE_CHATGPT = False   # Troque para True quando quiser usar a API
OPENAI_KEY = ""

# Se for usar ChatGPT
if USE_CHATGPT:
    from openai import OpenAI
    client = OpenAI(api_key=OPENAI_KEY)

    def analisar_com_chatgpt(resultado_plugin: dict) -> str:
        """Envia resultado de um plugin para análise automática"""
        prompt = f"""
        Você é um analista de segurança. Analise o seguinte resultado:

        {json.dumps(resultado_plugin, indent=2)}

        Responda de forma clara, destacando possíveis riscos ou confirmando se não há evidências relevantes.
        """

        resp = client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300
        )

        return resp.choices[0].message.content

def load_config(plugin_name: str) -> dict:
    """Carrega config JSON se existir"""
    cfg_path = os.path.join(CONFIG_DIR, f"{plugin_name}.json")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r") as f:
            return json.load(f)
    return {}

def main():
    tests = {}

    for plugin_file in os.listdir(PLUGINS_DIR):
        if not plugin_file.endswith(".py") or plugin_file.startswith("__"):
            continue

        plugin_name = plugin_file[:-3]
        plugin_path = f"{PLUGINS_DIR}.{plugin_name}"

        try:
            module = importlib.import_module(plugin_path)

            # 🔹 procura classe que herda BasePlugin
            plugin_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and "BasePlugin" in [b.__name__ for b in attr.__bases__]:
                    plugin_class = attr
                    break

            if not plugin_class:
                print(f"[AVISO] {plugin_name} não possui classe de plugin")
                continue

            cfg = load_config(plugin_name)
            plugin_obj = plugin_class()
            result = plugin_obj.execute(TARGET, cfg)

            # 🔹 opcional: análise com ChatGPT
            if USE_CHATGPT:
                try:
                    result["analysis"] = analisar_com_chatgpt(result)
                    print(f"[AI] {plugin_name} analisado com ChatGPT")
                except Exception as e:
                    result["analysis"] = f"Erro na análise: {str(e)}"

            tests[plugin_name] = result
            print(f"[OK] {plugin_name} executado")

        except Exception as e:
            tests[plugin_name] = {
                "plugin": plugin_name,
                "target": TARGET,
                "raw": "",
                "parsed": {},
                "summary": f"Erro: {str(e)}",
                "analysis": None
            }
            print(f"[ERRO] {plugin_name}: {e}")

    # 🔹 cria estrutura results/YYYY-MM-DD/host/
    hoje = datetime.now().strftime("%Y-%m-%d")
    host = urlparse(TARGET).hostname or TARGET
    results_path = os.path.join(RESULTS_DIR, hoje, host)
    os.makedirs(results_path, exist_ok=True)

    # JSON estruturado completo
    json_path = os.path.join(results_path, "tests_raw.json")
    with open(json_path, "w") as f:
        json.dump(tests, f, indent=2)

    # Relatório em JSON só com resumo
    summary_data = {k: v["summary"] for k, v in tests.items()}
    summary_path = os.path.join(results_path, "relatorio.json")
    with open(summary_path, "w") as f:
        json.dump(summary_data, f, indent=2)

    print(f"\n[+] Resultados salvos em {results_path}")

    # opcional: enviar para API
    resposta_api = enviar_resultados(json_path)
    print("[API]", resposta_api)
        
if __name__ == "__main__":
    main()
