import os
import importlib
import json
from analysis import analisar

# 🎯 Configurações globais
TARGET = "psdatab.com.br"   # alvo principal
OUTPUT_PATH = "results/"
SAVE_INDIVIDUAL = False          # salva relatórios separados por plugin?

# Lista de plugins a executar
PLUGINS = [
    "plugins.curl_headers",
    "plugins.curl_files"
]


def carregar_config(plugin_name: str) -> dict:
    """Carrega config JSON de um plugin, se existir."""
    cfg_file = os.path.join("configs", plugin_name.split(".")[-1] + ".json")
    if os.path.exists(cfg_file):
        with open(cfg_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

if __name__ == "__main__":
    os.makedirs(OUTPUT_PATH, exist_ok=True)
    tests = {}

    for plugin_path in PLUGINS:
        print(f"[+] Executando {plugin_path}...")
        try:
            plugin = importlib.import_module(plugin_path)
            cfg = carregar_config(plugin_path)

            # verifica se está habilitado (default = True)
            if cfg.get("enabled", True) is False:
                tests[plugin_path] = "[SKIPPED] Plugin desativado no config"
                continue

            if hasattr(plugin, "run"):
                tests[plugin_path] = plugin.run(TARGET, cfg)
            else:
                tests[plugin_path] = "[ERRO] Plugin não possui função run()"

            # salva saída individual (se habilitado)
            if SAVE_INDIVIDUAL:
                fname = plugin_path.split(".")[-1] + ".txt"
                with open(os.path.join(OUTPUT_PATH, fname), "w", encoding="utf-8") as f:
                    f.write(tests[plugin_path])

        except Exception as e:
            tests[plugin_path] = f"[ERRO PLUGIN] {str(e)}"

    # Gera relatório consolidado
    analise = analisar(tests, TARGET)

    with open(os.path.join(OUTPUT_PATH, "relatorio.txt"), "w", encoding="utf-8") as f:
        f.write(analise)

    print("[+] Relatório consolidado salvo em results/relatorio.txt")
