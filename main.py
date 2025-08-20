import os
import importlib
from analysis import analisar

# 🎯 Alvo de teste
TARGET = "http://testphp.vulnweb.com/"

# 📦 Lista de plugins a executar
PLUGINS = [
    "plugins.curl_headers",
    "plugins.curl_files",
    "plugins.nmap_services",
    "plugins.nmap_http_methods",
    "plugins.dig_dns",
    "plugins.sslscan",
    "plugins.whatweb",
    "plugins.wafw00f",
    "plugins.nikto",
    "plugins.gobuster",
    "plugins.theHarvester",
    "plugins.sublist3r",
    "plugins.dnsrecon",
    "plugins.testssl",
]


if __name__ == "__main__":
    tests = {}

    # Executa cada plugin
    for plugin_path in PLUGINS:
        print(f"[+] Executando {plugin_path}...")
        try:
            plugin = importlib.import_module(plugin_path)
            tests[plugin_path] = plugin.run(TARGET)
        except Exception as e:
            tests[plugin_path] = f"[ERRO PLUGIN] {str(e)}"

    # Gera análise (API ou local)
    analise = analisar(tests, TARGET)

    # Salva relatório
    os.makedirs("results", exist_ok=True)
    with open("results/relatorio.txt", "w", encoding="utf-8") as f:
        f.write(analise)

    print("[+] Relatório salvo em results/relatorio.txt")
