import os
import json
from datetime import datetime
from utils import Timer
from ai_analyzer import analyze_item
from api_adapter import to_controller_payload
from api_client import post_results

# ===== CONFIG =====
TARGET   = os.getenv("TARGET", "http://testphp.vulnweb.com")
API_KEY  = os.getenv("API_KEY", "your-team-api-key")

# ===== IMPORTA PLUGINS =====
from plugins.curl_headers import run_plugin as run_curl_headers

def ai_wrapper(plugin_name: str, item_uuid: str, result_text: str) -> str:
    # Encapsula a chamada — facilita trocar provedor sem tocar plugins
    return analyze_item(TARGET, plugin_name, item_uuid, result_text)

def main():
    print("[+] Iniciando Scan Automático")
    with Timer() as t_scan:
        # Execute os plugins desejados:
        plugins_output = []

        # CurlHeaders
        ph = run_curl_headers(TARGET, ai_wrapper)
        plugins_output.append(ph)

        # aqui você adiciona mais:
        # from plugins.curl_files import run_plugin as run_curl_files
        # plugins_output.append(run_curl_files(TARGET, ai_wrapper))
        # ...

    # Monta SEU JSON final
    my_json = {
        "cliente_api": API_KEY,
        "name": "Scan Automático",
        "target": TARGET,
        "description": "Scan automático via API",
        "finding_count": sum(len(p["result"]) for p in plugins_output),
        "analysis": None,
        "duration": t_scan.duration,
        "scan_results": plugins_output
    }

    # Salva no disco (útil para auditoria)
    outdir = "results"
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path_my = os.path.join(outdir, f"scan_myjson_{stamp}.json")
    with open(path_my, "w") as f:
        json.dump(my_json, f, indent=2, ensure_ascii=False)
    print(f"[+] Seu JSON salvo em: {path_my}")

    # Adapta para o formato do Controller atual
    controller_payload = to_controller_payload(my_json)
    path_api = os.path.join(outdir, f"scan_controller_payload_{stamp}.json")
    with open(path_api, "w") as f:
        json.dump(controller_payload, f, indent=2, ensure_ascii=False)
    print(f"[+] Payload da API salvo em: {path_api}")

    # Envia
    api_resp = post_results(controller_payload)
    print("[API]", api_resp)

if __name__ == "__main__":
    main()
