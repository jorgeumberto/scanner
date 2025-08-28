import os
from typing import Dict, Any, List

API_KEY = os.getenv("API_KEY", "your-team-api-key")

def to_controller_payload(your_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converte do seu JSON:
      {cliente_api, name, target, description, finding_count, analysis, duration, scan_results: [...]}
    para o formato atual do Controller:
      {"results": [ { api_key, scan_name, scan_description, target, status, finding_count, analysis, duration, scan_results: [ ... ] } ]}
    """
    scan_results_input = your_json.get("scan_results", [])

    # Achados totais = somar FAILs/medium/high, etc. Aqui usamos o tamanho total mesmo.
    finding_count = your_json.get("finding_count")
    if finding_count is None:
        count = 0
        for pr in scan_results_input:
            items = pr.get("result", [])
            count += len(items)
        finding_count = count

    # Monta o array esperado pelo Controller
    controller_scan = {
        "api_key": your_json.get("cliente_api") or API_KEY,
        "scan_name": your_json.get("name") or "Scan Automático",
        "scan_description": your_json.get("description"),
        "target": your_json.get("target"),
        "status": "completed",
        "finding_count": finding_count,
        "analysis": your_json.get("analysis"),
        "duration": str(your_json.get("duration", "")),
        "scan_results": []
    }

    # Flatten de cada plugin → para itens do scan_results
    for pr in scan_results_input:
        plugin_name = pr.get("plugin")
        for it in pr.get("result", []):
            controller_scan["scan_results"].append({
                # Campos que seu Controller atual entende:
                "scan_item_id": None,                 # você pode resolver por UUID no backend depois
                "scan_id": None,                      # será preenchido pelo backend após criar o scan
                "result": it.get("result"),
                "analisys": it.get("analysis_ai"),
                "duration": str(it.get("duration")),
                "severity": it.get("severity"),
                "item": plugin_name,                  # ou o nome real do item, se preferir
                "status": "completed",
                "evidence": None,
                # Extras úteis para futura resolução:
                "scan_item_uuid": it.get("scan_item_uuid"),
                "plugin": plugin_name,
                "auto": "Y" if it.get("auto") else "N",
            })

    return {"results": [controller_scan]}
