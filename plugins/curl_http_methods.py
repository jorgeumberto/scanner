# plugins/curl_http_methods.py
from utils import run_cmd, Timer
from typing import Dict, Any, List

# UUIDs placeholders – troque pelos reais (22 e 23)
UUIDS = {
    22: "uuid-022",  # Métodos HTTP informados (OPTIONS/Allow)
    23: "uuid-023",  # Métodos inseguros desabilitados
}

DANGEROUS = {"PUT", "DELETE", "TRACE", "CONNECT"}

def run_plugin(target: str, ai_fn):
    items: List[Dict[str, Any]] = []
    with Timer() as t:
        raw = run_cmd(["curl", "-sSI", "-X", "OPTIONS", target], timeout=20)

    # extrai Allow:
    allow = ""
    for line in raw.splitlines():
        if line.lower().startswith("allow:"):
            allow = line.split(":", 1)[1].strip()
            break

    # 22) Allow
    uuid22 = UUIDS[22]
    res22 = f"Allow: {allow}" if allow else "Allow ausente"
    items.append({
        "plugin_uuid": uuid22,
        "scan_item_uuid": uuid22,
        "result": res22,
        "analysis_ai": ai_fn("CurlHttpMethods", uuid22, res22),
        "severity": "info" if allow else "low",
        "duration": t.duration,
        "auto": True
    })

    # 23) inseguros desabilitados
    allowed = [m.strip().upper() for m in allow.split(",")] if allow else []
    found_danger = sorted(set(allowed).intersection(DANGEROUS))
    uuid23 = UUIDS[23]
    if found_danger:
        res23 = "Métodos perigosos permitidos: " + ", ".join(found_danger)
        sev23 = "high"
    else:
        res23 = "Nenhum método perigoso permitido"
        sev23 = "info" if allow else "low"
    items.append({
        "plugin_uuid": uuid23,
        "scan_item_uuid": uuid23,
        "result": res23,
        "analysis_ai": ai_fn("CurlHttpMethods", uuid23, res23),
        "severity": sev23,
        "duration": t.duration,
        "auto": True
    })

    return {"plugin": "CurlHttpMethods", "result": items}
