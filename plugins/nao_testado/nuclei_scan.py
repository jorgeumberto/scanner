# plugins/nuclei_scan.py
import json
import tempfile
from utils import run_cmd, Timer
from typing import Dict, Any, List

# UUIDs placeholders — troque pelos reais dos respectivos IDs
UUIDS = {
    35: "uuid-035",  # Open Redirect
    52: "uuid-052",  # XXE
    53: "uuid-053",  # OS Command Injection
    54: "uuid-054",  # SSTI
    55: "uuid-055",  # LFI/RFI/Traversal
    56: "uuid-056",  # SSRF
    57: "uuid-057",  # Deserialização insegura
    60: "uuid-060",  # Credenciais padrão
    61: "uuid-061",  # Enumeração de usuários
    68: "uuid-068",  # IDOR
    72: "uuid-072",  # Debug/stack traces/erros detalhados (parte 1)
    74: "uuid-074"   # Debug/stack traces/erros detalhados (parte 2)
}

# Mapa: nome lógico -> (tags nuclei, id_relatorio, severidade se achou)
GROUPS = [
    ("open_redirect",       ["open-redirect"],            35, "medium"),
    ("xxe",                 ["xxe"],                      52, "high"),
    ("os_cmd_injection",    ["os-cmd-injection","cmdi"],  53, "high"),
    ("ssti",                ["ssti"],                     54, "high"),
    ("lfi_rfi_traversal",   ["lfi","rfi","traversal"],    55, "high"),
    ("ssrf",                ["ssrf"],                     56, "high"),
    ("deserialization",     ["deserialization"],          57, "high"),
    ("default_creds",       ["default-login"],            60, "medium"),
    ("user_enum",           ["user-enum"],                61, "medium"),
    ("idor",                ["idor"],                     68, "high"),
    ("debug_error_leak1",   ["debug"],                    72, "low"),
    ("debug_error_leak2",   ["error","stack-trace"],      74, "low")
]

def _run_nuclei_jsonl(target: str, tags: List[str], timeout: int, rate_limit: int, concurrency: int) -> List[Dict[str, Any]]:
    """
    Executa nuclei com -jsonl e retorna lista de findings (cada linha JSON → dict)
    """
    # Constrói comando
    cmd = [
        "nuclei",
        "-u", target,
        "-t", "http",            # escopo http
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-jsonl"
    ]
    for tg in tags:
        cmd += ["-tags", tg]

    # Executa
    out = run_cmd(cmd, timeout=timeout)
    findings: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            # ignora linhas não-JSON
            pass
    return findings

def _summarize_findings(findings: List[Dict[str, Any]], max_lines: int = 5) -> str:
    """
    Retorna um resumo compacto das evidências.
    """
    if not findings:
        return "Nenhum achado"
    lines = []
    for f in findings[:max_lines]:
        tpl = f.get("template", "")
        name = f.get("info", {}).get("name", "")
        sev  = f.get("info", {}).get("severity", "")
        url  = f.get("matched-at", "")
        lines.append(f"- {name} [{sev}] ({tpl}) -> {url}")
    extra = len(findings) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} achados")
    return "\n".join(lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional):
      { "timeout": 600, "rate_limit": 50, "concurrency": 10 }
    """
    if cfg is None:
        cfg = {}
    timeout     = int(cfg.get("timeout", 600))
    rate_limit  = int(cfg.get("rate_limit", 50))
    concurrency = int(cfg.get("concurrency", 10))

    items: List[Dict[str, Any]] = []

    for group_name, tags, evid_id, sev_if_found in GROUPS:
        with Timer() as t:
            findings = _run_nuclei_jsonl(target, tags, timeout, rate_limit, concurrency)
        summary = _summarize_findings(findings)
        uuid = UUIDS[evid_id]
        severity = sev_if_found if findings else "info"
        items.append({
            "plugin_uuid": uuid,
            "scan_item_uuid": uuid,
            "result": summary,
            "analysis_ai": ai_fn("NucleiScan", uuid, summary),
            "severity": severity,
            "duration": t.duration,
            "auto": True
        })

    return {"plugin": "NucleiScan", "result": items}
