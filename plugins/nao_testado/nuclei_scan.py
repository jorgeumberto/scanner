# plugins/nuclei_scan.py
import json
import shutil
from typing import Dict, Any, List, Tuple

from utils import run_cmd, Timer

# Para o carregamento dinâmico de config no main:
#   - o main procura configs/nuclei.json automaticamente
PLUGIN_CONFIG_NAME = "nuclei"

# UUIDs placeholders — troque pelos reais dos respectivos IDs do relatório
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
    72: "uuid-072",  # Debug/erros (parte 1)
    74: "uuid-074"   # Debug/erros (parte 2)
}

# Mapa: (nome lógico, tags nuclei, id_relatorio, severidade quando há achados)
DEFAULT_GROUPS: List[Tuple[str, List[str], int, str]] = [
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

def _ensure_nuclei_available() -> bool:
    """Retorna True se o binário nuclei estiver disponível no PATH."""
    return shutil.which("nuclei") is not None

def _run_nuclei_jsonl(target: str,
                      tags: List[str],
                      timeout: int,
                      rate_limit: int,
                      concurrency: int,
                      templates_dir: str = None,
                      severity_filter: List[str] = None,
                      extra_args: List[str] = None) -> List[Dict[str, Any]]:
    """
    Executa nuclei com -jsonl e retorna lista de findings (cada linha JSON -> dict).
    """
    cmd = ["nuclei", "-u", target, "-rl", str(rate_limit), "-c", str(concurrency), "-jsonl", "-silent"]

    # escopo http por padrão (não força se quiser usar templates não-http)
    # remova '-t http' se quiser permitir todos os templates
    # cmd += ["-t", "http"]

    if templates_dir:
        cmd += ["-ud", templates_dir]  # templates user dir
    for tg in tags:
        cmd += ["-tags", tg]

    if severity_filter:
        # nuclei aceita --severity critical,high,medium,low,info
        cmd += ["-severity", ",".join(severity_filter)]

    if extra_args:
        cmd += extra_args

    out = run_cmd(cmd, timeout=timeout)
    findings: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # algumas versões emitem logs não-JSON; filtrar por { ... }
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            # ignora linhas inválidas
            pass
    return findings

def _summarize_findings(findings: List[Dict[str, Any]], max_lines: int = 5) -> str:
    """Resumo compacto de achados."""
    if not findings:
        return "Nenhum achado"
    lines = []
    for f in findings[:max_lines]:
        tpl = f.get("template", "")
        info = f.get("info", {}) or {}
        name = info.get("name", "")
        sev  = info.get("severity", "")
        url  = f.get("matched-at", "") or f.get("host", "")
        lines.append(f"- {name} [{sev}] ({tpl}) -> {url}")
    extra = len(findings) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} achados")
    return "\n".join(lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional):
    {
      "timeout": 600,
      "rate_limit": 50,
      "concurrency": 10,
      "severity_filter": [],                 # ex.: ["medium","high","critical"]
      "templates_dir": null,                 # path do diretório de templates (para -ud)
      "groups_override": [                   # opcional: sobrescrever os grupos
        {"name":"idor","tags":["idor"],"id":68,"sev_on_find":"high"}
      ],
      "extra_args": []                       # lista de flags extras p/ nuclei
    }
    """
    if cfg is None:
        cfg = {}

    if not _ensure_nuclei_available():
        # Falta o binário — reporta como um item info com mensagem clara
        msg = "nuclei não encontrado no PATH. Instale com: apt install nuclei ou baixe em https://github.com/projectdiscovery/nuclei"
        # Podemos consolidar num único item (por simplicidade)
        return {
            "plugin": "NucleiScan",
            "result": [{
                "plugin_uuid": "uuid-nuclei-missing",
                "scan_item_uuid": "uuid-nuclei-missing",
                "result": msg,
                "analysis_ai": ai_fn("NucleiScan", "uuid-nuclei-missing", msg),
                "severity": "info",
                "duration": 0.0,
                "auto": True
            }]
        }

    timeout      = int(cfg.get("timeout", 600))
    rate_limit   = int(cfg.get("rate_limit", 50))
    concurrency  = int(cfg.get("concurrency", 10))
    sev_filter   = cfg.get("severity_filter") or []
    templates    = cfg.get("templates_dir")
    extra_args   = cfg.get("extra_args") or []

    groups_cfg = cfg.get("groups_override")
    if groups_cfg and isinstance(groups_cfg, list):
        groups: List[Tuple[str, List[str], int, str]] = []
        for g in groups_cfg:
            name = g.get("name") or "custom"
            tags = g.get("tags") or []
            evid = int(g.get("id", 0))
            sev  = g.get("sev_on_find", "info")
            groups.append((name, tags, evid, sev))
    else:
        groups = DEFAULT_GROUPS

    items: List[Dict[str, Any]] = []

    for group_name, tags, evid_id, sev_if_found in groups:
        # roda nuclei para o grupo
        with Timer() as t:
            findings = _run_nuclei_jsonl(
                target=target,
                tags=tags,
                timeout=timeout,
                rate_limit=rate_limit,
                concurrency=concurrency,
                templates_dir=templates,
                severity_filter=sev_filter,
                extra_args=extra_args
            )
        duration_group = t.duration  # <- fora do with

        summary = _summarize_findings(findings)
        uuid = UUIDS.get(evid_id, f"uuid-missing-{evid_id}")
        severity = sev_if_found if findings else "info"

        items.append({
            "plugin_uuid": uuid,
            "scan_item_uuid": uuid,
            "result": summary,
            "analysis_ai": ai_fn("NucleiScan", uuid, summary),
            "severity": severity,
            "duration": duration_group,
            "auto": True
        })

    return {"plugin": "NucleiScan", "result": items}
