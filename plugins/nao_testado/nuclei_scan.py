# plugins/nuclei_scan.py
import json
import shutil
from typing import Dict, Any, List, Tuple

from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "nuclei"

# UUIDs placeholders — troque pelos reais
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
    return shutil.which("nuclei") is not None

def _nuclei_version() -> str:
    out = run_cmd(["nuclei", "-version"], timeout=15)
    line = out.splitlines()[0] if out else ""
    return line.strip() or "(desconhecida)"

def _run_nuclei_jsonl(targets: List[str],
                      tags: List[str],
                      timeout: int,
                      rate_limit: int,
                      concurrency: int,
                      templates_dir: str = None,
                      severity_filter: List[str] = None,
                      extra_args: List[str] = None) -> Tuple[List[Dict[str, Any]], Dict[str,int]]:
    """
    Executa nuclei -jsonl para múltiplos alvos (targets) e retorna:
      - lista de findings (dicts)
      - contagem agregada de códigos HTTP vistos (best-effort)
    """
    findings: List[Dict[str, Any]] = []
    http_counts: Dict[str, int] = {}

    for tgt in targets:
        cmd = ["nuclei", "-u", tgt, "-rl", str(rate_limit), "-c", str(concurrency), "-jsonl", "-silent"]
        if templates_dir:
            cmd += ["-ud", templates_dir]
        for tg in tags:
            cmd += ["-tags", tg]
        if severity_filter:
            cmd += ["-severity", ",".join(severity_filter)]
        if extra_args:
            cmd += extra_args

        out = run_cmd(cmd, timeout=timeout)
        for line in out.splitlines():
            s = line.strip()
            if not s or not (s.startswith("{") and s.endswith("}")):
                # heurística: alguns outputs do nuclei incluem hints tipo "http-code: 200"
                if "http-code:" in s:
                    code = s.split("http-code:")[-1].strip().split()[0]
                    if code.isdigit():
                        http_counts[code] = http_counts.get(code, 0) + 1
                continue
            try:
                obj = json.loads(s)
                findings.append(obj)
                # tenta contar http.status no JSON (nem sempre presente)
                code = str(obj.get("matcher-status", "")) or str(obj.get("status", ""))
                if code.isdigit():
                    http_counts[code] = http_counts.get(code, 0) + 1
            except Exception:
                pass

    return findings, http_counts

def _summarize_findings(findings: List[Dict[str, Any]], max_lines: int = 5) -> str:
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

def _no_findings_report(
    target: str,
    groups: List[Tuple[str, List[str], int, str]],
    sev_filter: List[str],
    rate_limit: int,
    concurrency: int,
    templates_dir: str,
    version: str,
    http_counts: Dict[str,int],
    extra_info: Dict[str, Any]
) -> str:
    group_names = ", ".join(g[0] for g in groups)
    tags_str = " | ".join(",".join(g[1]) for g in groups)
    sev_str = ", ".join(sev_filter) if sev_filter else "(nenhum)"
    tmpl = templates_dir or "(padrão do nuclei)"

    # HTTP histogram in a compact way
    if http_counts:
        # ordena por int do código
        pairs = sorted(((int(k), v) for k, v in http_counts.items() if str(k).isdigit()))
        http_line = ", ".join([f"{k}={v}" for k, v in pairs])
    else:
        http_line = "(sem dados)"

    lines = [
        "Nenhum achado",
        f"— alvo: {target}",
        f"— grupos executados: {group_names}" if group_names else "— grupos executados: (nenhum)",
        f"— tags: {tags_str}" if tags_str else "— tags: (nenhuma)",
        f"— filtros de severidade: {sev_str}",
        f"— rate_limit/concurrency: {rate_limit}/{concurrency}",
        f"— templates_dir: {tmpl}",
        f"— versão nuclei: {version}",
        f"— HTTP hints: {http_line}",
        "",
        "Sugestões:",
        "• rode `nuclei -update` para garantir templates atualizados (ou configure templates_dir).",
        "• remova/ajuste filters de severidade em configs/nuclei.json (ex.: \"severity_filter\": []).",
        "• aumente rate_limit/concurrency com permissão do cliente.",
        "• inclua grupos/tags extras ou paths específicos (cfg.paths / cfg.extra_urls).",
        "• se o app exige login, integre com ZAP/Burp ou configure autenticação/state.",
    ]

    # extra_info permite acoplar “motivos” (ex.: resoluções 403/429 elevadas)
    if extra_info.get("note"):
        lines.append(f"• nota: {extra_info['note']}")

    return "\n".join(lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional):
    {
      "timeout": 600,
      "rate_limit": 50,
      "concurrency": 10,
      "severity_filter": [],                  # ["medium","high","critical"]
      "templates_dir": null,
      "groups_override": [ { "name": "...", "tags": [], "id": 68, "sev_on_find": "high" } ],
      "extra_args": [],
      "paths": ["/", "/login", "/buscar?q=test"],   # será combinado com target
      "extra_urls": ["https://foo.tld/admin"],      # URLs completas adicionais
      "no_findings_verbose": true                   # liga relatório detalhado
    }
    """
    if cfg is None:
        cfg = {}

    if not _ensure_nuclei_available():
        msg = "nuclei não encontrado no PATH. Instale com: apt install nuclei ou baixe em https://github.com/projectdiscovery/nuclei"
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
    nofind_verbose = bool(cfg.get("no_findings_verbose", True))

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

    # monta a lista de alvos (target + paths + extra_urls)
    targets: List[str] = [target]
    for p in cfg.get("paths") or []:
        p = p.lstrip("/")
        targets.append(target.rstrip("/") + "/" + p)
    for u in cfg.get("extra_urls") or []:
        targets.append(u)

    version = _nuclei_version()
    items: List[Dict[str, Any]] = []

    for group_name, tags, evid_id, sev_if_found in groups:
        with Timer() as t:
            findings, http_counts = _run_nuclei_jsonl(
                targets=targets,
                tags=tags,
                timeout=timeout,
                rate_limit=rate_limit,
                concurrency=concurrency,
                templates_dir=templates,
                severity_filter=sev_filter,
                extra_args=extra_args
            )
        duration_group = t.duration

        summary = _summarize_findings(findings)
        uuid = UUIDS.get(evid_id, f"uuid-missing-{evid_id}")
        severity = sev_if_found if findings else "info"

        # se não achou nada e verbose ligado, substitui o summary por relatório detalhado
        if not findings and nofind_verbose:
            summary = _no_findings_report(
                target=target,
                groups=[(group_name, tags, evid_id, sev_if_found)],
                sev_filter=sev_filter,
                rate_limit=rate_limit,
                concurrency=concurrency,
                templates_dir=templates,
                version=version,
                http_counts=http_counts,
                extra_info={}
            )

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
