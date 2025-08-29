# plugins/subdomains_enum.py
import shutil
import re
from typing import Dict, Any, List, Set
from utils import run_cmd, Timer, extract_host

# Ajuda o main dinâmico a achar configs/subdomains.json
PLUGIN_CONFIG_NAME = "subdomains"
PLUGIN_CONFIG_ALIASES = ["subfinder", "amass", "sublist3r"]

# UUIDs placeholders — troque pelos reais (IDs 15 e 16)
UUIDS = {
    15: "uuid-015",  # Enumeração de subdomínios
    16: "uuid-016",  # Tomada de subdomínio (CNAME/A órfãos)
}

# ----------------- helpers -----------------

def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def _norm_domain(d: str) -> str:
    return d.strip().lower().rstrip(".")

def _run_subfinder(domain: str, timeout: int, extra_args: List[str]) -> Set[str]:
    cmd = ["subfinder", "-silent", "-d", domain]
    if extra_args:
        cmd += extra_args
    out = run_cmd(cmd, timeout=timeout)
    subs = {_norm_domain(x) for x in out.splitlines() if x.strip()}
    return subs

def _run_amass(domain: str, timeout: int, extra_args: List[str]) -> Set[str]:
    # modo passive para ser mais rápido/seguro por padrão
    cmd = ["amass", "enum", "-passive", "-d", domain]
    if extra_args:
        cmd += extra_args
    out = run_cmd(cmd, timeout=timeout)
    subs = set()
    for line in out.splitlines():
        line = line.strip()
        # linhas do amass geralmente são "sub.example.com"
        if line and "." in line:
            subs.add(_norm_domain(line))
    return subs

def _run_sublist3r(domain: str, timeout: int, threads: int, wordlist: str) -> Set[str]:
    cmd = ["sublist3r", "-d", domain, "-t", str(threads)]
    if wordlist:
        cmd += ["-w", wordlist]
    out = run_cmd(cmd, timeout=timeout)
    subs = set()
    for line in out.splitlines():
        line = line.strip()
        if line and line.endswith(domain):
            subs.add(_norm_domain(line))
    return subs

def _resolve_record(name: str, rr: str, timeout: int = 10) -> List[str]:
    out = run_cmd(["dig", "+short", name, rr], timeout=timeout)
    vals = []
    for ln in out.splitlines():
        s = ln.strip().rstrip(".")
        if s:
            vals.append(s)
    return vals

# Providers comuns associados a possíveis takeovers (heurística)
PROVIDER_HINTS = {
    "aws":       [".s3.amazonaws.com", ".cloudfront.net", ".elb.amazonaws.com"],
    "azure":     [".azurewebsites.net", ".blob.core.windows.net", ".cloudapp.net"],
    "gcp":       [".storage.googleapis.com", ".appspot.com"],
    "github":    [".github.io"],
    "heroku":    [".herokuapp.com"],
    "fastly":    [".fastly.net"],
    "desk":      [".desk.com"],
    "wordpress": [".wpengine.com"],
    "shopify":   [".myshopify.com"],
}

# Mensagens HTTP comuns de recursos ausentes
HTTP_TAKEOVER_PATTERNS = [
    r"no such app",
    r"there isn't a github pages site here",
    r"repository not found",
    r"project not found",
    r"no such bucket",
    r"the specified bucket does not exist",
    r"application error",
    r"heroku | no such app",
    r"fastly error: unknown domain",
    r"bucketname\.s3\.amazonaws\.com 404"
]

def _http_probe(url: str, timeout: int = 10) -> str:
    # pega apenas cabeçalhos + pequenas amostras de corpo
    out = run_cmd(["curl", "-sS", "-i", "-m", str(timeout), url], timeout=timeout+2)
    return out

def _check_takeover(sub: str, cnames: List[str], a_records: List[str], http_body: str) -> bool:
    """
    Heurística:
      - se há CNAME para provedor conhecido E (sem A records ou HTTP mostra mensagens padrão),
      - marca como potencial takeover.
    """
    lname = sub.lower()
    cname_str = " ".join([c.lower() for c in cnames])
    a_empty = len(a_records) == 0

    provider_hit = False
    for prov, suffixes in PROVIDER_HINTS.items():
        for sfx in suffixes:
            if sfx in cname_str:
                provider_hit = True
                break
        if provider_hit:
            break

    http_text = (http_body or "").lower()
    http_hit = any(re.search(pat, http_text) for pat in HTTP_TAKEOVER_PATTERNS)

    return provider_hit and (a_empty or http_hit)

def _summarize_list(items: List[str], checklist_name: str, max_lines: int = 25) -> str:
    if not items:
        return f"Nenhum achado para {checklist_name}"
    lines = []
    for s in items[:max_lines]:
        lines.append(f"- {s}")
    extra = len(items) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} subdomínios")
    return "\n".join(lines)

# ----------------- plugin -----------------

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/subdomains.json:
    {
      "timeout_enum": 600,
      "timeout_dns": 10,
      "timeout_http": 10,
      "prefer": ["subfinder", "amass", "sublist3r"],   # ordem de preferência
      "extra_args": {
        "subfinder": ["-all"],
        "amass": ["-src"],
        "sublist3r": []
      },
      "sublist3r_threads": 40,
      "sublist3r_wordlist": null,
      "limit_results": 0,                  # 0 = sem limite; senão corta para N subdomínios
      "http_probe": true,                  # faz GET/HEAD nos subdomínios para takeover hints
      "providers_enabled": true            # aplica heurística de provedores comuns
    }
    """
    cfg = cfg or {}
    domain = extract_host(target)
    items: List[Dict[str, Any]] = []

    timeout_enum   = int(cfg.get("timeout_enum", 600))
    timeout_dns    = int(cfg.get("timeout_dns", 10))
    timeout_http   = int(cfg.get("timeout_http", 10))
    prefer_list    = cfg.get("prefer") or ["subfinder", "amass", "sublist3r"]
    extra_args_map = cfg.get("extra_args") or {}
    s3_threads     = int(cfg.get("sublist3r_threads", 40))
    s3_wordlist    = cfg.get("sublist3r_wordlist")
    limit_results  = int(cfg.get("limit_results", 0))
    do_http_probe  = bool(cfg.get("http_probe", True))
    providers_on   = bool(cfg.get("providers_enabled", True))

    # 1) Enumeração (mescla de ferramentas disponíveis)
    all_subs: Set[str] = set()
    with Timer() as t_enum:
        for tool in prefer_list:
            try:
                if tool == "subfinder" and _has("subfinder"):
                    subs = _run_subfinder(domain, timeout_enum, extra_args_map.get("subfinder", []))
                    all_subs |= subs
                elif tool == "amass" and _has("amass"):
                    subs = _run_amass(domain, timeout_enum, extra_args_map.get("amass", []))
                    all_subs |= subs
                elif tool == "sublist3r" and _has("sublist3r"):
                    subs = _run_sublist3r(domain, timeout_enum, s3_threads, s3_wordlist)
                    all_subs |= subs
            except Exception:
                # falha isolada de uma ferramenta não deve parar o plugin
                continue
    duration_enum = t_enum.duration

    subs_list = sorted(all_subs)
    if limit_results and len(subs_list) > limit_results:
        subs_list = subs_list[:limit_results]

    # 2) Resultado do item 15 (enumeração)
    uuid15 = UUIDS[15]
    res15 = _summarize_list(subs_list, "Enumeração de subdomínios")
    items.append({
        "plugin_uuid": uuid15,
        "scan_item_uuid": uuid15,
        "result": res15,
        "analysis_ai": ai_fn("Subdomains", uuid15, res15),
        "severity": "info" if subs_list else "info",
        "duration": duration_enum,
        "auto": True
    })

    # 3) Heurística de takeover (item 16)
    takeover_hits: List[str] = []
    with Timer() as t_tko:
        for sub in subs_list:
            cnames = _resolve_record(sub, "CNAME", timeout=timeout_dns)
            arecs  = _resolve_record(sub, "A", timeout=timeout_dns)
            http_body = ""
            if do_http_probe:
                # tenta HTTPS primeiro, cai para HTTP
                http_body = _http_probe("https://" + sub, timeout=timeout_http)
                if not http_body:
                    http_body = _http_probe("http://" + sub, timeout=timeout_http)

            flag = False
            if providers_on:
                flag = _check_takeover(sub, cnames, arecs, http_body)
            else:
                # fallback mínimo: CNAME sem A e HTTP 404/erro explícito
                http_low = (http_body or "").lower()
                simple_404 = (" 404 " in http_body) or ("not found" in http_low)
                flag = (len(cnames) > 0 and len(arecs) == 0 and simple_404)

            if flag:
                hint = f"{sub}  CNAME={','.join(cnames) or '-'}  A={','.join(arecs) or '-'}"
                takeover_hits.append(hint)
    duration_tko = t_tko.duration

    uuid16 = UUIDS[16]
    if takeover_hits:
        res16 = "Possível tomada de subdomínio:\n" + "\n".join(f"- {h}" for h in takeover_hits)
        sev16 = "high"
    else:
        res16 = "Nenhum achado para Tomada de subdomínio (CNAME/A órfãos)"
        sev16 = "info"

    items.append({
        "plugin_uuid": uuid16,
        "scan_item_uuid": uuid16,
        "result": res16,
        "analysis_ai": ai_fn("Subdomains", uuid16, res16),
        "severity": sev16,
        "duration": duration_tko,
        "auto": True
    })

    return {"plugin": "Subdomains", "result": items}
