# plugins/dig_dns.py (alinhado ao padrão de saída do curl_files, com tag 'command' por item)
from utils import run_cmd, Timer, extract_host,  ensure_tool
from typing import Dict, Any, List, Optional
import re, json, os

PLUGIN_NAME = "DigDNS"

# UUIDs default – podem ser sobrescritos via configs/dig_dns.json
DEFAULT_UUIDS: Dict[str, str] = {
    "dns_records": "uuid-010-dns-records",  # A/AAAA/MX/TXT
    "reverse_ptr": "uuid-011-dns-reverse",  # PTR
    "spf":         "uuid-012-spf",          # SPF (TXT v=spf1)
    "dmarc":       "uuid-013-dmarc",        # DMARC (TXT v=DMARC1)
}

# Config default
DEFAULT_CFG: Dict[str, Any] = {
    # extras seguros (performance) – podem ser sobrescritos em configs/dig_dns.json
    "dig_extra_args": ["+time=2", "+tries=1"],
    "dns_server": None,                 # ex.: "8.8.8.8" → vira "@8.8.8.8"
    "enable_reverse_ptr": True,         # ativa 11) PTR reverso
    "spf_required_if_mx": True,         # se tem MX e não tem SPF → escalar severidade
    "dmarc_required_if_mx": True,       # se tem MX e não tem DMARC → escalar severidade
    "severity_overrides": {},           # ex.: {"spf":"medium","dmarc":"high"}
    "timeout": 10,                      # timeout base por consulta dig
}

def _load_config_file() -> Dict[str, Any]:
    """Lê configs/dig_dns.json se existir; caso contrário, {}."""
    path = os.path.join("configs", "dig_dns.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _merge_cfg(user_cfg: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = dict(DEFAULT_CFG)
    file_cfg = _load_config_file()
    if file_cfg:
        cfg.update(file_cfg)
    if user_cfg:
        cfg.update(user_cfg)
    # normalizações simples
    if isinstance(cfg.get("dig_extra_args"), str):
        cfg["dig_extra_args"] = [cfg["dig_extra_args"]]
    return cfg

def _ai(ai_fn, uuid: str, msg: str) -> str:
    try:
        return ai_fn(PLUGIN_NAME, uuid, msg)
    except Exception:
        return "[AI desabilitada]"

# -------- helpers para dig --------

def _dig_args(base: List[str], cfg: Dict[str, Any]) -> List[str]:
    args = base[:]
    # Extras seguros para performance
    extras = cfg.get("dig_extra_args") or []
    if isinstance(extras, list):
        args.extend(extras)
    if cfg.get("dns_server"):
        args.append(f"@{cfg['dns_server']}")
    return args

def _cmd_str(base_args: List[str], cfg: Dict[str, Any]) -> str:
    """String exata do comando que será (ou foi) executado."""
    return " ".join(_dig_args(base_args, cfg))

def _run_dig(host_or_ip: str, rr: Optional[str], cfg: Dict[str, Any], timeout: int = 10) -> str:
    cmd = ["dig", "+short"]
    if rr:
        cmd += [host_or_ip, rr]
    else:
        cmd += [host_or_ip]
    cmd = _dig_args(cmd, cfg)
    return (run_cmd(cmd, timeout=timeout) or "").strip()

def _txt_lines_to_strings(txt_output: str) -> List[str]:
    """
    Concatena segmentos entre aspas que o `dig +short` às vezes separa.
    Ex.: "\"v=spf1 include:_spf.example\" \"-all\"" -> "v=spf1 include:_spf.example-all"
    """
    lines: List[str] = []
    for line in txt_output.splitlines():
        parts = re.findall(r'"([^"]*)"', line)
        if parts:
            lines.append("".join(parts))
        else:
            line = line.strip()
            if line:
                lines.append(line)
    return lines

def _has_mx(mx_output: str) -> bool:
    # qualquer conteúdo não vazio conta como presença de MX
    return any(line.strip() for line in mx_output.splitlines())

# ---------- helpers padronizados (espelhando curl_files) ----------

def _build_item(uuid: str, msg: str, severity: str, duration: float, ai_fn, item_name: str, command: str) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": msg,
        "analysis_ai": _ai(ai_fn, uuid, msg),
        "severity": severity,
        "duration": duration,
        "auto": True,
        "reference": "https://en.wikipedia.org/wiki/List_of_DNS_record_types",
        "item_name": item_name,
        "command": command,
    }

# ========== plugin principal ==========

def run_plugin(target: str, ai_fn, cfg_in: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:

    ensure_tool('dig')  # lança erro se não houver

    cfg = _merge_cfg(cfg_in)
    timeout = int(cfg.get("timeout", 10) or 10)

    host = extract_host(target)
    items: List[Dict[str, Any]] = []

    # UUIDs (sobrescrevíveis)
    uuids = dict(DEFAULT_UUIDS)
    uuids.update({k: v for k, v in (cfg.get("uuids") or {}).items() if k in uuids})

    # 10) A/AAAA/MX/TXT
    with Timer() as t10:
        a_raw    = _run_dig(host, "A",    cfg, timeout=timeout)
        aaaa_raw = _run_dig(host, "AAAA", cfg, timeout=timeout)
        mx_raw   = _run_dig(host, "MX",   cfg, timeout=timeout)
        txt_raw  = _run_dig(host, "TXT",  cfg, timeout=timeout)

        a_txt    = a_raw.strip()    if a_raw.strip()    else "(vazio)"
        aaaa_txt = aaaa_raw.strip() if aaaa_raw.strip() else "(vazio)"
        mx_txt   = mx_raw.strip()   if mx_raw.strip()   else "(vazio)"
        txt_txt  = txt_raw.strip()  if txt_raw.strip()  else "(vazio)"

        res10 = f"== A ==\n{a_txt}\n== AAAA ==\n{aaaa_txt}\n== MX ==\n{mx_txt}\n== TXT ==\n{txt_txt}"

    cmds10 = [
        _cmd_str(["dig", "+short", host, "A"], cfg),
        _cmd_str(["dig", "+short", host, "AAAA"], cfg),
        _cmd_str(["dig", "+short", host, "MX"], cfg),
        _cmd_str(["dig", "+short", host, "TXT"], cfg),
    ]
    items.append(_build_item(
        uuids["dns_records"], res10, "info", t10.duration, ai_fn,
        "DNS Records (A/AAAA/MX/TXT)",
        " ; ".join(cmds10)
    ))

    # Preparação para PTR
    a_addrs    = [l.strip() for l in a_raw.splitlines() if l.strip()]
    aaaa_addrs = [l.strip() for l in aaaa_raw.splitlines() if l.strip()]

    # 11) PTR reverso (se habilitado)
    if bool(cfg.get("enable_reverse_ptr", True)):
        with Timer() as t11:
            ips = [*a_addrs, *aaaa_addrs]
            if not ips:
                res11 = "A/AAAA não resolvidos – PTR ignorado"
                cmds11: List[str] = []
            else:
                ptrs: List[str] = []
                cmds11 = []
                for ipaddr in ips:
                    cmds11.append(_cmd_str(["dig", "+short", "-x", ipaddr], cfg))
                    out_ptr = _run_dig(ipaddr, None, cfg, timeout=timeout) if False else (
                        run_cmd(_dig_args(["dig", "+short", "-x", ipaddr], cfg), timeout=timeout) or ""
                    )
                    out_ptr = out_ptr.strip() if out_ptr.strip() else "(sem PTR)"
                    ptrs.append(f"{ipaddr} -> {out_ptr}")
                res11 = "\n".join(ptrs) if ptrs else "Sem IPs para resolver PTR"

        items.append(_build_item(
            uuids["reverse_ptr"], res11, "info", t11.duration, ai_fn,
            "Reverse PTR Lookup",
            " ; ".join(cmds11)
        ))

    # 12) SPF (TXT com v=spf1)
    with Timer() as t12:
        txt_raw_spf = _run_dig(host, "TXT", cfg, timeout=timeout)
        txt_lines   = _txt_lines_to_strings(txt_raw_spf)
        spf_hit     = next((l for l in txt_lines if "v=spf1" in l.lower()), "")
    res12 = spf_hit if spf_hit else "SPF não encontrado"
    base_sev_spf = "info" if spf_hit else "low"
    sev12 = base_sev_spf
    if not spf_hit and bool(cfg.get("spf_required_if_mx", True)) and _has_mx(mx_raw):
        sev12 = "medium"
    sev12 = (cfg.get("severity_overrides", {}) or {}).get("spf", sev12)
    cmd12 = _cmd_str(["dig", "+short", host, "TXT"], cfg)
    items.append(_build_item(
        uuids["spf"], res12, sev12, t12.duration, ai_fn,
        "SPF Record (TXT v=spf1)",
        cmd12
    ))

    # 13) DMARC (TXT com v=DMARC1)
    with Timer() as t13:
        dmarc_host = f"_dmarc.{host}"
        dmarc_raw  = _run_dig(dmarc_host, "TXT", cfg, timeout=timeout)
        dmarc_lines = _txt_lines_to_strings(dmarc_raw)
        dmarc_hit   = next((l for l in dmarc_lines if "v=dmarc1" in l.lower()), "")
    res13 = dmarc_hit if dmarc_hit else "DMARC não encontrado"
    base_sev_dm = "info" if dmarc_hit else "low"
    sev13 = base_sev_dm
    if not dmarc_hit and bool(cfg.get("dmarc_required_if_mx", True)) and _has_mx(mx_raw):
        sev13 = "medium"
    sev13 = (cfg.get("severity_overrides", {}) or {}).get("dmarc", sev13)
    cmd13 = _cmd_str(["dig", "+short", dmarc_host, "TXT"], cfg)
    items.append(_build_item(
        uuids["dmarc"], res13, sev13, t13.duration, ai_fn,
        "DMARC Record (TXT v=DMARC1)",
        cmd13
    ))

    return {
        "plugin": PLUGIN_NAME,
        "file_name": "dig_dns.py",
        "description": "Consult DNS registries (A/AAAA/MX/TXT), reverse PTR and valid SPF/DMARC.",
        "category": "Information Gathering",
        "result": items
    }
