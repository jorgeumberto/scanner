# plugins/dig_dns.py (alinhado ao padrão de saída do curl_files)
from utils import run_cmd, Timer, extract_host
from typing import Dict, Any, List, Optional
import shutil, re, json, os

PLUGIN_NAME = "DigDNS"

# UUIDs default – podem ser sobrescritos via configs/dig_dns.json
DEFAULT_UUIDS: Dict[str, str] = {
    "dns_records": "uuid-010-dns-records",  # A/AAAA/MX/TXT
    "reverse_ptr": "uuid-011-dns-reverse",  # PTR
    "spf":         "uuid-012-spf",          # SPF (TXT v=spf1)
    "dmarc":       "uuid-013-dmarc",        # DMARC (TXT v=DMARC1)
}

def _load_config() -> Dict[str, Any]:
    path = os.path.join("configs", f"{PLUGIN_NAME}.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _uuids(cfg: Dict[str, Any]) -> Dict[str, str]:
    u = DEFAULT_UUIDS.copy()
    u.update(cfg.get("uuids", {}))
    return u

def _ai(ai_fn, scan_item_uuid: str, text: str) -> str:
    try:
        if callable(ai_fn):
            return ai_fn(PLUGIN_NAME, scan_item_uuid, text)
    except Exception:
        pass
    return "[AI desabilitada]"

def _dig_args(base: List[str], cfg: Dict[str, Any]) -> List[str]:
    args = base[:]
    # Extras seguros para performance
    args.extend(cfg.get("dig_extra_args", ["+time=2", "+tries=1"]))
    if cfg.get("dns_server"):
        args.append(f"@{cfg['dns_server']}")
    return args

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
    lines = []
    for line in txt_output.splitlines():
        parts = re.findall(r'"([^"]*)"', line)
        if parts:
            lines.append("".join(parts))
        else:
            # Pode vir sem aspas dependendo do resolver
            line = line.strip()
            if line:
                lines.append(line)
    return lines

def _has_mx(mx_output: str) -> bool:
    # `dig +short MX` -> "10 mx1.example.com." linhas; qualquer conteúdo não vazio conta
    return any(line.strip() for line in mx_output.splitlines())

# ---------- helpers padronizados (espelhando curl_files) ----------

def _build_item(uuid: str, msg: str, severity: str, duration: float, ai_fn, item_name:str) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": msg,
        "analysis_ai": _ai(ai_fn, uuid, msg),
        "severity": severity,
        "duration": duration,
        "auto": True,
        "reference": "https://en.wikipedia.org/wiki/List_of_DNS_record_types",
        "item_name": item_name,
    }

# ---------- plugin ----------

def run_plugin(target: str, ai_fn):
    """
    Contrato igual ao dos plugins curl_*:
      retorna {"plugin": "dig_dns", "result": [items]}
      e cada item contém:
        - scan_item_uuid, result, analysis_ai, severity, duration, auto, file_name, description
    """
    cfg = _load_config()
    uuids = _uuids(cfg)
    timeout = int(cfg.get("timeout", 10))
    reverse_enabled = bool(cfg.get("reverse_enabled", True))
    records: List[str] = cfg.get("records", ["A", "AAAA", "MX", "TXT"])

    # Política: elevar severidade se houver MX mas faltarem SPF/DMARC
    spf_required_if_mx = bool(cfg.get("spf_required_if_mx", True))
    dmarc_required_if_mx = bool(cfg.get("dmarc_required_if_mx", True))

    items: List[Dict[str, Any]] = []
    host = extract_host(target) or target

    # Dependência
    if shutil.which("dig") is None:
        msg = "Dependência ausente: 'dig' não encontrado no PATH."
        for key in ["dns_records", "reverse_ptr", "spf", "dmarc"]:
            uuid = uuids[key]
            with Timer() as t_dep:
                pass
            items.append(_build_item(uuid, msg, "info", t_dep.duration, ai_fn, "Dig not found in PATH"))
        return {"plugin": PLUGIN_NAME, "result": items}

    # 10) Registros DNS (A/AAAA/MX/TXT)
    with Timer() as t10:
        outputs = []
        a_addrs: List[str] = []
        aaaa_addrs: List[str] = []
        mx_raw = ""
        for rr in records:
            out = _run_dig(host, rr, cfg, timeout=timeout)
            if rr.upper() == "TXT":
                txt_norm = "\n".join(_txt_lines_to_strings(out))
                outputs.append(f"== {rr.upper()} ==\n{txt_norm if txt_norm else '(vazio)'}")
            else:
                outputs.append(f"== {rr.upper()} ==\n{out if out else '(vazio)'}")
            if rr.upper() == "A":
                a_addrs = [l.strip() for l in out.splitlines() if l.strip()]
            elif rr.upper() == "AAAA":
                aaaa_addrs = [l.strip() for l in out.splitlines() if l.strip()]
            elif rr.upper() == "MX":
                mx_raw = out

    res10 = "\n".join(outputs).strip()
    items.append(_build_item(uuids["dns_records"], res10, "info", t10.duration, ai_fn, "DNS Records (A/AAAA/MX/TXT)"))

    # 11) PTR reverso (se habilitado)
    if reverse_enabled:
        with Timer() as t11:
            ips = [*a_addrs, *aaaa_addrs]
            if not ips:
                res11 = "A/AAAA não resolvidos – PTR ignorado"
            else:
                ptrs: List[str] = []
                for ipaddr in ips:
                    out_ptr = run_cmd(_dig_args(["dig", "+short", "-x", ipaddr], cfg), timeout=timeout) or ""
                    out_ptr = out_ptr.strip() if out_ptr.strip() else "(sem PTR)"
                    ptrs.append(f"{ipaddr} -> {out_ptr}")
                res11 = "\n".join(ptrs) if ptrs else "Sem IPs para resolver PTR"
        items.append(_build_item(uuids["reverse_ptr"], res11, "info", t11.duration, ai_fn, "Reverse PTR Lookup"))

    # 12) SPF (TXT com v=spf1)
    with Timer() as t12:
        txt_raw = _run_dig(host, "TXT", cfg, timeout=timeout)
        txt_lines = _txt_lines_to_strings(txt_raw)
        spf_hit = next((l for l in txt_lines if "v=spf1" in l.lower()), "")
    res12 = spf_hit if spf_hit else "SPF não encontrado"
    base_sev_spf = "info" if spf_hit else "low"
    sev12 = base_sev_spf
    if not spf_hit and spf_required_if_mx and _has_mx(mx_raw):
        sev12 = "medium"
    sev12 = cfg.get("severity_overrides", {}).get("spf", sev12)
    items.append(_build_item(uuids["spf"], res12, sev12, t12.duration, ai_fn, "SPF Record (TXT v=spf1)"))

    # 13) DMARC (TXT em _dmarc.<host> com v=DMARC1)
    with Timer() as t13:
        dmarc_raw = _run_dig(f"_dmarc.{host}", "TXT", cfg, timeout=timeout)
        dmarc_lines = _txt_lines_to_strings(dmarc_raw)
        dmarc_hit = next((l for l in dmarc_lines if "v=dmarc1" in l.lower()), "")
    res13 = dmarc_hit if dmarc_hit else "DMARC não encontrado"
    base_sev_dm = "info" if dmarc_hit else "low"
    sev13 = base_sev_dm
    if not dmarc_hit and dmarc_required_if_mx and _has_mx(mx_raw):
        sev13 = "medium"
    sev13 = cfg.get("severity_overrides", {}).get("dmarc", sev13)
    items.append(_build_item(uuids["dmarc"], res13, sev13, t13.duration, ai_fn, "DMARC Record (TXT v=DMARC1)"))

    return {
        "plugin": PLUGIN_NAME, 
        "file_name": "dig_dns.py",
        "description": "Consult DNS registries (A/AAAA/MX/TXT), reverse PTR and valid SPF/DMARC.",
        "category": "Information Gathering",
        "result": items
        }
