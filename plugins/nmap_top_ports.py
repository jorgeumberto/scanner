from typing import Dict, Any, List, Tuple
from utils import run_cmd
import xml.etree.ElementTree as ET
import time

# ====== tenta usar o normalizador que você já tem no utils ======
_utils_fmt = None
try:
    from utils import format_target_for_nmap as _utils_fmt  # preferido
except Exception:
    try:
        from utils import normalize_target_for_scanner as _utils_fmt
    except Exception:
        try:
            from utils import normalize_target as _utils_fmt
        except Exception:
            try:
                from utils import format_target as _utils_fmt
            except Exception:
                _utils_fmt = None

# ====== UUID ======
UUIDS = {301: "uuid-301-nmap-top-ports"}

# ====== fallback de normalização (usado só se o utils não oferecer) ======
def _fallback_normalize(target: str) -> Tuple[str, List[str]]:
    """
    Aceita URL ou host/IP (v4/v6). Retorna (host_limpo, flags_af),
    onde flags_af é ['-4'] ou ['-6'] ou [].
    """
    from urllib.parse import urlparse
    import ipaddress

    t = (target or "").strip()
    parsed = urlparse(t if "://" in t else f"//{t}", scheme="http")
    host = (parsed.hostname or t.split("/")[0] or "").strip("[]")

    flags_af: List[str] = []
    try:
        ip_obj = ipaddress.ip_address(host)
        flags_af = ["-4"] if ip_obj.version == 4 else ["-6"]
    except Exception:
        # hostname: deixa sem -4/-6
        pass
    return host, flags_af

def _normalize_target(target: str) -> Tuple[str, List[str]]:
    """
    Wrapper que usa o método do utils se existir; senão usa fallback.
    Aceita retorno do utils como:
      - string com host, ou
      - (host,), ou
      - (host, flags) onde flags pode ser str ou lista.
    """
    if _utils_fmt:
        try:
            res = _utils_fmt(target)
            # string simples
            if isinstance(res, str):
                return res.strip().strip("[]"), []
            # tupla/lista
            if isinstance(res, (tuple, list)) and res:
                host = str(res[0]).strip().strip("[]")
                flags = res[1] if len(res) > 1 else []
                if isinstance(flags, str):
                    flags = [flags]
                # filtra apenas -4/-6 se vier algo a mais
                flags = [f for f in flags if f in ("-4", "-6")]
                return host, flags
        except Exception:
            pass
    # fallback
    return _fallback_normalize(target)

# ====== nmap helpers ======
def _run_nmap_xml(host: str, af_flags: List[str], timeout: int = 600) -> str:
    """
    Varre TODAS as portas TCP (1–65535), sem ping e sem DNS, saída em XML (-oX -).
    -sT: TCP connect (não exige root).
    """
    cmd = ["nmap", "-sT", "-Pn", "-n"] + (af_flags or []) + ["-p-", "-oX", "-", host]
    return run_cmd(cmd, timeout=timeout) or ""

def _parse_nmap_ports(xml_text: str) -> Tuple[str, List[Dict[str, str]], List[Dict[str, str]]]:
    """
    Retorna (host_state, ports, extraports)
      host_state: "up" | "down" | ""
      ports: [{"port":"80","proto":"tcp","state":"open","service":"http"} ...]
      extraports: [{"state":"closed","count":"65530"} ...]
    """
    host_state = ""
    ports: List[Dict[str, str]] = []
    extras: List[Dict[str, str]] = []

    xml = (xml_text or "").strip()
    if not xml or not xml.lstrip().startswith("<"):
        return host_state, ports, extras

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return host_state, ports, extras

    host_el = root.find(".//host")
    if host_el is None:
        return host_state, ports, extras

    status_el = host_el.find("./status")
    if status_el is not None:
        host_state = status_el.get("state") or ""

    for p in host_el.findall("./ports/port"):
        proto = p.get("protocol") or ""
        portid = p.get("portid") or ""
        state_el = p.find("./state")
        state = state_el.get("state") if state_el is not None else ""
        serv_el = p.find("./service")
        service = serv_el.get("name") if serv_el is not None else ""
        if portid and proto:
            ports.append({
                "port": portid,
                "proto": proto,
                "state": state,
                "service": service
            })

    for ex in host_el.findall("./ports/extraports"):
        extras.append({
            "state": ex.get("state") or "",
            "count": ex.get("count") or ""
        })

    return host_state, ports, extras

def _fmt_ports(ports: List[Dict[str, str]]) -> str:
    if not ports:
        return "(sem portas individuais)"
    return " | ".join(f"{p['port']}/{p['proto']} {p['state']} {p['service'] or '-'}" for p in ports)

def _fmt_extras(extras: List[Dict[str, str]]) -> str:
    if not extras:
        return "(sem agregado)"
    return ", ".join(f"{e['count']} {e['state']}" for e in extras if e.get("count") and e.get("state"))

def _severity(ports: List[Dict[str, str]], extras: List[Dict[str, str]]) -> str:
    states = {p["state"] for p in ports}
    if "open" in states:
        return "high"
    if "filtered" in states:
        return "medium"
    extra_states = {e["state"] for e in extras}
    if "filtered" in extra_states:
        return "medium"
    return "info"

# ====== plugin ======
def run_plugin(target: str, ai_fn) -> Dict[str, Any]:
    t0 = time.time()

    host, af_flags = _normalize_target(target)
    xml = _run_nmap_xml(host, af_flags)
    host_state, ports, extras = _parse_nmap_ports(xml)

    if host_state and host_state != "up":
        result_text = f"Host {host_state} — Nmap não retornou portas."
        severity = "info"
    else:
        details = [
            f"Portas (individuais): {_fmt_ports(ports)}",
            f"Agregado: {_fmt_extras(extras)}"
        ]
        severity = _severity(ports, extras)
        if severity == "high":
            motivo = "Encontrou porta(s) aberta(s) — serviço exposto; revisar ACL/exposição."
        elif severity == "medium":
            motivo = "Sem abertas; presença de estados 'filtered' — firewall/filtragem ativa."
        else:
            motivo = "Apenas fechadas (agregado) — sem serviços ouvindo nas amostras."
        result_text = " || ".join(details) + f" — Motivo: {motivo}"

    duration = round(time.time() - t0, 3)

    item = {
        "scan_item_uuid": UUIDS[301],
        "result": result_text,
        "analysis_ai": ai_fn("nma_top_ports", UUIDS[301], result_text),
        "severity": severity,
        "duration": duration,
        "auto": True,
        "reference": "https://nmap.org",
        "item_name": "Nmap Top Ports Scan"
    }

    return {
        "plugin": "nmap_top_ports", 
        "plugin_uuid": "uuid-nmap-top-ports",
        "file_name": "nmap_top_ports.py",
        "description": "Scans all TCP ports using Nmap to identify open and filtered ports.",
        "category": "Information Gathering",
        "result": [item]}
