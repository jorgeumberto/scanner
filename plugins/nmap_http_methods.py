from typing import Dict, Any, List, Tuple, Set
from utils import run_cmd
import xml.etree.ElementTree as ET
import time
import re

# ===== tenta usar normalizador do utils (se existir) =====
_utils_fmt = None
try:
    from utils import format_target_for_nmap as _utils_fmt
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

# ===== UUIDs (alinha com o curl_http_methods) =====
UUIDS = {
    201: "uuid-201-options-allow",     # OPTIONS / Allow header (resumo)
    202: "uuid-202-trace-enabled",     # TRACE habilitado
    203: "uuid-203-put-allowed",       # PUT permitido
    204: "uuid-204-delete-allowed",    # DELETE permitido
    205: "uuid-205-patch-allowed",     # PATCH permitido
    206: "uuid-206-propfind-allowed",  # PROPFIND permitido
    207: "uuid-207-mkcol-allowed",     # MKCOL permitido
    208: "uuid-208-move-allowed",      # MOVE permitido
    209: "uuid-209-copy-allowed",      # COPY permitido
    210: "uuid-210-cors-preflight",    # (não aplicável via nmap) info
}

# ===== helpers =====

_HTTP_VERBS = {
    "GET","HEAD","POST","OPTIONS","PUT","DELETE","PATCH","TRACE",
    # WebDAV principais
    "PROPFIND","PROPPATCH","MKCOL","MOVE","COPY","LOCK","UNLOCK","SEARCH"
}

_VERB_SEVERITY = {
    "PUT": "high",
    "DELETE": "high",
    "PATCH": "medium",
    "PROPFIND": "high",
    "MKCOL": "high",
    "MOVE": "high",
    "COPY": "high",
    # os demais não geram itens dedicados aqui
}

def _normalize_target_and_port(target: str) -> Tuple[str, int, bool, List[str]]:
    """
    Usa a função do utils se disponível (para limpar host). Em seguida, extrai a porta:
    - se URL com esquema: porta explícita ou padrão (80 http / 443 https)
    - se "host:porta": usa porta
    - senão: 80
    Retorna: (host, port, is_https, af_flags[-4/-6 opcional])
    """
    from urllib.parse import urlparse

    raw = (target or "").strip()
    # tentar normalizador do utils
    host_only: str = raw
    af_flags: List[str] = []
    if _utils_fmt:
        try:
            res = _utils_fmt(raw)
            if isinstance(res, str):
                host_only = res.strip().strip("[]")
            elif isinstance(res, (tuple, list)) and res:
                host_only = str(res[0]).strip().strip("[]")
                flags = res[1] if len(res) > 1 else []
                if isinstance(flags, str):
                    flags = [flags]
                af_flags = [f for f in flags if f in ("-4","-6")]
        except Exception:
            pass

    # tentar extrair porta/esquema da string original
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="http")
    scheme = (parsed.scheme or "http").lower()
    port = parsed.port
    is_https = (scheme == "https") or (port == 443)

    # se não veio hostname do utils, use o da URL
    if not host_only:
        host_only = (parsed.hostname or raw.split("/")[0] or "").strip("[]")

    # se porta ainda não definida, deduza
    if port is None:
        if scheme == "https":
            port = 443
        else:
            # se no raw havia "host:NN", pegue
            if ":" in (parsed.netloc or "") and parsed.port:
                port = parsed.port
            else:
                port = 80

    return host_only, port, is_https, af_flags

def _run_nmap_http_scripts(host: str, port: int, is_https: bool, af_flags: List[str], timeout: int = 180) -> str:
    """
    Executa nmap com scripts http-* focados em métodos.
    Saída XML (-oX -). Usa -sT, -Pn, -n.
    Em HTTPS (ou porta 443), força http.ssl=true para os scripts.
    """
    scripts = "http-methods,http-trace,http-webdav-scan"
    args = ["-sT", "-Pn", "-n"] + (af_flags or []) + ["-p", str(port), "--script", scripts, "-oX", "-"]
    if is_https:
        args += ["--script-args", "http.ssl=true"]
    return run_cmd(["nmap"] + args + [host], timeout=timeout) or ""

def _extract_methods_from_output(text: str) -> Set[str]:
    """
    Pega verbos HTTP do atributo 'output' dos scripts (caixa alta).
    """
    if not text:
        return set()
    candidates = set(re.findall(r"\b[A-Z]{3,10}\b", text))
    return {c for c in candidates if c in _HTTP_VERBS}

def _parse_nmap_scripts(xml_text: str) -> Dict[str, Any]:
    """
    Lê o XML e retorna:
      {
        "allowed": set([...]),
        "trace_enabled": bool,
        "webdav": set([...])   # métodos WebDAV detectados
      }
    Consolida métodos de http-methods e http-webdav-scan.
    """
    data = {"allowed": set(), "trace_enabled": False, "webdav": set()}
    xml = (xml_text or "").strip()
    if not xml or not xml.lstrip().startswith("<"):
        return data

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return data

    for script in root.findall(".//host/ports/port/script"):
        sid = script.get("id") or ""
        out = script.get("output") or ""

        if sid == "http-methods":
            methods = _extract_methods_from_output(out)
            data["allowed"].update(methods)

            # também tenta coletar de tabelas (quando presentes)
            for elem in script.findall(".//elem"):
                val = (elem.text or "").strip().upper()
                if val in _HTTP_VERBS:
                    data["allowed"].add(val)

        elif sid == "http-trace":
            # heurística: se output mencionar 'enabled', considera ativo
            if re.search(r"\benabled\b", out, re.IGNORECASE):
                data["trace_enabled"] = True

        elif sid == "http-webdav-scan":
            methods = _extract_methods_from_output(out)
            data["webdav"].update(methods)
            # idem: tenta pegar de elem/table
            for elem in script.findall(".//elem"):
                val = (elem.text or "").strip().upper()
                if val in _HTTP_VERBS:
                    data["webdav"].add(val)

    # consolida allowed com webdav (para fins de relatório)
    if data["webdav"]:
        data["allowed"].update(data["webdav"])

    return data

def _make_item(uuid: str, result: str, severity: str, duration: float, ai_fn) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": result,
        "analysis_ai": ai_fn("nmap_http_methods", uuid, result),
        "severity": severity,
        "duration": duration,
        "auto": True,
    }

# ===== plugin =====
def run_plugin(target: str, ai_fn) -> Dict[str, Any]:
    t0 = time.time()

    host, port, is_https, af_flags = _normalize_target_and_port(target)
    xml = _run_nmap_http_scripts(host, port, is_https, af_flags)
    parsed = _parse_nmap_scripts(xml)

    allowed = parsed["allowed"]
    dav = parsed["webdav"]
    trace_on = parsed["trace_enabled"]

    items: List[Dict[str, Any]] = []

    # 201) OPTIONS/Allow (resumo)
    if allowed:
        msg = (f"{host}:{port} — Métodos anunciados/detectados: {', '.join(sorted(allowed))} — "
               "Seguro: cabeçalho/descoberta informativa; verifique necessidade de cada método.")
    else:
        msg = (f"{host}:{port} — Não foi possível extrair métodos via Nmap (http-methods). "
               "Info: servidor pode não anunciar Allow ou requer caminhos específicos.")
    items.append(_make_item(UUIDS[201], msg, "info", round(time.time()-t0, 3), ai_fn))

    # 202) TRACE
    if trace_on:
        msg = f"{host}:{port} — TRACE habilitado — Risco: método de depuração ativo; desabilite."
        sev = "high"
    else:
        msg = f"{host}:{port} — TRACE desabilitado (não detectado) — Seguro."
        sev = "info"
    items.append(_make_item(UUIDS[202], msg, sev, round(time.time()-t0, 3), ai_fn))

    # 203..209) Métodos de risco (com motivo)
    for verb, uuid in [
        ("PUT", UUIDS[203]),
        ("DELETE", UUIDS[204]),
        ("PATCH", UUIDS[205]),
        ("PROPFIND", UUIDS[206]),
        ("MKCOL", UUIDS[207]),
        ("MOVE", UUIDS[208]),
        ("COPY", UUIDS[209]),
    ]:
        if verb in allowed:
            sev = _VERB_SEVERITY.get(verb, "medium")
            motivo = {
                "high":   "Risco: método sensível permitido; garanta authz estrita ou desabilite.",
                "medium": "Atenção: método permitido; avalie necessidade e controles."
            }[sev]
            msg = f"{host}:{port} — {verb} permitido — {motivo}"
        else:
            msg = f"{host}:{port} — {verb} não anunciado/detectado — Seguro (no contexto desta rota/host)."
            sev = "info"
        items.append(_make_item(uuid, msg, sev, round(time.time()-t0, 3), ai_fn))

    # 210) CORS (não aplicável via nmap)
    items.append(_make_item(
        UUIDS[210],
        f"{host}:{port} — CORS/Preflight não avaliado por Nmap — Info: use o plugin curl_http_methods para testar ACA*.",
        "info",
        round(time.time()-t0, 3),
        ai_fn
    ))

    return {"plugin": "nmap_http_methods", "result": items}
