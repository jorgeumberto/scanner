# plugins/nikto_scan.py
from typing import Dict, Any, List, Optional
from utils import run_cmd, Timer
from urllib.parse import urlparse
import shlex

PLUGIN_CONFIG_NAME = "nikto_scan"
PLUGIN_CONFIG_ALIASES = ["nikto", "nikto2"]

UUID_NIKTO = "uuid-065-nikto-scan"  # UUID dedicado ao Nikto

REFERENCE_URL = "https://cirt.net/Nikto2"

def _safe_run(cmd: List[str], timeout: int) -> str:
    try:
        return run_cmd(cmd, timeout=timeout) or ""
    except Exception:
        return ""

def _resolve_tool_path(tool: str) -> str:
    """
    Resolve o caminho absoluto do binário via PATH.
    Retorna string vazia se não encontrado.
    """
    if path:
        return path
    if which:
        return which.splitlines()[0].strip()
    return ""

def _nikto_info() -> Dict[str, str]:
    """
    Retorna {'path': <caminho-ou-vazio>, 'version': <linha-versão-ou-vazio>}
    """
    path = _resolve_tool_path("nikto")
    ver = ""
    if path:
        # nikto -Version imprime versão
        ver = _safe_run(["bash", "-lc", f'{shlex.quote(path)} -Version 2>&1 | head -n 1'], timeout=6).strip()
        if not ver:
            # fallback
            ver = _safe_run(["bash", "-lc", f'{shlex.quote(path)} -Help 2>&1 | head -n 2'], timeout=6).strip()
    return {"path": path, "version": ver}

def _build_target_components(target: str, port: Optional[int], ssl: Optional[bool]) -> Dict[str, Any]:
    """
    Aceita target como URL (http/https) ou host puro. Retorna dict com:
    - host_for_nikto (string para -host)
    - port (int ou None)
    - ssl_flag (bool ou None)
    """
    host_for_nikto = target
    ssl_flag = ssl
    final_port = port

    try:
        p = urlparse(target)
        if p.scheme in ("http", "https"):
            # Nikto aceita URL em -host (ex.: -host https://site)
            host_for_nikto = target
            if final_port is None and p.port:
                final_port = p.port
            if ssl_flag is None:
                ssl_flag = (p.scheme == "https")
        else:
            # host simples (sem esquema)
            host_for_nikto = target
    except Exception:
        # mantém default inalterado
        pass

    return {"host_for_nikto": host_for_nikto, "port": final_port, "ssl": ssl_flag}

def _build_nikto_command(
    nikto_path: str,
    target: str,
    port: Optional[int],
    ssl: Optional[bool],
    tuning: Optional[str],
    plugins: Optional[str],
    headers: Dict[str, str],
    nointeractive: bool,
    useragent: Optional[str]
) -> str:
    """
    Monta comando do Nikto com opções comuns:
    -host <alvo>
    -port <porta> (opcional)
    -ssl (opcional)
    -Tuning <códigos> (opcional)
    -Plugins <lista> (opcional)
    -Header "Key: Value" (pode repetir)
    -nointeractive para não travar
    -useragent (opcional)
    """
    parts: List[str] = [nikto_path, "-host", target]
    if port:
        parts += ["-port", str(port)]
    if ssl:
        parts += ["-ssl"]
    if tuning:
        parts += ["-Tuning", tuning]
    if plugins:
        parts += ["-Plugins", plugins]
    if useragent:
        parts += ["-useragent", useragent]
    if nointeractive:
        parts += ["-nointeractive"]
    for k, v in (headers or {}).items():
        parts += ["-Header", f"{k}: {v}"]
    # saída “normal” no stdout (sem arquivo), sem cores
    parts += ["-nolookup"]
    return " ".join(shlex.quote(x) for x in parts)

def _parse_nikto_output(out: str) -> List[str]:
    """
    Extrai linhas de achados típicos do Nikto.
    Regras simples:
    - Coleta linhas iniciadas com '+ ' (achados)
    - Mantém também o resumo final (linhas 'Host', 'End Time', etc.)
    """
    if not out:
        return ["Sem saída do Nikto (verifique conectividade e parâmetros)."]
    findings: List[str] = []
    trailer: List[str] = []
    for ln in out.splitlines():
        l = ln.strip()
        if not l:
            continue
        # Principais achados iniciam com '+ ' ou contêm 'OSVDB' (legado) ou plugin id
        if l.startswith("+ "):
            findings.append(l)
        elif l.lower().startswith("host:") or l.lower().startswith("end time") or l.lower().startswith("start time"):
            trailer.append(l)
    # limita tamanho
    collected = findings[:120] + (["..."] if len(findings) > 120 else [])
    collected += trailer[-5:]
    if not collected:
        collected = ["Nenhum achado reconhecido no formato padrão do Nikto."]
    return collected

def _severity_from_findings(lines: List[str]) -> str:
    """
    Heurística simples de severidade:
    - high: se alguma linha contém 'VULNERABLE' ou 'SQL Injection' ou 'Directory traversal' etc.
    - medium: se existem achados (linhas iniciadas com '+ ')
    - info: caso contrário
    """
    text = "\n".join(lines).lower()
    high_keys = ["vulnerable", "sql injection", "directory traversal", "remote file inclusion", "rfi", "lfi", "command injection"]
    if any(k in text for k in high_keys):
        return "high"
    if any(ln.strip().startswith("+ ") for ln in lines):
        return "medium"
    return "info"

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/nikto_scan.json:
    {
      "timeout": 900,               # tempo total da execução
      "port": null,                 # porta explícita (opcional)
      "ssl": null,                  # força -ssl (True/False) ou deixa Nikto inferir (None)
      "tuning": "",                 # códigos Nikto Tuning (ex.: "x 1 2 3" ou "bde")
      "plugins": "",                # lista de plugins (ex.: "apache_expect_xss")
      "headers": { "User-Agent": "Mozilla/5.0" },
      "nointeractive": true,        # evita prompt interativo
      "useragent": null             # define -useragent explicitamente
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 900))
    port = cfg.get("port", None)
    ssl = cfg.get("ssl", None)
    tuning = cfg.get("tuning") or ""
    plugins = cfg.get("plugins") or ""
    headers = cfg.get("headers") or {}
    nointeractive = bool(cfg.get("nointeractive", True))
    useragent = cfg.get("useragent", None)

    info = _nikto_info()
    if not info["path"]:
        txt = "Nikto não encontrado no PATH (Kali: apt-get install nikto)."
        item = {
            "plugin_uuid": UUID_NIKTO,
            "scan_item_uuid": UUID_NIKTO,
            "result": txt,
            "analysis_ai": ai_fn("NiktoScan", UUID_NIKTO, txt),
            "severity": "info",
            "duration": 0.0,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": "Nikto Web Server Scan",
            "command": ""
        }
        return {
            "plugin": "NiktoScan",
            "plugin_uuid": UUID_NIKTO,
            "file_name": "nikto_scan.py",
            "description": "Integração com Nikto para varredura de servidor web (misconfigs, exposições, vulnerabilidades conhecidas).",
            "category": "Dynamic Scanning",
            "result": [item]
        }

    comps = _build_target_components(target, port, ssl)
    cmd_str = _build_nikto_command(
        nikto_path=info["path"],
        target=comps["host_for_nikto"],
        port=comps["port"],
        ssl=comps["ssl"],
        tuning=tuning,
        plugins=plugins,
        headers=headers,
        nointeractive=nointeractive,
        useragent=useragent
    )

    with Timer() as t:
        out = _safe_run(["bash", "-lc", cmd_str], timeout=timeout)

    parsed = _parse_nikto_output(out)
    severity = _severity_from_findings(parsed)

    # Evidência com versão e caminho do Nikto
    header_lines = [f"Ferramenta: {info['path']}", f"Versão: {info['version'] or 'N/D'}"]
    res = "\n".join("- " + ln for ln in header_lines + parsed)

    item = {
        "plugin_uuid": UUID_NIKTO,
        "scan_item_uuid": UUID_NIKTO,
        "result": res,
        "analysis_ai": ai_fn("NiktoScan", UUID_NIKTO, res),
        "severity": severity,
        "duration": t.duration,
        "auto": True,
        "reference": REFERENCE_URL,
        "item_name": "Nikto Web Server Scan",
        "command": cmd_str
    }

    return {
        "plugin": "NiktoScan",
        "plugin_uuid": UUID_NIKTO,
        "file_name": "nikto_scan.py",
        "description": "Varredura de servidor web com Nikto (detecção de misconfigurações e vetores comuns), com saída padronizada.",
        "category": "Dynamic Scanning",
        "result": [item]
    }