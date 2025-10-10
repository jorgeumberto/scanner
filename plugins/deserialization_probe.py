# plugins/deserialization_probe.py
from typing import Dict, Any, Optional
from utils import run_cmd, Timer
import base64
import re
import json

PLUGIN_CONFIG_NAME = "deserialization_probe"
PLUGIN_CONFIG_ALIASES = ["insecure_deser"]
UUID_057 = "uuid-057-deserialization"  # (57)

REFERENCE_URL = "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"

# POC base (inócua) codificada em base64 para vetores que esperam strings seguras
POC = base64.b64encode(b"test-object").decode()

MAX_SNIPPET = 800  # limite de evidência retornada
DEFAULT_TIMEOUT = 12

def _parse_http_status(raw: str) -> Optional[int]:
    """
    Lê a primeira linha de status HTTP (após -i/-I) e extrai o código.
    Suporta múltiplos blocos (redirects). Usa o último status encontrado.
    """
    codes = []
    for line in raw.splitlines():
        m = re.match(r"^HTTP/\d\.\d\s+(\d{3})\b", line.strip(), re.IGNORECASE)
        if m:
            try:
                codes.append(int(m.group(1)))
            except Exception:
                pass
    return codes[-1] if codes else None

def _has_echo(raw: str, token: str) -> bool:
    # heurística simples de eco do valor injetado
    tok = token.strip()
    if not tok:
        return False
    return tok in raw

def _has_deser_indicators(raw: str) -> bool:
    """
    Indicadores comuns de desserialização/exceções em diversas stacks.
    (Heurístico leve — não envia payloads perigosos.)
    """
    patterns = [
        r"Deserializ", r"Serialization", r"ObjectInputStream", r"InvalidClassException",
        r"StreamCorruptedException", r"NotSerializableException", r"readObject",
        r"__wakeup", r"unserialize", r"TypeConfusion", r"BinaryFormatter",
        r"ISerializable", r"Marshal", r"YAML\.load", r"pickle", r"binascii\.Error",
        r"messagepack", r"kryo"
    ]
    blob = raw[:4096]  # limitar busca
    return any(re.search(p, blob, re.IGNORECASE) for p in patterns)

def _build_command(url: str, timeout: int, mode: str, header_name: str, param_name: str, cookie_name: str, poc_value: str) -> str:
    base = f'curl -sS -L -m {timeout} -i'
    if mode == "header":
        return f'{base} -H "{header_name}: {poc_value}" "{url}"'
    elif mode == "cookie":
        return f'{base} -H "Cookie: {cookie_name}={poc_value}" "{url}"'
    elif mode == "query":
        sep = "&" if "?" in url else "?"
        return f'{base} "{url}{sep}{param_name}={poc_value}"'
    elif mode == "json":
        data = json.dumps({param_name: poc_value})
        return f"{base} -H 'Content-Type: application/json' --data '{data}' '{url}'"
    else:
        # fallback para header
        return f'{base} -H "{header_name}: {poc_value}" "{url}"'

def _run_probe(url: str, timeout: int, mode: str, header_name: str, param_name: str, cookie_name: str, poc_value: str) -> str:
    cmd = _build_command(url, timeout, mode, header_name, param_name, cookie_name, poc_value)
    # Executa via bash -lc para preservar aspas corretamente
    raw = run_cmd(["bash", "-lc", cmd], timeout=timeout + 2)
    return raw

def _classify_severity(status: Optional[int], raw: str, poc_value: str) -> str:
    """
    Heurística de severidade:
      - high: eco claro do valor + status 2xx; ou indicadores fortes de desserialização com 2xx
      - medium: indicadores de desserialização (erros/mensagens) sem 2xx, mas com resposta processada (ex.: 4xx/5xx com stack hints)
      - low: 2xx/3xx sem indicadores; ou eco sem 2xx
      - info: ausência de sinais
    """
    echo = _has_echo(raw, poc_value)
    deser = _has_deser_indicators(raw)
    is_2xx = status is not None and 200 <= status < 300
    is_3xx = status is not None and 300 <= status < 400
    is_4xx5xx = status is not None and status >= 400

    if (echo and is_2xx) or (deser and is_2xx):
        return "high"
    if deser and is_4xx5xx:
        return "medium"
    if is_2xx or is_3xx or echo:
        return "low"
    return "info"

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg: {
      "enabled": false,
      "timeout": 12,
      "endpoint": "/api/deserialize",
      "header_name": "X-Serialized",
      "param_name": "data",
      "cookie_name": "serialized",
      "poc": "<custom-base64-or-string>"
    }
    """
    cfg = cfg or {}

    if not bool(cfg.get("enabled", False)):
        txt = "Desabilitado (defina enabled=true e endpoint/mode para executar o probe)."
        item = {
            "plugin_uuid": UUID_057,
            "scan_item_uuid": UUID_057,
            "result": txt,
            "analysis_ai": ai_fn("DeserializationProbe", UUID_057, txt),
            "severity": "info",
            "duration": 0.0,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": "Insecure Deserialization Probe",
            "command": ""
        }
        return {
            "plugin": "DeserializationProbe",
            "plugin_uuid": UUID_057,
            "file_name": "deserialization_probe.py",
            "description": "Lightweight probe for insecure deserialization indicators via multiple vectors (header, cookie, query, JSON).",
            "category": "Server-Side Testing",
            "result": [item]
        }

    timeout = int(cfg.get("timeout", DEFAULT_TIMEOUT))
    endpoint = cfg.get("endpoint", "/api/deserialize")
    url = target.rstrip("/") + endpoint

    # Vetor padrão e parâmetros configuráveis
    header_name = cfg.get("header_name", "X-Serialized")
    param_name = cfg.get("param_name", "data")
    cookie_name = cfg.get("cookie_name", "serialized")
    poc_value = str(cfg.get("poc", POC))

    command = _build_command(url, timeout, mode, header_name, param_name, cookie_name, poc_value)

    with Timer() as t:
        raw = _run_probe(url, timeout, mode, header_name, param_name, cookie_name, poc_value)

    status = _parse_http_status(raw)
    sev = _classify_severity(status, raw, poc_value)

    # Evidência recortada: cabeçalhos + parte do corpo (limite)
    snippet = raw[:MAX_SNIPPET] if raw else "Sem resposta"

    item = {
        "plugin_uuid": UUID_057,
        "scan_item_uuid": UUID_057,
        "result": snippet,
        "analysis_ai": ai_fn("DeserializationProbe", UUID_057, snippet),
        "severity": sev,
        "duration": t.duration,
        "auto": True,
        "reference": REFERENCE_URL,
        "item_name": "Insecure Deserialization Probe",
        "command": command
    }

    return {
        "plugin": "DeserializationProbe",
        "plugin_uuid": UUID_057,
        "file_name": "deserialization_probe.py",
        "description": "Lightweight probe for insecure deserialization indicators via multiple vectors (header, cookie, query, JSON).",
        "category": "Server-Side Testing",
        "result": [item]
    }