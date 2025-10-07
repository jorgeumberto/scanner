# plugins/whatweb_fingerprint.py
import json
import os
import re
import tempfile
from typing import Dict, Any, List

from utils import run_cmd, Timer

# Ajuda o main dinâmico a achar configs/whatweb.json
PLUGIN_CONFIG_NAME = "whatweb"
PLUGIN_CONFIG_ALIASES = ["whatweb_fingerprint"]

# UUID placeholder — troque pelo UUID real do item 7 (Fingerprints de tecnologias)
UUID_7 = "uuid-007-fingerprints"

def _run_whatweb_json(target: str, timeout: int, aggression: int, user_agent: str,
                      follow_redirects: bool, plugins: List[str], extra_args: List[str]) -> Dict[str, Any]:
    """
    Executa whatweb com saída JSON. Muitas builds exigem escrever em arquivo (--log-json).
    Retorna dict com o JSON do WhatWeb ou {} se falhar.
    """
    with tempfile.TemporaryDirectory() as td:
        out_path = os.path.join(td, "whatweb.json")

        cmd = ["whatweb", target, "-a", str(aggression)]
        if follow_redirects:
            cmd += ["--follow-redirect"]
        if user_agent:
            cmd += ["--user-agent", user_agent]
        if plugins:
            # aceita lista de plugins (ex.: ["Apache","PHP","jQuery"])
            cmd += ["--plugins", ",".join(plugins)]
        if extra_args:
            cmd += extra_args

        # saída JSON para arquivo
        cmd += ["--log-json", out_path]

        _ = run_cmd(cmd, timeout=timeout)

        try:
            with open(out_path, "r") as f:
                # algumas versões escrevem múltiplas linhas; pegar a primeira JSON válida
                content = f.read().strip()
                if not content:
                    return {}
                # arquivo pode ter várias linhas JSON; tente carregar a última linha não vazia
                lines = [ln for ln in content.splitlines() if ln.strip()]
                for ln in reversed(lines):
                    try:
                        return json.loads(ln)
                    except Exception:
                        continue
                return {}
        except Exception:
            return {}

def _fallback_parse_text(raw: str) -> List[Dict[str, str]]:
    """
    Parser best-effort para quando não há JSON:
    Exemplo de linha WhatWeb:
      http://site [200 OK] Country[UNITED STATES][US], HTTPServer[nginx/1.19.0], PHP[5.6.40], jQuery[1.12.4]
    Retorna lista de dicts: [{"name":"HTTPServer","version":"nginx/1.19.0"}, ...]
    """
    results: List[Dict[str, str]] = []
    if not raw:
        return results

    # pega tudo depois do primeiro ']' (depois de [200 OK])
    parts = raw.split("]", 1)
    tail = parts[1] if len(parts) > 1 else raw

    # separa por vírgulas principais
    tokens = [t.strip() for t in tail.split(",") if t.strip()]
    for tok in tokens:
        # formato comum: Name[value] ou Name[value][extra]
        m = re.match(r"([A-Za-z0-9\-\_]+)\[(.*?)\]", tok)
        if m:
            name = m.group(1)
            value = m.group(2)
            # tenta separar versão no value (ex.: nginx/1.19.0 ou PHP 5.6.40)
            ver = None
            if "/" in value:
                ver = value
            else:
                m2 = re.search(r"\b\d+(\.\d+){1,3}\b", value)
                if m2:
                    ver = m2.group(0)
            results.append({"name": name, "version": ver or value})
    return results

def _summarize(entries: List[Dict[str, str]], checklist_name: str, max_lines: int = 8) -> str:
    """Resumo com mensagem contextual."""
    if not entries:
        return f"Nenhum achado para {checklist_name}"
    lines = []
    for e in entries[:max_lines]:
        nm = e.get("name", "?")
        ver = e.get("version", "")
        lines.append(f"- {nm}" + (f" ({ver})" if ver else ""))
    extra = len(entries) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} tecnologias")
    return "\n".join(lines)

def _heuristic_severity(entries: List[Dict[str, str]]) -> str:
    """
    Heurística leve para elevar de 'info' para 'low' se detectar algo potencialmente defasado:
      - php/5.x
      - apache/2.2
      - jquery 1.x
    Nada definitivo (é só para chamar atenção).
    """
    text = " ".join([(e.get("name","") + " " + (e.get("version","") or "")) for e in entries]).lower()

    patterns = [
        r"php[/\s]?5\.",         # PHP 5.x
        r"apache[/\s]?2\.2",     # Apache 2.2
        r"jquery[/\s]?1\.",      # jQuery 1.x
        r"openssl[/\s]?1\.0\.1"  # OpenSSL 1.0.1 (heartbleed era)
    ]
    for pat in patterns:
        if re.search(pat, text):
            return "low"
    return "info"

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/whatweb.json:
    {
      "timeout": 120,
      "aggression": 3,               # 1 a 4
      "user_agent": "Pentest-Auto/1.0",
      "follow_redirects": true,
      "plugins": [],                 # ex.: ["Apache","PHP","jQuery","WordPress"]
      "extra_args": []               # quaisquer flags extras suportadas pelo WhatWeb
    }
    """
    cfg = cfg or {}
    timeout          = int(cfg.get("timeout", 120))
    aggression       = int(cfg.get("aggression", 3))
    user_agent       = cfg.get("user_agent", "Pentest-Auto/1.0")
    follow_redirects = bool(cfg.get("follow_redirects", True))
    plugins          = cfg.get("plugins") or []
    extra_args       = cfg.get("extra_args") or []

    # -- Verificação: whatweb instalado? --
    try:
        which_out = run_cmd(["which", "whatweb"], timeout=5)
    except Exception:
        which_out = ""

    if not which_out or not which_out.strip():
        # Retorna um item informando a ausência do whatweb, sem executar nada.
        items = [{
            "plugin_uuid": UUID_7,
            "scan_item_uuid": UUID_7,
            "result": "whatweb não encontrado no PATH. Instale o whatweb para usar este plugin.",
            "analysis_ai": ai_fn("WhatWeb", "uuid-whatweb-missing", "whatweb não encontrado"),
            "severity": "info",
            "duration": 0,
            "auto": True,
            "command": "which whatweb",
            "reference": "https://github.com/urbanadventurer/WhatWeb"
        }]
        return {
            "plugin": "WhatWeb",
            "plugin_uuid": "uuid-whatweb",
            "file_name": "whatweb_fingerprint.py",
            "description": "Fingerprinting de tecnologias usando WhatWeb (verifica se whatweb está instalado antes de executar).",
            "category": "Fingerprinting",
            "result": items
        }

    items: List[Dict[str, Any]] = []

    # 1) tenta JSON
    with Timer() as t_json:
        data = _run_whatweb_json(
            target=target,
            timeout=timeout,
            aggression=aggression,
            user_agent=user_agent,
            follow_redirects=follow_redirects,
            plugins=plugins,
            extra_args=extra_args
        )
    duration = t_json.duration

    detections: List[Dict[str, str]] = []
    if data:
        # Estrutura comum do JSON do WhatWeb (pode variar por versão):
        # {"target":"...", "plugins":[{"name":"HTTPServer","version":"nginx/1.19.0","string":"..."}, ...]}
        plugs = data.get("plugins") or []
        for p in plugs:
            name = p.get("name") or ""
            version = p.get("version") or p.get("string") or ""
            if name:
                detections.append({"name": name, "version": version})
    else:
        # 2) fallback para saída texto direta (sem JSON)
        with Timer() as t_txt:
            raw = run_cmd(["whatweb", target, "-a", str(aggression)], timeout=timeout)
        duration = max(duration, t_txt.duration)
        detections = _fallback_parse_text(raw)

    # resultado único (ID 7)
    friendly_label = "Fingerprints de tecnologias"
    result_text = _summarize(detections, friendly_label)
    severity = _heuristic_severity(detections) if detections else "info"

    items.append({
        "plugin_uuid": UUID_7,
        "scan_item_uuid": UUID_7,
        "result": result_text,
        "analysis_ai": ai_fn("WhatWeb", UUID_7, result_text),
        "severity": severity,
        "duration": duration,
        "auto": True
    })

    return {
        "plugin": "WhatWeb",
        "plugin_uuid": "uuid-whatweb",
        "file_name": "whatweb_fingerprint.py",
        "description": "Fingerprinting de tecnologias usando WhatWeb.",
        "category": "Fingerprinting",
        "result": items
    }
