# plugins/open_redirect_probe.py
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
import itertools
import os

from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "open_redirect_probe"

UUID_35 = "uuid-035-open_redirect_probe"  # Redirecionamento aberto ausente/presente

COMMON_PARAMS = [
    "next", "url", "redirect", "return", "continue", "dest", "destination",
    "redir", "goto", "target", "r", "u", "back", "to"
]

COMMON_PATHS = [
    "/", "/login", "/logout", "/signin", "/redirect", "/out"
]

EXTERNAL_TEST = os.getenv("TARGET", "http://example.com")

def _build_tests(base_url: str, params: List[str], paths: List[str],
                 extra_params: List[str], extra_paths: List[str]) -> List[str]:
    tests: List[str] = []
    P = params + (extra_params or [])
    S = paths + (extra_paths or [])
    base = base_url.rstrip("/")
    for pth, prm in itertools.product(S, P):
        url = f"{base}{pth}"
        sep = "&" if "?" in url else "?"
        tests.append(f"{url}{sep}{prm}={EXTERNAL_TEST}")
    return tests

# -------- helpers de comando/exec --------
def _curl_cmd_args(url: str, timeout: int) -> List[str]:
    # não seguir redirecionamentos: queremos inspecionar Location
    return ["curl", "-sS", "-I", "-m", str(timeout), url]

def _curl_cmd_str(url: str, timeout: int) -> str:
    return " ".join(_curl_cmd_args(url, timeout))

def _head(url: str, timeout: int) -> str:
    # não seguir redirecionamentos: queremos inspecionar Location
    return run_cmd(_curl_cmd_args(url, timeout), timeout=timeout + 2)

def _parse_location(raw_headers: str) -> str:
    for ln in raw_headers.splitlines():
        if ln.lower().startswith("location:"):
            return ln.split(":", 1)[1].strip()
    return ""

def _summarize(findings: List[str], checklist_name: str, max_lines: int = 20) -> str:
    if not findings:
        return f"Nenhum achado para {checklist_name}"
    lines = [f"- {f}" for f in findings[:max_lines]]
    extra = len(findings) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} parâmetros/rotas vulneráveis")
    return "\n".join(lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/open_redirect.json):
    {
      "timeout": 20,
      "params": ["next","url","redirect","return","continue"],
      "paths": ["/","/login","/redirect"],
      "extra_params": [],
      "extra_paths": [],
      "limit_tests": 150
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    params = cfg.get("params") or COMMON_PARAMS
    paths = cfg.get("paths") or COMMON_PATHS
    extra_params = cfg.get("extra_params") or []
    extra_paths = cfg.get("extra_paths") or []
    limit = int(cfg.get("limit_tests", 150))

    base_url = target
    tests = _build_tests(base_url, params, paths, extra_params, extra_paths)
    if limit and len(tests) > limit:
        tests = tests[:limit]

    vulnerable: List[str] = []
    vuln_cmds: List[str] = []

    with Timer() as t:
        for test_url in tests:
            try:
                hdrs = _head(test_url, timeout)
                loc = _parse_location(hdrs)
                if loc and EXTERNAL_TEST in loc:
                    vulnerable.append(f"{test_url} -> {loc}")
                    vuln_cmds.append(_curl_cmd_str(test_url, timeout))
            except Exception:
                # ignora erros individuais e segue testando os demais
                continue
    duration = t.duration

    checklist = "Redirecionamento aberto (open redirect)"
    if vulnerable:
        severity = "high"
        result = _summarize(vulnerable, checklist)
        command = " ; ".join(vuln_cmds)  # comandos que reproduzem os achados
    else:
        severity = "info"
        result = f"Nenhum achado para {checklist}. Recomanda-se revisão manua com a ferramenta OWASP ZAP ou Burp Suite."
        # comando representativo do primeiro teste (se houver)
        command = _curl_cmd_str(tests[0], timeout) if tests else ""

    return {
        "plugin": "OpenRedirectProbe",
        "result": [{
            "plugin_uuid": UUID_35,
            "scan_item_uuid": UUID_35,
            "result": result,
            "analysis_ai": ai_fn("OpenRedirectProbe", UUID_35, result),
            "severity": severity,
            "duration": duration,
            "auto": True,
            "command": command
        }]
    }
