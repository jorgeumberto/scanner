# plugins/jwt_check.py
import base64
import json
import re
from typing import Dict, Any, List, Tuple
from utils import run_cmd as _run_cmd_shadow, Timer

# === injected: capture executed shell commands for tagging ===
try:
    from utils import run_cmd as __run_cmd_orig  # keep original
except Exception as _e_inject:
    __run_cmd_orig = None

EXEC_CMDS = []  # type: list[str]

def run_cmd(cmd, timeout=None):
    """
    Wrapper injected to capture the exact command used.
    Keeps the original behavior, but records the command string.
    """
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    EXEC_CMDS.append(cmd_str)
    if __run_cmd_orig is None:
        raise RuntimeError("run_cmd original não disponível para execução.")
    return __run_cmd_orig(cmd, timeout=timeout)
# === end injected ===


PLUGIN_CONFIG_NAME = "jwt_check"
PLUGIN_CONFIG_ALIASES = ["jwt", "jwt_security"]

UUID_046 = "uuid-046-jwt-check"  # Item 46: JWT seguro (alg!=none, exp/iat/aud/iss)

JWT_RE = re.compile(r"eyJ[0-9A-Za-z_\-]+=*\.[0-9A-Za-z_\-]+=*\.[0-9A-Za-z_\-]+=*", re.ASCII)

def _curl_headers(url: str, timeout: int, headers: List[str]) -> str:
    cmd = ["curl", "-sS", "-i", "-m", str(timeout), url]
    for h in headers or []:
        cmd += ["-H", h]
    return run_cmd(cmd, timeout=timeout+2)

def _b64json(b64: str) -> Dict[str, Any]:
    try:
        # pad base64url
        pad = '=' * (-len(b64) % 4)
        dec = base64.urlsafe_b64decode(b64 + pad)
        return json.loads(dec.decode("utf-8", errors="ignore"))
    except Exception:
        return {}

def _analyze_token(tok: str) -> Tuple[str, str]:
    """
    Retorna (resumo, severity) para um token
    Heurísticas:
      - alg == none -> high
      - sem exp -> medium
      - sem iss/aud -> low
      - tip: exp no passado -> medium
    """
    try:
        h_b64, p_b64, s_b64 = tok.split(".", 2)
    except ValueError:
        return ("Token inválido (formato)", "low")

    head = _b64json(h_b64)
    payl = _b64json(p_b64)

    alg = (head.get("alg") or "").upper()
    typ = (head.get("typ") or "")

    probs = []
    severity = "info"

    if alg == "NONE":
        probs.append("alg=none")
        severity = "high"

    if "exp" not in payl:
        probs.append("exp ausente")
        severity = "medium" if severity != "high" else "high"
    else:
        try:
            import time as _time
            if int(payl["exp"]) < int(_time.time()):
                probs.append("exp expirado")
                severity = "medium" if severity != "high" else "high"
        except Exception:
            pass

    if "iss" not in payl or "aud" not in payl:
        probs.append("iss/aud ausentes")
        if severity not in ("high", "medium"):
            severity = "low"

    parts = [f"alg={alg or '?'}", f"typ={typ or '?'}"]
    for k in ("iss", "aud", "sub"):
        if k in payl:
            parts.append(f"{k}={payl[k]}")

    if probs:
        parts.append("⚠ " + ", ".join(probs))
    else:
        parts.append("OK (requisitos básicos presentes)")

    return ("; ".join(parts), severity)

def _summarize(lines: List[str], checklist_name: str, max_lines: int = 12) -> str:
    if not lines:
        return f"Nenhum achado para {checklist_name}"
    body = [f"- {l}" for l in lines[:max_lines]]
    extra = len(lines) - len(body)
    if extra > 0:
        body.append(f"... +{extra} tokens")
    return "\n".join(body)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/jwt_check.json):
    {
      "timeout": 20,
      "tokens": [],                     # tokens JWT brutos para analisar
      "endpoints": ["/api/me"],         # endpoints para tentar coletar JWT via Set-Cookie/Authorization
      "headers": ["Authorization: Bearer EXEMPLO"],  # se necessário
      "absolute_only": false
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    tokens = cfg.get("tokens") or []
    endpoints = cfg.get("endpoints") or []
    headers = cfg.get("headers") or []
    absolute_only = bool(cfg.get("absolute_only", False))

    # 1) coleta de tokens a partir de endpoints (opcional)
    with Timer() as t_collect:
        for ep in endpoints:
            if ep.startswith("http://") or ep.startswith("https://"):
                url = ep
            else:
                if absolute_only:
                    continue
                url = target.rstrip("/") + "/" + ep.lstrip("/")
            out = _curl_headers(url, timeout, headers)
            # tenta pegar JWT em Set-Cookie / Authorization
            for ln in out.splitlines():
                m = JWT_RE.search(ln)
                if m:
                    tokens.append(m.group(0))
    # 2) análise
    summaries: List[str] = []
    worst = "info"
    with Timer() as t_an:
        for tok in tokens:
            s, sev = _analyze_token(tok)
            summaries.append(s)
            # aglutina pior severidade
            if sev == "high":
                worst = "high"
            elif sev == "medium" and worst != "high":
                worst = "medium"
            elif sev == "low" and worst not in ("high", "medium"):
                worst = "low"
    duration = round(t_collect.duration + t_an.duration, 3)

    checklist = "JWT seguro (alg!=none, exp/iat/aud/iss)"
    result = _summarize(summaries, checklist)

    return {
        "plugin": "JWTSecurity",
        "file_name": "jwt_check.py",
        "description": "Check for common JWT security issues.",
        "category": "Configuration and Deployment Management",
        "result": [{
            "plugin_uuid": UUID_046,
            "scan_item_uuid": UUID_046,
            "result": result,
            "analysis_ai": ai_fn("JWTSecurity", UUID_046, result),
            "severity": worst if summaries else "info",
            "duration": duration,
            "auto": True,
            "reference": "https://auth0.com/docs/security/tokens/json-web-tokens/json-web-token-best-practices",
            "item_name": checklist,
            "command": EXEC_CMDS[-1] if EXEC_CMDS else "",

        }]
    }
