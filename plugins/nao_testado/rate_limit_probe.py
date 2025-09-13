# plugins/rate_limit_probe.py
from typing import Dict, Any, List
import time
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "rate_limit_probe"
PLUGIN_CONFIG_ALIASES = ["ratelimit", "rl_probe"]

UUID_84 = "uuid-084"  # Rate limiting aplicado a endpoints sensíveis

def _curl_status(url: str, timeout: int, headers: List[str]) -> str:
    # retorna somente código HTTP e headers relevantes
    cmd = ["curl", "-sS", "-o", "/dev/null", "-D", "-", "-m", str(timeout), "-w", "%{http_code}", url]
    for h in headers or []:
        cmd += ["-H", h]
    return run_cmd(cmd, timeout=timeout+2)

def _parse_http_code(output: str) -> int:
    # último token costuma ser o código do -w %{http_code}
    try:
        tail = output.strip().splitlines()[-1]
        return int(tail)
    except Exception:
        return 0

def _has_header(output: str, name: str) -> bool:
    for ln in output.splitlines():
        if ln.lower().startswith(name.lower() + ":"):
            return True
    return False

def _get_header(output: str, name: str) -> str:
    for ln in output.splitlines():
        if ln.lower().startswith(name.lower() + ":"):
            return ln.split(":", 1)[1].strip()
    return ""

def _summarize(entries: List[str], checklist_name: str, max_lines: int = 30) -> str:
    if not entries:
        return f"Nenhum achado para {checklist_name}"
    body = [f"- {e}" for e in entries[:max_lines]]
    extra = len(entries) - len(body)
    if extra > 0:
        body.append(f"... +{extra} evidências")
    return "\n".join(body)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/rate_limit_probe.json):
    {
      "timeout": 10,
      "paths": ["/api/login", "/api/reset", "/api/otp"],
      "requests_per_path": 20,
      "sleep_between": 0.0,
      "headers": ["Authorization: Bearer test", "X-API-Key: testkey"],
      "treat_429_as_ok": true
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 10))
    paths = cfg.get("paths") or ["/api/login"]
    requests_per_path = int(cfg.get("requests_per_path", 20))
    sleep_between = float(cfg.get("sleep_between", 0.0))
    headers = cfg.get("headers") or []
    treat_429_as_ok = bool(cfg.get("treat_429_as_ok", True))

    evidences: List[str] = []
    worst = "info"

    with Timer() as t:
        for path in paths:
            url = target.rstrip("/") + "/" + path.lstrip("/")
            codes = []
            got_429 = False
            rl_hdr = ""
            for i in range(requests_per_path):
                out = _curl_status(url, timeout, headers)
                code = _parse_http_code(out)
                codes.append(code)
                if code == 429:
                    got_429 = True
                    rl_hdr = _get_header(out, "Retry-After") or _get_header(out, "X-RateLimit-Remaining")
                    break
                if sleep_between > 0:
                    time.sleep(sleep_between)

            if got_429:
                msg = f"{url} :: 429 recebido após {len(codes)} requisições" + (f" | hint: {rl_hdr}" if rl_hdr else "")
                evidences.append(msg)
                if treat_429_as_ok:
                    # 429 é desejável: mostra que há rate limiting
                    worst = "info" if worst != "high" else worst
                else:
                    worst = "low" if worst not in ("high", "medium") else worst
            else:
                # sem 429: pode indicar ausência de rate limit
                last = codes[-1] if codes else 0
                evidences.append(f"{url} :: nenhum 429 após {len(codes)} requisições (último={last})")
                worst = "medium" if worst != "high" else worst

    duration = t.duration
    checklist = "Rate limiting aplicado a endpoints sensíveis"
    result = _summarize(evidences, checklist)

    return {
        "plugin": "RateLimitProbe",
        "result": [{
            "plugin_uuid": UUID_84,
            "scan_item_uuid": UUID_84,
            "result": result,
            "analysis_ai": ai_fn("RateLimitProbe", UUID_84, result),
            "severity": worst,
            "duration": duration,
            "auto": True
        }]
    }
