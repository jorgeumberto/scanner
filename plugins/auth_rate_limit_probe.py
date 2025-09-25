# plugins/auth_rate_limit_probe.py
from typing import Dict, Any
from utils import run_cmd, Timer
from urllib.parse import urlencode

PLUGIN_CONFIG_NAME = "auth_rate_limit_probe"
PLUGIN_CONFIG_ALIASES = ["rl_auth"]
UUID_063 = "uuid-063-bruteforce-limit"  # (63) Brute Force Protection
UUID_084 = "uuid-084-rate-limit"        # (84) Rate Limit Probe Details

def _post(url: str, data: Dict[str, str], timeout: int) -> str:
    """
    Retorna HEADERS + BODY (-i) em minúsculas, para facilitar busca por 'retry-after'.
    """
    form = urlencode(data)
    # -sS: silencioso com erros; -i: inclui cabeçalhos; -m: timeout; --data: formulário
    return run_cmd(
        ["bash", "-lc", f'curl -sS -i -m {timeout} -X POST --data "{form}" "{url}"'],
        timeout=timeout + 2
    ).lower()

def _extract_http_code(raw: str) -> str:
    """
    Pega o primeiro código HTTP encontrado nas linhas que começam com 'HTTP/'.
    Nota: pode haver múltiplas linhas (redirects, etc.).
    """
    for ln in raw.splitlines():
        if ln.startswith("http/"):  # já está em lower()
            parts = ln.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return parts[1]
    return "?"

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (exemplo):
    {
      "timeout": 15,
      "login_url":"http://localhost:8080/auth-test.php",
      "user_field":"username",
      "pass_field":"password",
      "user":"admin",
      "tries":6,
      "sleep":0,
      "severity_if_vulnerable":"medium"  # ou "high"
    }
    """
    cfg         = cfg or {}
    timeout     = int(cfg.get("timeout", 15))
    url         = target + "/admin/auth_rl.php"
    uf          = cfg.get("user_field", "username")
    pf          = cfg.get("pass_field", "password")
    user        = cfg.get("user", "admin")
    tries       = max(2, int(cfg.get("tries", 6)))
    slp         = int(cfg.get("sleep", 0))
    sev_vuln    = cfg.get("severity_if_vulnerable", "medium")

    evid = []
    hits_protection = 0  # conta 429 ou retry-after

    with Timer() as t:
        for i in range(tries):
            raw = _post(url, {uf: user, pf: "WrongPass!234"}, timeout)
            code = _extract_http_code(raw)
            has_retry = ("retry-after" in raw)
            if code == "429" or has_retry:
                hits_protection += 1
            evid.append(f"tentativa {i+1}: http {code}" + (" (retry-after)" if has_retry else ""))

            if slp:
                run_cmd(["bash", "-lc", f"sleep {slp}"], timeout=slp + 1)

    # Lógica de severidade:
    # - Se houve 429/retry-after em alguma tentativa => há sinal de proteção -> info
    # - Se NÃO houve nenhum 429/retry-after => vulnerável (sem rate-limit/lockout evidente) -> medium/high
    if hits_protection == 0:
        sev_63 = sev_vuln
        res63 = (
            f"Sem evidência de rate limit/lockout após {tries} tentativas consecutivas de login falho."
            f"Isto indica vulnerabilidade a brute force."
        )
    else:
        sev_63 = "info"
        res63 = (
            f"Foram observados sinais de proteção ({hits_protection} ocorrência(s) de 429/Retry-After) "
            f"durante {tries} tentativas. O endpoint aparenta ter algum rate limit/lockout."
        )

    res84 = "Detalhes das tentativas:\n" + "\n".join(f"- {e}" for e in evid)

    return {
        "plugin": "AuthRateLimitProbe",
        "plugin_uuid": "auth_rate_limit_probe-001",
        "file_name": "auth_rate_limit_probe.py",
        "description": "Probes for authentication rate limiting by sending multiple failed login attempts.",
        "category": "Brute Force Protection",
        "result": [
            {
                "scan_item_uuid": UUID_063,
                "result": res63,
                "analysis_ai": ai_fn("AuthRateLimitProbe", UUID_063, res63),
                "severity": sev_63,
                "duration": t.duration,
                "auto": True,
                "reference": "https://owasp.org/www-project-top-ten/2017/A02_2021-Cryptographic_Failures",  # pode ajustar
                "item_name": "Brute Force Protection"
            },
            {
                "scan_item_uuid": UUID_084,
                "result": res84,
                "analysis_ai": ai_fn("AuthRateLimitProbe", UUID_084, res84),
                "severity": "info",
                "duration": t.duration,
                "auto": True,
                "reference": "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                "item_name": "Rate Limit Probe Details"
            }
        ]
    }
