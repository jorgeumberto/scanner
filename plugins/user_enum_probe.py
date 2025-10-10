# plugins/user_enum_probe.py
import os
from typing import Dict, Any, List
from utils import run_cmd, Timer
from urllib.parse import urlencode

PLUGIN_CONFIG_NAME = "user_enum_probe"
PLUGIN_CONFIG_ALIASES = ["user_enum","login_enum"]

UUID_061 = "uuid-061-user-enum"  # (61) Enumeração de usuários

REFERENCE_URL = "https://owasp.org/www-community/attacks/Account_Enumeration"

def _post(url: str, data: Dict[str,str], headers: Dict[str,str], timeout: int) -> str:
    hdrs = []
    for k,v in headers.items():
        hdrs += ["-H", f"{k}: {v}"]
    form = urlencode(data)
    # Retorna headers (-i) + corpo, com follow redirects (-L)
    return run_cmd(
        ["bash","-lc", f'curl -sS -L -m {timeout} {" ".join(hdrs)} -X POST --data "{form}" "{url}" -i'],
        timeout=timeout+2
    )

def _build_command_template(url: str, timeout: int, headers: Dict[str,str], user_field: str, pass_field: str) -> str:
    """
    Constrói um comando cURL reprodutível (template) com placeholders:
      {USERNAME} substitui o candidato.
    """
    hdrs = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
    return (
        f'curl -sS -L -m {timeout} {hdrs} -X POST '
        f'--data "{user_field}={{USERNAME}}&{pass_field}=invalidPass123!" '
        f'"{url}" -i'
    ).strip()

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):

    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    url     = os.getenv("TARGET_LOGIN")
    uf      = cfg.get("user_field","username")
    pf      = cfg.get("pass_field","password")
    like_ok = [s.lower() for s in (cfg.get("valid_like")  or ["exists","reset sent","found"])]
    like_no = [s.lower() for s in (cfg.get("invalid_like") or ["not found","unknown","inexistente"])]
    headers = cfg.get("headers") or {}
    cands   = cfg.get("candidates") or ["admin","test","user@example.com"]

    if not url:
        txt = "Config ausente: login_url."
        item = {
            "plugin_uuid": UUID_061,
            "scan_item_uuid": UUID_061,
            "result": txt,
            "analysis_ai": ai_fn("UserEnumProbe", UUID_061, txt),
            "severity": "info",
            "duration": 0.0,
            "auto": True,
            "reference": REFERENCE_URL,
            "item_name": "User Enumeration Probe",
            "command": ""
        }
        return {
            "plugin": "UserEnumProbe",
            "plugin_uuid": UUID_061,
            "file_name": "user_enum_probe.py",
            "description": "Probes login endpoint for user enumeration via response content differences.",
            "category": "Authentication",
            "result": [item]
        }

    evid: List[str] = []
    leaks = 0
    neg_or_amb = 0
    neutral = 0

    with Timer() as t:
        for u in cands:
            body = _post(url, {uf: u, pf: "invalidPass123!"}, headers, timeout).lower()
            if any(x in body for x in like_ok) and not any(x in body for x in like_no):
                leaks += 1
                evid.append(f"{u}: resposta sugere existência do usuário")
            elif any(x in body for x in like_no):
                neg_or_amb += 1
                evid.append(f"{u}: resposta nega/ambígua")
            else:
                neutral += 1
                evid.append(f"{u}: resposta neutra/ambígua")

    sev = "medium" if leaks else "info"

    # Resumo + evidências
    summary = f"Resumo: leaks={leaks}, nega/ambígua={neg_or_amb}, neutra/ambígua={neutral}"
    txt = "\n".join(["- " + summary] + [f"- {e}" for e in evid])

    # Comando template reprodutível (com placeholder {USERNAME})
    command = _build_command_template(url, timeout, headers, uf, pf)

    item = {
        "plugin_uuid": UUID_061,
        "scan_item_uuid": UUID_061,
        "result": txt,
        "analysis_ai": ai_fn("UserEnumProbe", UUID_061, txt),
        "severity": sev,
        "duration": t.duration,
        "auto": True,
        "reference": REFERENCE_URL,
        "item_name": "User Enumeration Probe",
        "command": command
    }

    return {
        "plugin": "UserEnumProbe",
        "plugin_uuid": UUID_061,
        "file_name": "user_enum_probe.py",
        "description": "Probes login endpoint for user enumeration via response content differences.",
        "category": "Authentication",
        "result": [item]
    }