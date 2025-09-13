# plugins/headers_policies.py
from typing import Dict, Any, List, Tuple
from urllib.parse import urljoin
from utils import run_cmd, Timer

# Localização automática do config
PLUGIN_CONFIG_NAME = "headers_policies"
PLUGIN_CONFIG_ALIASES = ["referrer_permissions", "cache_headers"]

# UUIDs placeholders — troque pelos reais
UUID_21 = "uuid-021"  # Cache-Control/Pragma p/ conteúdo sensível
UUID_29 = "uuid-029"  # Referrer-Policy / Permissions-Policy

SENSITIVE_HINTS = [
    "login", "signin", "account", "profile", "checkout", "cart", "payment",
    "admin", "reset", "2fa", "mfa", "settings", "invoice", "token"
]

def _curl_head(url: str, timeout: int) -> str:
    # -sS silencioso com erros, -I HEAD, -L segue redirect, -m timeout
    return run_cmd(["curl", "-sS", "-I", "-L", "-m", str(timeout), url], timeout=timeout+2)

def _parse_header(raw: str, name: str) -> str:
    for ln in raw.splitlines():
        if ln.lower().startswith(name.lower() + ":"):
            return ln.split(":", 1)[1].strip()
    return ""

def _is_sensitive_path(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in SENSITIVE_HINTS)

def _summarize(lines: List[str], checklist_name: str, max_lines: int = 20) -> str:
    if not lines:
        return f"Nenhum achado para {checklist_name}"
    body = [f"- {l}" for l in lines[:max_lines]]
    extra = len(lines) - len(body)
    if extra > 0:
        body.append(f"... +{extra} evidências")
    return "\n".join(body)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/headers_policies.json):
    {
      "timeout": 20,
      "paths": ["/", "/login", "/account", "/checkout"],   # onde validar
      "extra_urls": [],                                     # URLs completas adicionais
      "treat_all_as_sensitive": false                       # se true, aplica regra "sensível" a todos
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    paths = cfg.get("paths") or ["/", "/login", "/account"]
    extra_urls = cfg.get("extra_urls") or []
    treat_all_as_sensitive = bool(cfg.get("treat_all_as_sensitive", False))

    urls: List[str] = [urljoin(target.rstrip("/") + "/", p.lstrip("/")) for p in paths]
    urls += extra_urls

    evid_cache: List[str] = []   # Item 21
    evid_policy: List[str] = []  # Item 29

    with Timer() as t:
        for u in urls:
            try:
                hdrs = _curl_head(u, timeout)
            except Exception:
                continue

            cc  = _parse_header(hdrs, "Cache-Control")
            pg  = _parse_header(hdrs, "Pragma")
            rp  = _parse_header(hdrs, "Referrer-Policy")
            pp  = _parse_header(hdrs, "Permissions-Policy")  # (ex-Feature-Policy)

            # ---- Item 21: Cache headers para conteúdo sensível ----
            is_sensitive = treat_all_as_sensitive or _is_sensitive_path(u)
            if is_sensitive:
                # Recomendação típica: Cache-Control: no-store, no-cache, must-revalidate; Pragma: no-cache
                miss_parts = []
                if not cc:
                    miss_parts.append("Cache-Control ausente")
                else:
                    low = cc.lower()
                    if "no-store" not in low:
                        miss_parts.append("no-store ausente")
                    if "no-cache" not in low:
                        miss_parts.append("no-cache ausente")
                    if "must-revalidate" not in low and "private" not in low:
                        miss_parts.append("must-revalidate/private ausente")
                if not pg:
                    miss_parts.append("Pragma ausente (no-cache)")

                if miss_parts:
                    evid_cache.append(f"{u} :: {', '.join(miss_parts)}")
                else:
                    evid_cache.append(f"{u} :: cache adequado ({cc}; Pragma: {pg or '—'})")

            # ---- Item 29: Referrer-Policy / Permissions-Policy ----
            pol_parts = []
            if not rp:
                pol_parts.append("Referrer-Policy ausente")
            else:
                # valores razoáveis: no-referrer, same-origin, strict-origin(-when-cross-origin)
                pol_parts.append(f"Referrer-Policy: {rp}")
            if not pp:
                pol_parts.append("Permissions-Policy ausente")
            else:
                pol_parts.append(f"Permissions-Policy: {pp}")

            evid_policy.append(f"{u} :: " + " | ".join(pol_parts))

    duration = t.duration

    # Severidades (simples): ausência em rotas sensíveis = medium; presença com valores ruins = low; ok = info
    sev21 = "info"
    if any("ausente" in e for e in evid_cache):
        sev21 = "medium"

    sev29 = "info"
    if any("ausente" in e for e in evid_policy):
        sev29 = "low"

    res21 = _summarize(evid_cache, "Cache-Control/Pragma para conteúdo sensível")
    res29 = _summarize(evid_policy, "Headers Referrer-Policy / Permissions-Policy")

    return {
        "plugin": "HeadersPolicies",
        "result": [
            {
                "plugin_uuid": UUID_21,
                "scan_item_uuid": UUID_21,
                "result": res21,
                "analysis_ai": ai_fn("HeadersPolicies", UUID_21, res21),
                "severity": sev21,
                "duration": duration,
                "auto": True
            },
            {
                "plugin_uuid": UUID_29,
                "scan_item_uuid": UUID_29,
                "result": res29,
                "analysis_ai": ai_fn("HeadersPolicies", UUID_29, res29),
                "severity": sev29,
                "duration": duration,
                "auto": True
            }
        ]
    }
