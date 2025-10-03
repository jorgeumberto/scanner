# plugins/takeover_check.py
"""
Plugin: takeover_check
Objetivo:
  - Detectar possíveis tomadas de subdomínio (subdomain takeover) usando
    heurísticas de CNAME + fingerprinting de providers (GitHub Pages, Heroku, S3, etc).
  - Registra comandos executados em `command`.
  - Retorna item(s) com evidências ou diagnóstico.
Config (opcional) em configs/takeover_check.json:
{
  "timeout": 20,
  "hosts": [],                      # subdomínios (strings). Se vazio, tenta guesses.
  "guess_from_target": true,
  "paths": ["/", "/index.html"],
  "only_https": false
}
"""

import time
import subprocess
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse

PLUGIN_CONFIG_NAME = "takeover_check"
PLUGIN_CONFIG_ALIASES = ["subtakeover", "takeover"]

UUID_016 = "uuid-016-tackover"  # (16) Tomada de subdomínio (subdomain takeover)

FINGERPRINTS: List[Tuple[str, str, str]] = [
    ("GitHub Pages",        "github.io",            "there isn't a github pages site here"),
    ("GitHub Pages CNAME",  "github.io",            "domain does not have a valid cname record"),
    ("AWS S3",              "amazonaws.com",        "nosuchbucket"),
    ("Heroku",              "herokudns.com",        "no such app"),
    ("Heroku",              "herokuapp.com",        "no such app"),
    ("Unbounce",            "unbouncepages.com",    "the requested url was not found on this server"),
    ("Fastly",              "fastly.net",           "fastly error: unknown domain"),
    ("Ghost",               "ghost.io",             "the thing you were looking for is no longer here"),
    ("Squarespace",         "squarespace.com",      "no such account"),
    ("Shopify",             "myshopify.com",        "sorry, this shop is currently unavailable"),
    ("WordPress",           "wordpress.com",        "do you want to register"),
    ("Zendesk",             "zendesk.com",          "help center closed"),
    ("Tumblr",              "domains.tumblr.com",   "there's nothing here"),
    ("Surge",               "surge.sh",             "project not found"),
    ("Cargo",               "cargocollective.com",  "404 not found"),
    ("Webflow",             "proxy-ssl.webflow.com","the site you were looking for couldn't be found"),
    ("Vercel",              "vercel-dns.com",       "this domain is not configured"),
    ("Bitbucket",           "bitbucket.io",         "repository not found"),
]

# === injected: capture executed shell commands for tagging ===
try:
    from utils import run_cmd as __run_cmd_orig, Timer as __Timer_orig, extrair_host as __extrair_host_orig
except Exception:
    __run_cmd_orig = None
    __Timer_orig = None
    __extrair_host_orig = None

EXEC_CMDS: List[str] = []

def run_cmd(cmd, timeout: Optional[int] = None) -> str:
    """
    Wrapper para capturar o comando exato usado.
    Usa utils.run_cmd quando disponível; senão fallback para subprocess.
    """
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    EXEC_CMDS.append(cmd_str)
    if __run_cmd_orig is None:
        try:
            p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=(timeout or 30))
            return (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return f"[ERRO run_cmd-fallback] {e}"
    return __run_cmd_orig(cmd, timeout=timeout)

# Timer fallback
class _SimpleTimer:
    def __enter__(self): 
        self._t0 = time.time()
        return self
    def __exit__(self, exc_type, exc, tb):
        self.duration = time.time() - self._t0

Timer = __Timer_orig or _SimpleTimer

# extract_host fallback (equivalente a extrair_host)
def _extract_host_fallback(target: str) -> str:
    try:
        if "://" not in target:
            target = "//" + target
        p = urlparse(target, allow_fragments=False)
        host = p.hostname or target
        return host.split(":")[0]
    except Exception:
        return target

extract_host = __extrair_host_orig or _extract_host_fallback
# === end injected ===

def _dig_cname(host: str, timeout: int) -> str:
    """
    Consulta CNAME (dig +short <host> CNAME). Usa run_cmd para registrar.
    Retorna primeira linha ou empty string.
    """
    out = run_cmd(["dig", "+short", host, "CNAME"], timeout=timeout)
    lines = (out or "").strip().splitlines()
    return lines[0].strip() if lines else ""

def _curl_body(url: str, timeout: int) -> str:
    """
    Faz GET simples com curl (seguindo redirects). Usa run_cmd para registrar.
    """
    return run_cmd(["curl", "-sS", "-L", "-m", str(timeout), url], timeout=timeout + 2)

def _check_finger(cname: str, body: str) -> Tuple[bool, str]:
    """
    Verifica se o CNAME e o body (resposta HTTP) combinam com fingerprints conhecidas.
    """
    c = (cname or "").lower()
    b = (body or "").lower()
    for prov, frag, sig in FINGERPRINTS:
        if frag in c and sig in b:
            return True, prov
    return False, ""

def _summarize(lines: List[str], checklist: str, max_lines: int = 80) -> str:
    if not lines:
        return f"Nenhum achado para {checklist}"
    body = [f"- {l}" for l in lines[:max_lines]]
    extra = len(lines) - len(body)
    if extra > 0:
        body.append(f"... +{extra} evidências")
    return "\n".join(body)

def build_item(uuid: str, result_text: str, severity: str, duration: float, ai_fn, item_name: str) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": result_text,
        "analysis_ai": ai_fn(PLUGIN_CONFIG_NAME, uuid, result_text) if callable(ai_fn) else None,
        "severity": severity,
        "duration": duration,
        "auto": True,
        "item_name": item_name,
        "command": EXEC_CMDS[:]  # histórico de comandos executados nesta run
    }

def run_plugin(target: str, ai_fn, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    run_plugin(target, ai_fn, cfg)
    cfg (opcional):
      - timeout: int
      - hosts: list[str]
      - guess_from_target: bool
      - paths: list[str]
      - only_https: bool
    """
    cfg = cfg or {}
    timeout    = int(cfg.get("timeout", 20))
    hosts      = cfg.get("hosts") or []
    guess      = bool(cfg.get("guess_from_target", True))
    paths      = cfg.get("paths") or ["/"]
    only_https = bool(cfg.get("only_https", False))

    domain = extract_host(target) or target
    if not hosts and guess and domain:
        hosts = [f"{p}.{domain}" for p in ["www", "dev", "staging", "test", "blog", "cdn", "assets"]]

    evid: List[str] = []
    worst = "info"

    with Timer() as t:
        if not hosts:
            evid.append("Sem hosts para verificar (configure 'hosts' no JSON ou habilite 'guess_from_target').")
        else:
            for h in hosts:
                # consultar CNAME (registro DNS)
                cname = _dig_cname(h, timeout=3)
                had_match = False

                schemes = ["https://"] if only_https else ["https://", "http://"]
                for sc in schemes:
                    for p in paths:
                        url = f"{sc}{h}{p}"
                        body = _curl_body(url, timeout)
                        ok, provider = _check_finger(cname, body)
                        if ok:
                            evid.append(f"{h} :: CNAME={cname or '—'} | Fingerprint TAKEOVER: {provider} | URL: {url}")
                            worst = "high"
                            had_match = True
                            break
                    if had_match:
                        break

                if not had_match:
                    if cname:
                        evid.append(f"{h} :: CNAME={cname} | sem fingerprint de takeover nas URLs testadas")
                    else:
                        evid.append(f"{h} :: sem CNAME | sem fingerprint de takeover nas URLs testadas")

    duration = getattr(t, "duration", 0.0)
    summary = _summarize(evid, "Tomada de subdomínio (CNAME órfão)")

    item = build_item(UUID_016, summary, worst, duration, ai_fn, "Subdomain takeover check")

    return {
        "plugin": "takeover_check",
        "plugin_uuid": UUID_016,
        "file_name": "takeover_check.py",
        "description": "Detecta possíveis tomadas de subdomínio combinando CNAMEs órfãos com fingerprints de provedores (GitHub Pages, Heroku, S3, etc).",
        "category": "Information Gathering",
        "result": [item]
    }
