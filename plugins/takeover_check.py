# plugins/takeover_check.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer, extrair_host

PLUGIN_CONFIG_NAME = "takeover_check"
PLUGIN_CONFIG_ALIASES = ["subtakeover", "takeover"]

UUID_016 = "uuid-016"  # (16) Tomada de subdomínio

FINGERPRINTS = [
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

def _dig_cname(host: str, timeout: int) -> str:
    out = run_cmd(["dig", "+short", host, "CNAME"], timeout=timeout)
    return out.strip().split("\n")[0] if out.strip() else ""

def _curl_body(url: str, timeout: int) -> str:
    return run_cmd(["curl", "-sS", "-L", "-m", str(timeout), url], timeout=timeout+2)

def _check_finger(cname: str, body: str) -> Tuple[bool, str]:
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

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/takeover_check.json):
    {
      "timeout": 20,
      "hosts": [],                      # subdomínios (strings). Se vazio, tenta guesses.
      "guess_from_target": true,        # se true e hosts vazio, testa <www|dev|staging|test|blog|cdn|assets>.<domain>
      "paths": ["/", "/index.html"],    # caminhos para GET
      "only_https": false
    }
    """
    cfg = cfg or {}
    timeout     = int(cfg.get("timeout", 20))
    hosts       = cfg.get("hosts") or []
    guess       = bool(cfg.get("guess_from_target", True))
    paths       = cfg.get("paths") or ["/"]
    only_https  = bool(cfg.get("only_https", False))

    domain = extrair_host(target) or target
    if not hosts and guess and domain:
        hosts = [f"{p}.{domain}" for p in ["www","dev","staging","test","blog","cdn","assets"]]

    evid: List[str] = []
    worst = "info"

    with Timer() as t:
        if not hosts:
            evid.append("Sem hosts para verificar (configure 'hosts' no JSON ou habilite 'guess_from_target').")
        else:
            for h in hosts:
                cname = _dig_cname(h, timeout=3)
                had_match = False  # marca se achamos takeover para esse host

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
                        break  # próximo host

                if not had_match:
                    # registrar uma evidência neutra por host, pra ficar claro que foi checado
                    if cname:
                        evid.append(f"{h} :: CNAME={cname} | sem fingerprint de takeover nas URLs testadas")
                    else:
                        evid.append(f"{h} :: sem CNAME | sem fingerprint de takeover nas URLs testadas")

    duration = t.duration
    result = _summarize(evid, "Tomada de subdomínio (CNAME órfão)")

    return {
        "plugin": "TakeoverCheck",
        "result": [{
            "plugin_uuid": UUID_016,
            "scan_item_uuid": UUID_016,
            "result": result,
            "analysis_ai": ai_fn("TakeoverCheck", UUID_016, result),
            "severity": worst,
            "duration": duration,
            "auto": True
        }]
    }
