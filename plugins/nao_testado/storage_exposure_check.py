# plugins/storage_exposure_check.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer, extrair_host
import re

PLUGIN_CONFIG_NAME = "storage_exposure_check"
PLUGIN_CONFIG_ALIASES = ["buckets", "s3", "gcs", "azureblob"]

# >>> troque pelo UUID real do item (18)
UUID_018 = "uuid-018"

S3_PATTERNS = [
    "s3.amazonaws.com",
    ".s3.amazonaws.com",
    ".s3-website",
]
GCS_PATTERNS = [
    "storage.googleapis.com",
    ".storage.googleapis.com"
]
AZ_PATTERNS = [
    "blob.core.windows.net"
]

def _curl(url: str, timeout: int) -> str:
    # segue redirects e não imprime progresso
    return run_cmd(["curl", "-sS", "-L", "-m", str(timeout), url], timeout=timeout+2)

def _looks_public_listing(body: str) -> bool:
    b = body.lower()
    # heurísticas básicas de XML/JSON listagem
    return any(sig in b for sig in [
        "<listbucketresult", "<blobs>", "<enumerationresults", "\"is_truncated\"", "\"contents\""
    ])

def _exists_but_denied(body: str) -> bool:
    b = body.lower()
    # mensagens comuns que indicam bucket existente sem listagem
    return any(sig in b for sig in [
        "accessdenied", "authorizationheaderisinvalid", "anonymous caller does not have storage.objects.list",
        "resource not found", "this request is not authorized"
    ])

def _mk_candidates(domain: str) -> List[str]:
    # derive nomes simples: foo, foo-static, static-foo, cdn-foo, files-foo, foo-prod, foo-staging
    base = domain.split(".")[0]
    seeds = [
        base, f"{base}-static", f"static-{base}", f"cdn-{base}", f"files-{base}",
        f"{base}-prod", f"{base}-staging", f"{base}-assets", f"assets-{base}"
    ]
    # endpoints canônicos
    cands = []
    for name in seeds:
        cands.append(f"https://{name}.s3.amazonaws.com")
        cands.append(f"https://{name}.s3.amazonaws.com/?list-type=2")
        cands.append(f"https://storage.googleapis.com/{name}")
        cands.append(f"https://storage.googleapis.com/{name}/?prefix=")
        cands.append(f"https://{name}.blob.core.windows.net")
        cands.append(f"https://{name}.blob.core.windows.net/?comp=list")
    return list(dict.fromkeys(cands))

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/storage_exposure_check.json):
    {
      "timeout": 20,
      "extra_urls": [
        "https://meu-bucket.s3.amazonaws.com",
        "https://storage.googleapis.com/minha-cdn",
        "https://minhaconta.blob.core.windows.net/meucontainer?comp=list"
      ]
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    extra  = cfg.get("extra_urls") or []

    domain = extrair_host(target) or target
    urls = _mk_candidates(domain) + extra

    evid: List[str] = []
    worst = "info"

    with Timer() as t:
        for u in urls:
            body = _curl(u, timeout)
            if not body:
                continue
            if _looks_public_listing(body):
                evid.append(f"{u} :: listagem/objetos públicos visíveis")
                worst = "high"
            elif _exists_but_denied(body):
                evid.append(f"{u} :: bucket/existe sem listagem (AccessDenied/sem permissão)")
                if worst != "high":
                    worst = "medium"

    summary = "\n".join(f"- {e}" for e in evid) if evid else "Nenhum achado para buckets/storage expostos"
    item = {
        "plugin_uuid": UUID_018,
        "scan_item_uuid": UUID_018,
        "result": summary,
        "analysis_ai": ai_fn("StorageExposureCheck", UUID_018, summary),
        "severity": worst,
        "duration": t.duration,
        "auto": True
    }

    return {
        "plugin": "StorageExposureCheck",
        "result": [item]
    }
