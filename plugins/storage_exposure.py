# plugins/storage_exposure.py
import re
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer, extract_host

PLUGIN_CONFIG_NAME = "storage_exposure"
PLUGIN_CONFIG_ALIASES = ["s3", "gcs", "azure_blob"]

UUID_18 = "uuid-018"  # Exposição de buckets/storage (S3/GCS/Azure Blob)

def _mk_candidates(domain: str) -> List[str]:
    """
    Gera nomes de bucket candidatos a partir do domínio.
    ex.: app.example.com -> ["app-example", "example", "example-com", "app", "appexample"]
    """
    d = domain.lower()
    parts = d.split(".")
    base = parts[-2] if len(parts) >= 2 else d
    tld = parts[-1] if len(parts) >= 1 else ""
    subs = parts[:-2] if len(parts) > 2 else []

    cands = set()
    cands.add(base)
    cands.add(f"{base}-{tld}")
    if subs:
        cands.add(subs[-1])
        cands.add(f"{subs[-1]}-{base}")
        cands.add(f"{subs[-1]}{base}")
    cands.add(d.replace(".", "-"))
    cands.add(d.replace(".", ""))

    # limpa
    out = sorted({re.sub(r"[^a-z0-9\-]", "", x) for x in cands if x})
    return out

def _http_head(url: str, timeout: int) -> str:
    return run_cmd(["curl", "-sS", "-I", "-m", str(timeout), url], timeout=timeout+2)

def _http_get(url: str, timeout: int) -> str:
    return run_cmd(["curl", "-sS", "-m", str(timeout), url], timeout=timeout+2)

def _probe_s3(bucket: str, timeout: int) -> Tuple[str, str]:
    # HEAD no endpoint virtual-host e GET em listing (antigo estilo path)
    urls = [
        f"http://{bucket}.s3.amazonaws.com/",
        f"https://{bucket}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket}"
    ]
    for u in urls:
        head = _http_head(u, timeout)
        if "200 OK" in head or "403 Forbidden" in head or "404 Not Found" in head:
            body = _http_get(u, timeout)
            return u, (head + "\n" + body)
    return "", ""

def _probe_gcs(bucket: str, timeout: int) -> Tuple[str, str]:
    urls = [
        f"https://storage.googleapis.com/{bucket}",
        f"https://{bucket}.storage.googleapis.com/"
    ]
    for u in urls:
        head = _http_head(u, timeout)
        if any(code in head for code in ["200 OK", "403 Forbidden", "404 Not Found"]):
            body = _http_get(u, timeout)
            return u, (head + "\n" + body)
    return "", ""

def _probe_azure(bucket: str, timeout: int) -> Tuple[str, str]:
    urls = [
        f"https://{bucket}.blob.core.windows.net/?comp=list"
    ]
    for u in urls:
        head = _http_head(u, timeout)
        if any(code in head for code in ["200 OK", "403 Forbidden", "404 Not Found"]):
            body = _http_get(u, timeout)
            return u, (head + "\n" + body)
    return "", ""

def _analyze_response(provider: str, url: str, resp: str) -> Tuple[str, str]:
    """
    Retorna (status_humano, severity)
      - listing público (200 + XML de listagem) -> high
      - AccessDenied/AuthorizationRequired -> baixo (existe, mas protegido)
      - NoSuchBucket/ResourceNotFound -> info
    """
    low = resp.lower()
    if not resp:
        return "sem resposta", "info"

    if "200 ok" in low:
        # heurística: se tem XML de listing
        if "<listbucketresult" in low or "<enumerateresponse" in low or "<blobs>" in low:
            return f"LISTAGEM PÚBLICA: {url}", "high"
        # alguns buckets requerem auth mas retornam 200 com HTML — marca como low
        return f"acesso potencial (verificar): {url}", "low"

    if "403 forbidden" in low or "accessdenied" in low or "authorizationrequired" in low:
        return f"existe mas protegido: {url}", "info"

    if "404 not found" in low or "nosuchbucket" in low or "resourcenotfound" in low:
        return f"não encontrado: {url}", "info"

    return f"indeterminado ({url})", "info"

def _summarize(entries: List[str], checklist_name: str, max_lines: int = 20) -> str:
    if not entries:
        return f"Nenhum achado para {checklist_name}"
    lines = [f"- {e}" for e in entries[:max_lines]]
    extra = len(entries) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} evidências")
    return "\n".join(lines)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/storage_exposure.json):
    {
      "timeout": 30,
      "providers": ["s3","gcs","azure"],
      "candidates": [],                  # se quiser forçar nomes
      "limit_candidates": 20
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 30))
    providers = cfg.get("providers") or ["s3", "gcs", "azure"]
    domain = extract_host(target)
    candidates = cfg.get("candidates") or _mk_candidates(domain)
    limit = int(cfg.get("limit_candidates", 20))
    if limit and len(candidates) > limit:
        candidates = candidates[:limit]

    evidences: List[str] = []
    worst_sev = "info"

    with Timer() as t:
        for cand in candidates:
            for prov in providers:
                try:
                    if prov == "s3":
                        url, resp = _probe_s3(cand, timeout)
                    elif prov == "gcs":
                        url, resp = _probe_gcs(cand, timeout)
                    elif prov == "azure":
                        url, resp = _probe_azure(cand, timeout)
                    else:
                        continue
                    if not url:
                        continue
                    label, sev = _analyze_response(prov, url, resp)
                    evidences.append(label)
                    # prioriza severidades
                    if sev == "high":
                        worst_sev = "high"
                    elif sev == "low" and worst_sev != "high":
                        worst_sev = "low"
                except Exception:
                    continue
    duration = t.duration

    checklist = "Exposição de buckets/storage (S3/GCS/Azure Blob)"
    result = _summarize(evidences, checklist)

    return {
        "plugin": "StorageExposure",
        "result": [{
            "plugin_uuid": UUID_18,
            "scan_item_uuid": UUID_18,
            "result": result,
            "analysis_ai": ai_fn("StorageExposure", UUID_18, result),
            "severity": worst_sev,
            "duration": duration,
            "auto": True
        }]
    }
