# plugins/storage_bucket_probe.py
"""
Plugin: storage_bucket_probe
Objetivo:
  - Tentar descobrir buckets / storage públicos (S3, GCS, Azure) a partir de nomes candidatos.
  - Registra os comandos executados em `command`.
  - Gera itens quando heurísticas indicam possível bucket público.
Config (opcional): configs/storage_bucket_probe.json
{
  "timeout": 15,
  "candidates": ["media","static","assets","uploads"],
  "providers": ["s3","gcs","azure"],
  "extra": []
}
"""
import re
import time
from typing import Dict, Any, List, Optional

PLUGIN_CONFIG_NAME = "storage_bucket_probe"
PLUGIN_CONFIG_ALIASES = ["bucket_probe", "obj_storage"]
UUID_018 = "uuid-018-storage"  # (18) Buckets/storage expostos

# === injected: capture executed shell commands for tagging ===
try:
    from utils import run_cmd as __run_cmd_orig, Timer as __Timer_orig, extrair_host as __extrair_host_orig
except Exception:
    __run_cmd_orig = None
    __Timer_orig = None
    __extrair_host_orig = None

EXEC_CMDS: List[str] = []

def run_cmd(cmd, timeout=None):
    """
    Wrapper para capturar o comando usado em EXEC_CMDS.
    Mantém compatibilidade com utils.run_cmd quando disponível,
    caso contrário usa subprocess como fallback.
    """
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    EXEC_CMDS.append(cmd_str)
    if __run_cmd_orig is None:
        import subprocess
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

# extrair_host fallback (mantém comportamento esperado)
def _extrair_host_fallback(target: str) -> str:
    try:
        # trata urls e hosts simples
        if "://" not in target:
            # permite passar host:port ou host
            host = target.split("/")[0]
        else:
            from urllib.parse import urlparse
            host = urlparse(target).hostname or target
        return str(host).split(":")[0]
    except Exception:
        return target

extrair_host = __extrair_host_orig or _extrair_host_fallback
# === end injected ===

def _try(url: str, timeout: int) -> str:
    """
    Usa curl via run_cmd. Limita a leitura para as primeiras linhas.
    Mantive head -n 60 para não puxar conteúdo massivo.
    """
    # montar comando como lista para run_cmd registrar corretamente
    cmd = ["bash", "-lc", f'curl -sSL -m {int(timeout)} "{url}" | head -n 60']
    return run_cmd(cmd, timeout=timeout + 2) or ""

def build_item(uuid: str, result_text: str, severity: str, duration: float, ai_fn, item_name: str) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": result_text,
        "analysis_ai": ai_fn(PLUGIN_CONFIG_NAME, uuid, result_text) if callable(ai_fn) else None,
        "severity": severity,
        "duration": duration,
        "auto": True,
        "item_name": item_name,
        "command": EXEC_CMDS[-1] if EXEC_CMDS else ""
    }

def run_plugin(target: str, ai_fn, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    run_plugin(target, ai_fn, cfg)
    cfg:
      - timeout: int
      - candidates: list[str]
      - providers: list[str]  # subset of ["s3","gcs","azure"]
      - extra: list[str]      # urls extras
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 15))
    cands = cfg.get("candidates") or ["media", "static", "assets", "uploads"]
    provs = cfg.get("providers") or ["s3", "gcs", "azure"]
    extra = cfg.get("extra") or []

    domain = extrair_host(target)

    patterns: List[str] = []
    for c in cands:
        if "s3" in provs:
            patterns += [f"https://{c}.{domain}.s3.amazonaws.com/", f"http://{c}.{domain}.s3.amazonaws.com/"]
        if "gcs" in provs:
            patterns += [f"https://storage.googleapis.com/{c}.{domain}/", f"https://{c}.{domain}.storage.googleapis.com/"]
        if "azure" in provs:
            # tentativa simples; fabricantes/nomes podem variar — mantenha heurística
            patterns += [f"https://{c}{domain.replace('.','')}.blob.core.windows.net/", f"https://{c}.blob.core.windows.net/"]
    patterns += extra

    evid: List[str] = []
    hits = 0
    with Timer() as t:
        # limitar para evitar loop infinito quando listas grandes
        for u in patterns[:50]:
            try:
                body = _try(u, timeout).lower()
            except Exception as e:
                body = f"[ERRO] {e}"
            if not body:
                continue
            # heurísticas comuns para buckets públicos / respostas XML dos serviços
            if any(k in body for k in ["<listbucketresult", "<listbucket", "xml", "accessdenied", "allaccessdisabled", "blobserviceclient", "no such bucket", "<error>"]):
                hits += 1
                snippet = re.sub(r"\s+", " ", body)[:400]
                evid.append(f"{u} :: {snippet}")

    severity = "low" if hits else "info"
    duration = getattr(t, "duration", 0.0)
    items: List[Dict[str, Any]] = []

    if hits:
        txt = "Buckets/storage possivelmente expostos detectados:\n" + "\n".join(f"- {e}" for e in evid)
        items.append(build_item(UUID_018, txt, severity, duration, ai_fn, f"Storage buckets for {domain}"))
    else:
        # Para consistência com seu último pedido: quando não há hits, retornamos result vazio.
        items = []

    return {
        "plugin": PLUGIN_CONFIG_NAME,
        "plugin_uuid": UUID_018,
        "file_name": "storage_bucket_probe.py",
        "description": "Verifica possíveis buckets/obj storage públicos (S3/GCS/Azure) com base em candidatos e provedores. Registra comando usado em `command`.",
        "category": "Information Gathering",
        "result": items
    }
