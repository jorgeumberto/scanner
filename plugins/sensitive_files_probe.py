# plugins/sensitive_files_probe.py
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "sensitive_files_probe"
PLUGIN_CONFIG_ALIASES = ["files_probe", "sensitive_files"]

UUID_030 = "uuid-030-env"  # ENV/propriedades sensíveis não expostas
UUID_028 = "uuid-028-sensitive-logs"  # Logs sensíveis
UUID_003 = "uuid-003-files"  # Arquivos comuns expostos
UUID_004 = "uuid-004-sensitive-files"  # Arquivos sensíveis expostos

DEFAULT_PATHS = [
  "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
  "/config.php", "/config.yaml", "/config.yml",
  "/backup.zip", "/db.sql", "/database.sql", "/dump.sql",
  "/robots.txt", "/sitemap.xml", "/humans.txt", "/security.txt",
  "/logs/access.log", "/logs/error.log", "/storage/logs/laravel.log"
]

def _head_status(url: str, timeout: int) -> str:
    raw = run_cmd(["curl", "-sS", "-I", "-L", "-m", str(timeout), url], timeout=timeout+2)
    for ln in raw.splitlines():
        if ln.upper().startswith("HTTP/"):
            return ln.strip()
    return "HTTP/??"

def _get_body(url: str, timeout: int) -> str:
    return run_cmd(["curl", "-sS", "-L", "-m", str(timeout), url], timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg:
    { "timeout": 20, "paths": [ ... ] }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 20))
    paths   = cfg.get("paths") or DEFAULT_PATHS

    evid_env, evid_logs, evid_common, evid_sensitive = [], [], [], []

    with Timer() as t:
        for p in paths:
            url = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            st  = _head_status(url, timeout)
            if "200" in st or "206" in st:
                body = _get_body(url, timeout)[:400].lower()
                # classificação bem simples
                if p in ["/robots.txt", "/sitemap.xml", "/humans.txt", "/security.txt"]:
                    evid_common.append(f"{p} :: {st}")
                elif any(k in p for k in [".env",".git","config","backup","db.sql","dump.sql",".svn"]):
                    evid_sensitive.append(f"{p} :: {st}")
                elif "log" in p:
                    evid_logs.append(f"{p} :: {st}")
                # detecção textual extra de env/log
                if "app_key" in body or "database" in body or "password" in body:
                    evid_sensitive.append(f"{p} :: conteúdo aparenta credenciais (trecho: ...{body[:80]}...)")
                if "exception" in body or "trace" in body:
                    evid_logs.append(f"{p} :: conteúdo aparenta stack trace/log (trecho: ...{body[:80]}...)")

    # severidades
    sev030 = "info" if not evid_sensitive else "high"
    sev028 = "info" if not evid_logs else "medium"
    sev003 = "info" if not evid_common else "low"
    sev004 = "info" if not evid_sensitive else "high"

    def _mk(uuid, name, evid, sev):
        txt = "\n".join(f"- {e}" for e in evid) if evid else f"Nenhum achado para {name}"
        return {
            "plugin_uuid": uuid,
            "scan_item_uuid": uuid,
            "result": txt,
            "analysis_ai": ai_fn("SensitiveFilesProbe", uuid, txt),
            "severity": sev,
            "duration": t.duration,
            "auto": True
        }

    items = [
        _mk(UUID_030, "Ambiente/propriedades sensíveis (ENV)", evid_sensitive, sev030),
        _mk(UUID_028, "Logs sensíveis públicos", evid_logs, sev028),
        _mk(UUID_003, "Arquivos comuns expostos", evid_common, sev003),
        _mk(UUID_004, "Arquivos sensíveis expostos", evid_sensitive, sev004),
    ]
    return {"plugin": "SensitiveFilesProbe", "result": items}
