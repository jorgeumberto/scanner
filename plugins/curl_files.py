from typing import Dict, Any, List, Tuple
from urllib.parse import urljoin
from utils import run_cmd
import time

# ---------- helpers ----------

def safe_join(base: str, path: str) -> str:
    if not base.endswith('/'):
        base = base + '/'
    if path.startswith('/'):
        path = path[1:]
    return urljoin(base, path)

def fetch_status(url: str, max_time: int = 10) -> int:
    """
    Retorna o código HTTP sem baixar corpo.
    -L segue redirecionamentos; -k evita falhar com cert self-signed.
    """
    out = run_cmd([
        "curl", "-sSL", "-k", "-o", "/dev/null",
        "-w", "%{http_code}",
        "--max-time", str(max_time),
        url
    ], timeout=max_time + 5).strip()
    try:
        return int(out)
    except Exception:
        return 0  # erro/timeout/transporte

def exists_by_status(code: int) -> bool:
    # Considera existente se 200/401/403 (acessível ou presente porém restrito)
    return code in (200, 401, 403)

def sev_for_status(code: int, high_if_200=True, medium_if_restricted=True) -> str:
    if code == 200:
        return "high" if high_if_200 else "medium"
    if code in (401, 403):
        return "medium" if medium_if_restricted else "info"
    return "info"

def build_item(uuid: str, msg: str, severity: str, duration: float, ai_fn) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": msg,
        "analysis_ai": ai_fn("curl_files", uuid, msg),
        "severity": severity,
        "duration": duration,
        "auto": True,
        "file_name": "curl_files.py",
        "description": "Usa curl para baixar arquivos específicos de um servidor web e verificar sua existência.",
    }

def check_one(base: str, path: str, motivo_ok: str, motivo_risco_200: str, motivo_risco_restr: str,
              high_if_200=True, medium_if_restricted=True) -> Tuple[str, str, str]:
    """
    Retorna (url, mensagem, severidade) para um único caminho.
    """
    url = safe_join(base, path)
    code = fetch_status(url)
    if exists_by_status(code):
        if code == 200:
            sev = sev_for_status(code, high_if_200=high_if_200, medium_if_restricted=medium_if_restricted)
            return url, f"{url} — HTTP {code} — Risco: {motivo_risco_200}", sev
        else:  # 401/403
            sev = sev_for_status(code, high_if_200=high_if_200, medium_if_restricted=medium_if_restricted)
            return url, f"{url} — HTTP {code} — Risco: {motivo_risco_restr}", sev
    return url, f"{url} — HTTP {code} — Seguro: {motivo_ok}", "info"

def check_many(base: str, paths: List[str], motivo_ok: str, motivo_risco_200: str, motivo_risco_restr: str,
               high_if_200=True, medium_if_restricted=True) -> Tuple[bool, str, str]:
    hits, sev_top = [], "info"
    for p in paths:
        _, msg, sev = check_one(base, p, motivo_ok, motivo_risco_200, motivo_risco_restr,
                                high_if_200=high_if_200, medium_if_restricted=medium_if_restricted)
        if "— Risco:" in msg:
            hits.append(msg)
            if sev == "high":
                sev_top = "high"
            elif sev == "medium" and sev_top != "high":
                sev_top = "medium"
    if hits:
        return True, " | ".join(hits), sev_top
    # nenhum encontrado → mensagem única de OK
    return False, f"Não encontrado(s) — Seguro: {motivo_ok}", "info"

# ---------- plugin ----------

def run_plugin(target: str, ai_fn) -> Dict[str, Any]:
    t0 = time.time()
    items: List[Dict[str, Any]] = []

    # 101) Diretórios comuns (200 sugere listagem/índice acessível)
    dirs = ["", "uploads/", "files/", "backup/", "backups/", "logs/", "tmp/", "images/"]
    found, msg, sev = check_many(
        target, dirs,
        motivo_ok="diretórios não expostos",
        motivo_risco_200="diretório responde 200 (potencial listagem/índice acessível)",
        motivo_risco_restr="diretório existe mas restrito (401/403)"
    )
    items.append(build_item("uuid-101-dir-listing", msg, "high" if found else "info", time.time()-t0, ai_fn))

    # 102) .git/HEAD
    _, msg, sev = check_one(
        target, ".git/HEAD",
        motivo_ok=".git não exposto",
        motivo_risco_200=".git acessível (metadados e histórico podem vazar)",
        motivo_risco_restr=".git presente porém restrito (existe no docroot)"
    )
    items.append(build_item("uuid-102-git-exposed", msg, sev, time.time()-t0, ai_fn))

    # 103) .env
    _, msg, sev = check_one(
        target, ".env",
        motivo_ok=".env não exposto",
        motivo_risco_200=".env acessível (segredos/credenciais podem vazar)",
        motivo_risco_restr=".env presente porém restrito (indica arquivo sensível no docroot)"
    )
    items.append(build_item("uuid-103-env-exposed", msg, sev, time.time()-t0, ai_fn))

    # 104) /server-status
    # Qualquer existência importa; se 200 → medium; se 401/403 → medium (revelação parcial)
    _, msg_auto, sev_auto = check_one(
        target, "server-status?auto",
        motivo_ok="server-status ausente",
        motivo_risco_200="Apache status exposto (informações operacionais)",
        motivo_risco_restr="Apache status presente porém restrito"
    )
    _, msg_plain, sev_plain = check_one(
        target, "server-status",
        motivo_ok="server-status ausente",
        motivo_risco_200="Apache status exposto (informações operacionais)",
        motivo_risco_restr="Apache status presente porém restrito"
    )
    sev = "high" if ("— Risco:" in msg_auto and sev_auto == "high") or ("— Risco:" in msg_plain and sev_plain == "high") else ("medium" if ("— Risco:" in msg_auto or "— Risco:" in msg_plain) else "info")
    msg = " | ".join(m for m in [msg_auto, msg_plain] if m)
    items.append(build_item("uuid-104-server-status-open", msg, "medium" if "— Risco:" in msg else "info", time.time()-t0, ai_fn))

    # 105) phpinfo.php / info.php / test.php
    found, msg, sev = check_many(
        target, ["phpinfo.php", "info.php", "test.php"],
        motivo_ok="arquivos de diagnóstico não expostos",
        motivo_risco_200="arquivo de diagnóstico acessível (vaza versão/paths/extensões)",
        motivo_risco_restr="arquivo presente porém restrito"
    )
    items.append(build_item("uuid-105-phpinfo-exposed", msg, "medium" if found else "info", time.time()-t0, ai_fn))

    # 106) Arquivos de backup comuns
    found, msg, sev = check_many(
        target, ["index.php~", "index.php.bak", "config.php~", "config.php.bak",
                 "wp-config.php.bak", "settings.py~", "local.settings.php", "web.config.bak"],
        motivo_ok="backups não expostos",
        motivo_risco_200="backup acessível",
        motivo_risco_restr="backup presente porém restrito"
    )
    items.append(build_item("uuid-106-backup-files", msg, "high" if found else "info", time.time()-t0, ai_fn))

    # 107) Dumps e pacotes comuns
    found, msg, sev = check_many(
        target, ["backup.zip", "backup.tar.gz", "site.tar.gz",
                 "dump.sql", "db.sql", "database.sql", "backup.sql", "dump.tar.gz"],
        motivo_ok="dumps/arquivos não expostos",
        motivo_risco_200="dump/pacote acessível",
        motivo_risco_restr="dump/pacote presente porém restrito"
    )
    items.append(build_item("uuid-107-archives-dumps", msg, "high" if found else "info", time.time()-t0, ai_fn))

    # 108) .DS_Store
    _, msg, sev = check_one(
        target, ".DS_Store",
        motivo_ok=".DS_Store não exposto",
        motivo_risco_200=".DS_Store acessível (pode revelar estrutura de diretórios)",
        motivo_risco_restr=".DS_Store presente porém restrito"
    )
    items.append(build_item("uuid-108-dsstore-exposed", msg, "low" if "— Risco:" in msg else "info", time.time()-t0, ai_fn))

    # 109) .svn/entries
    _, msg, sev = check_one(
        target, ".svn/entries",
        motivo_ok=".svn não exposto",
        motivo_risco_200=".svn/entries acessível (metadados e paths do repositório)",
        motivo_risco_restr=".svn presente porém restrito"
    )
    items.append(build_item("uuid-109-svn-entries", msg, "medium" if "— Risco:" in msg else "info", time.time()-t0, ai_fn))

    # 110) Arquivos de manifesto/lock (exposição informacional)
    found, msg, sev = check_many(
        target, ["composer.json", "composer.lock", "package.json", "yarn.lock", "pnpm-lock.yaml"],
        motivo_ok="manifests/locks não expostos",
        motivo_risco_200="manifest/lock acessível (exposição de dependências/versões)",
        motivo_risco_restr="manifest/lock presente porém restrito",
        high_if_200=False,  # tratar como informacional/medium
        medium_if_restricted=True
    )
    items.append(build_item("uuid-110-package-files", msg, ("medium" if found else "info"), time.time()-t0, ai_fn))

    # 111) robots.txt (informativo)
    _, msg, _ = check_one(
        target, "robots.txt",
        motivo_ok="arquivo não presente; opcional",
        motivo_risco_200="arquivo presente (normal; pode listar rotas públicas)",
        motivo_risco_restr="arquivo presente porém restrito"
    )
    # robots não é risco por si só
    items.append(build_item("uuid-111-robots", msg.replace("— Risco:", "— Info:"), "info", time.time()-t0, ai_fn))

    # 112) sitemap.xml / sitemap_index.xml (informativo)
    found, msg, sev = check_many(
        target, ["sitemap.xml", "sitemap_index.xml"],
        motivo_ok="sitemap ausente; opcional",
        motivo_risco_200="sitemap presente (normal; indica URLs públicas para crawlers)",
        motivo_risco_restr="sitemap presente porém restrito"
    )
    # sitemap também não é risco por si só
    msg = msg.replace("— Risco:", "— Info:")
    items.append(build_item("uuid-112-sitemap", msg, "info", time.time()-t0, ai_fn))

    return {"plugin": "curl_files", "result": items}
