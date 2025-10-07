# plugins/gobuster_dir.py
"""
Refatorado para ficar no mesmo padrão do plugin `curl_headers`.
- Estrutura de saída consistente (campo `file_name`, `plugin_uuid`, `description`, `category`).
- Helper `make_item` que inclui `command` e usa `ai_fn` para análise.
- Uso de Timer para duração.
- Configurável via `cfg` (mesmo formato esperado no seu exemplo).
- Adicionado: verificação se `gobuster` está instalado (usa `which gobuster`).
- Adicionado: geração automática de wordlist se o arquivo configurado não existir (ex.: "configs/wordlists/directories.txt").
- Adicionado: suporte a `extra_flags` vindo do cfg (ex.: "--no-error").
"""
from typing import Dict, Any, List
from urllib.parse import urljoin
import os
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "gobuster_dir"
PLUGIN_CONFIG_ALIASES = ["dirb", "dirbuster", "dir"]
UUID_005 = "uuid-005-brute-force-dir"  # brute de diretórios/arquivos
UUID_006 = "uuid-006-dir-list-2"  # listagem de diretórios (opcional)


def _parse_gobuster(out: str) -> List[Dict[str, Any]]:
    """Parseia a saída do gobuster e retorna lista de dicts com path e status.

    Exemplos de linhas que a rotina tenta reconhecer:
      /admin (Status: 301) [Size: 123]
      /index.php (FOUND: 200)
      /secret  [200]
    """
    hits: List[Dict[str, Any]] = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        # linha que começa com / e contém Status: ou FOUND: ou termina com [code]
        if ln.startswith('/') and ('Status:' in ln or 'FOUND:' in ln or ('[' in ln and ']' in ln)):
            # tenta extrair path
            path = ln.split()[0]
            # extrai status code se possível
            status = None
            if 'Status:' in ln:
                try:
                    status = ln.split('Status:')[1].split(')')[0].strip()
                except Exception:
                    status = None
            elif 'FOUND:' in ln:
                try:
                    status = ln.split('FOUND:')[1].split(')')[0].strip()
                except Exception:
                    status = None
            else:
                # tenta extrair entre colchetes no final
                try:
                    part = ln.split('[')[-1]
                    if ']' in part:
                        status = part.split(']')[0]
                except Exception:
                    status = None
            hits.append({"path": path, "status": status or "unknown", "raw": ln})
    return hits


def _ensure_wordlist(path: str) -> None:
    """Garante que o arquivo de wordlist exista. Se não existir, cria com entradas básicas.
    PATH pode ser relativo (ex.: configs/wordlists/directories.txt).
    """
    if os.path.isabs(path):
        dirpath = os.path.dirname(path)
    else:
        dirpath = os.path.dirname(os.path.join(os.getcwd(), path))

    if dirpath and not os.path.isdir(dirpath):
        os.makedirs(dirpath, exist_ok=True)

    if not os.path.isfile(path):
        default_lines = [
            "admin",
            "login",
            "dashboard",
            "uploads",
            "images",
            "css",
            "js",
            "backup",
            "config",
            ".git",
            ".env",
            "api",
            "admin.php",
            "index.php",
            "wp-admin",
            "wp-login.php",
        ]
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(' '.join(default_lines) + ' ')
        except Exception:
            # se não conseguir escrever no local, apenas siga em frente — o gobuster pode falhar depois
            pass


def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """Executa gobuster dir e uma checagem simples de "Index of" em paths adicionais.

    Exemplos de cfg aceitos:
    {
      "wordlist": "configs/wordlists/directories.txt",
      "extensions": "php,txt,html",
      "status-codes": "200,204,301,302,307,401,403",
      "threads": 10,
      "timeout": 30,
      "add_paths_check": ["/", "/uploads/", "/static/"],
      "extra_flags": "--no-error"
    }
    """
    cfg = cfg or {}
    wl = cfg.get("wordlist", "")
    exts = cfg.get("extensions", "")
    codes = cfg.get("status-codes", "200,204,301,302,307,401,403")
    threads = str(cfg.get("threads", 50))
    timeout = int(cfg.get("timeout", 30))
    add_paths = cfg.get("add_paths_check") or ["/"]
    extra_flags = cfg.get("extra_flags", "")

    # se o usuário apontou para um wordlist interno, tenta criar se ausente
    try:
        _ensure_wordlist(wl)
    except Exception:
        # ignore erros de arquivo, o gobuster tratará
        pass

    # verifica se gobuster está instalado
    try:
        which_out = run_cmd(["which", "gobuster"], timeout=10)
    except Exception:
        which_out = ""

    if not which_out or not which_out.strip():
        # retorna um resultado informando que o gobuster não está disponível
        return {
            "plugin": "GobusterDir",
            "plugin_uuid": "uuid-gobuster-dir",
            "file_name": "gobuster_dir.py",
            "description": "Runs gobuster dir bruteforce and checks for basic directory listings.",
            "category": "Content Discovery",
            "result": [
                {
                    "scan_item_uuid": UUID_005,
                    "item_name": "Gobuster Availability",
                    "result": "gobuster não encontrado no PATH. Instale o gobuster para usar este plugin.",
                    "analysis_ai": ai_fn("GobusterDir", "uuid-gobuster-missing", "gobuster não encontrado"),
                    "severity": "info",
                    "duration": 0,
                    "auto": True,
                    "command": "which gobuster",
                    "reference": "https://github.com/OJ/gobuster"
                }
            ]
        }

    # helper para criar cada item com command incluso
    def make_item(uuid: str, item_name: str, result: str, severity: str, command: str) -> Dict[str, Any]:
        return {
            "scan_item_uuid": uuid,
            "item_name": item_name,
            "result": result,
            "analysis_ai": ai_fn("GobusterDir", uuid, result),
            "severity": severity,
            "duration": t.duration,
            "auto": True,
            "command": command,
            "reference": "https://github.com/OJ/gobuster"
        }

    # monta o comando gobuster
    cmd = ["gobuster", "dir", "-u", target, "-w", wl, "-q", "-t", threads, "-s", codes]
    if exts:
        cmd += ["-x", exts]
    if extra_flags:
        # split simples (o usuário deve passar flags apropriadas)
        cmd += extra_flags.split()

    items: List[Dict[str, Any]] = []

    with Timer() as t:
        # executa gobuster
        out = run_cmd(cmd, timeout=timeout)
        findings = _parse_gobuster(out)

        # checagem rápida de "Index of" (item 6)
        list_evid: List[str] = []
        for p in add_paths:
            url = urljoin(target.rstrip('/') + '/', p.lstrip('/'))
            body = run_cmd(["curl", "-sS", "-L", "-m", "10", url], timeout=12)
            if "Index of /" in body or "<title>Index of" in body or "Parent Directory" in body:
                list_evid.append(f"{p} :: directory listing aparent")

    # severidade: achados de paths => low; se listar diretórios => medium
    severity_findings = "low" if findings else "info"
    severity_list = "medium" if list_evid else "info"

    # prepara texto-resumo
    if findings:
        txt_hits = " ".join(f"- {h['path']} (status: {h.get('status')})" for h in findings)
    else:
        txt_hits = "Nenhum achado para brute force de diretórios/arquivos"

    if list_evid:
        txt_list = " ".join(f"- {e}" for e in list_evid)
    else:
        txt_list = "Nenhum achado para listagem de diretórios (extra)"

    # adiciona item principal (brute)
    items.append(make_item(
        UUID_005,
        "Brute-force de diretórios/arquivos (gobuster)",
        txt_hits,
        severity_findings,
        "{}".format(" ".join(cmd))
    ))

    # item opcional: listagem detectada
    items.append(make_item(
        UUID_006,
        "Detecção de Listing (Index of)",
        txt_list,
        severity_list,
        f"curl -sS -L -m 10 <target>/<path>  (checagem automática em {add_paths})"
    ))

    return {
        "plugin": "GobusterDir",
        "plugin_uuid": "uuid-gobuster-dir",
        "file_name": "gobuster_dir.py",
        "description": "Runs gobuster dir bruteforce and checks for basic directory listings.",
        "category": "Content Discovery",
        "result": items
    }
