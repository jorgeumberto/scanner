# plugins/dirbust.py
import shutil
import re
from typing import Dict, Any, List, Tuple

from utils import run_cmd, Timer

# Ajuda o main dinâmico a achar configs/dirbust.json
PLUGIN_CONFIG_NAME = "dirbust"
PLUGIN_CONFIG_ALIASES = ["gobuster", "dirb"]

# UUID placeholder — troque pelo UUID real do item 5 (Descoberta de diretórios/arquivos por força bruta)
UUID_5 = "uuid-005"

# ---------------- helpers ----------------

def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def _summarize(entries: List[Tuple[str, int, int]], checklist_name: str, max_lines: int = 25) -> str:
    """
    entries: lista de tuplas (path, status_code, size)
    """
    if not entries:
        return f"Nenhum achado para {checklist_name}"
    lines = []
    for p, code, size in entries[:max_lines]:
        lines.append(f"- {p} (HTTP {code}, size={size if size is not None else '?'})")
    extra = len(entries) - len(lines)
    if extra > 0:
        lines.append(f"... +{extra} entradas")
    return "\n".join(lines)

def _heuristic_severity(entries: List[Tuple[str,int,int]]) -> str:
    """
    Regras simples:
      - Se houver 200/204 em caminhos sensíveis (admin, backup, .git, .env, config, upload), 'high'
      - Se houver 200/204, 'medium'
      - Se só 301/302/403, 'low'
      - Vazio -> 'info'
    """
    if not entries:
        return "info"
    sensitive_tokens = ["admin", "backup", ".git", ".svn", ".env", "config", "db", "upload", "private", "secret"]
    any_ok = False
    any_sensitive = False
    only_redirect_or_forbidden = True

    for path, code, _ in entries:
        if code in (200, 201, 202, 204):
            any_ok = True
            only_redirect_or_forbidden = False
            if any(tok in path.lower() for tok in sensitive_tokens):
                any_sensitive = True
        elif code in (301, 302, 307, 308, 401, 403):
            # continua como only_redirect_or_forbidden
            pass
        else:
            # outros códigos (e.g. 500, 405) contam como não-only_redirect_or_forbidden
            only_redirect_or_forbidden = False

    if any_sensitive:
        return "high"
    if any_ok:
        return "medium"
    if only_redirect_or_forbidden:
        return "low"
    return "info"

# ---------------- Gobuster ----------------

# Exemplos de linhas do gobuster dir:
# /admin                (Status: 301) [Size: 0] [--> http://example.com/admin/]
# /robots.txt           (Status: 200) [Size: 72]
GOBUSTER_LINE = re.compile(
    r"^\s*(/[^\s]+)\s*\(Status:\s*(\d{3})\)\s*(?:\[Size:\s*(\d+)\])?", re.I
)

def _run_gobuster(target: str, wordlist: str, threads: int, ext_list: List[str],
                  include_status: List[int], exclude_status: List[int],
                  follow_redirect: bool, timeout: int, extra_args: List[str]) -> List[Tuple[str,int,int]]:
    if not wordlist:
        raise RuntimeError("Gobuster requer 'wordlist' definida em configs/dirbust.json")

    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-t", str(threads),
        "--no-error"
    ]
    if ext_list:
        cmd += ["-x", ",".join(ext_list)]
    if follow_redirect:
        cmd += ["-r"]
    if include_status:
        cmd += ["-s", ",".join(str(s) for s in include_status)]
    if exclude_status:
        cmd += ["-b", ",".join(str(s) for s in exclude_status)]
    if extra_args:
        cmd += extra_args

    out = run_cmd(cmd, timeout=timeout)
    findings: List[Tuple[str,int,int]] = []
    for line in out.splitlines():
        m = GOBUSTER_LINE.match(line.strip())
        if m:
            path = m.group(1).strip()
            code = int(m.group(2))
            sz   = int(m.group(3)) if m.group(3) else None
            findings.append((path, code, sz))
    return findings

# ---------------- Dirb ----------------

# Exemplo de linha do dirb:
# + http://example.com/admin (CODE:200|SIZE:512)
# ==> DIRECTORY: http://example.com/images/
DIRB_LINE = re.compile(
    r"^\s*(?:\+|==> DIRECTORY:)\s*(\S+)\s*(?:\(CODE:(\d{3})\|SIZE:(\d+)\))?",
    re.I
)

def _run_dirb(target: str, wordlist: str, ext_list: List[str],
              follow_redirect: bool, timeout: int, extra_args: List[str]) -> List[Tuple[str,int,int]]:
    if not wordlist:
        raise RuntimeError("Dirb requer 'wordlist' definida em configs/dirbust.json")
    cmd = ["dirb", target, wordlist, "-r", "-S"]  # -r recursivo (leve), -S silencioso
    if ext_list:
        cmd += ["-X", ",".join(ext_list)]
    if follow_redirect:
        cmd += ["-R"]
    if extra_args:
        cmd += extra_args

    out = run_cmd(cmd, timeout=timeout)
    findings: List[Tuple[str,int,int]] = []
    base = target.rstrip("/")

    for line in out.splitlines():
        s = line.strip()
        m = DIRB_LINE.match(s)
        if not m:
            continue
        url = m.group(1)
        # converte para path relativo
        path = url
        if url.startswith(base):
            path = url[len(base):]
        if not path.startswith("/"):
            path = "/" + path

        code = int(m.group(2)) if m.group(2) else 200  # DIRECTORY não traz code; assume 200
        sz   = int(m.group(3)) if m.group(3) else None
        findings.append((path, code, sz))

    return findings

# ---------------- Plugin principal ----------------

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (opcional) em configs/dirbust.json:
    {
      "timeout": 1800,
      "tool_preference": ["gobuster","dirb"],
      "wordlist": "/usr/share/wordlists/dirb/common.txt",
      "threads": 50,
      "extensions": ["php","asp","aspx","jsp"],
      "include_status": [200,204,301,302,307,401,403],
      "exclude_status": [],
      "follow_redirect": true,
      "limit_results": 0,
      "extra_args_gobuster": [],
      "extra_args_dirb": []
    }
    """
    cfg = cfg or {}
    timeout         = int(cfg.get("timeout", 1800))
    tool_pref       = cfg.get("tool_preference") or ["gobuster", "dirb"]
    wordlist        = cfg.get("wordlist") or "/usr/share/wordlists/dirb/common.txt"
    threads         = int(cfg.get("threads", 50))
    extensions      = cfg.get("extensions") or []
    include_status  = cfg.get("include_status") or [200,204,301,302,307,401,403]
    exclude_status  = cfg.get("exclude_status") or []
    follow_redirect = bool(cfg.get("follow_redirect", True))
    limit_results   = int(cfg.get("limit_results", 0))
    extra_gobuster  = cfg.get("extra_args_gobuster") or []
    extra_dirb      = cfg.get("extra_args_dirb") or []

    findings: List[Tuple[str,int,int]] = []

    # 1) Tenta as ferramentas conforme preferência
    with Timer() as t:
        for tool in tool_pref:
            try:
                if tool == "gobuster" and _has("gobuster"):
                    findings = _run_gobuster(
                        target=target,
                        wordlist=wordlist,
                        threads=threads,
                        ext_list=extensions,
                        include_status=include_status,
                        exclude_status=exclude_status,
                        follow_redirect=follow_redirect,
                        timeout=timeout,
                        extra_args=extra_gobuster
                    )
                    if findings:
                        break
                elif tool == "dirb" and _has("dirb"):
                    findings = _run_dirb(
                        target=target,
                        wordlist=wordlist,
                        ext_list=extensions,
                        follow_redirect=follow_redirect,
                        timeout=timeout,
                        extra_args=extra_dirb
                    )
                    if findings:
                        break
            except Exception:
                # falha de uma ferramenta não derruba o plugin; tenta a próxima
                continue
    duration = t.duration

    # 2) aplica limite (se configurado)
    if limit_results and len(findings) > limit_results:
        findings = findings[:limit_results]

    # 3) monta saída
    checklist_name = "Descoberta de diretórios/arquivos por força bruta (wordlist)"
    result_text = _summarize(findings, checklist_name)
    severity = _heuristic_severity(findings)

    item = {
        "plugin_uuid": UUID_5,
        "scan_item_uuid": UUID_5,
        "result": result_text,
        "analysis_ai": ai_fn("Dirbust", UUID_5, result_text),
        "severity": severity,
        "duration": duration,
        "auto": True
    }
    return {"plugin": "Dirbust", "result": [item]}
