# plugins/log_backups_exposure.py
"""
Plugin: log_backups_exposure
Objetivo:
  - Executar Nikto (com saída JSON) e classificar achados relevantes:
      * Arquivos sensíveis expostos
      * Listagem de diretórios habilitada
      * Logs sensíveis expostos
      * Outros (misc)
  - Registra os comandos executados em `command`.
  - Se o nikto não estiver instalado, retorna um item diagnóstico com
    informações e sugestões de instalação.
"""

import json
import tempfile
import os
import time
import shutil
from typing import Dict, Any, List, Optional

PLUGIN_CONFIG_NAME = "log_backups_exposure"

UUIDS = {
    4:  "uuid-004-files-sensitives",
    6:  "uuid-006-dir-list",
    28: "uuid-028-log-exposure",
    900:"uuid-900-misc",
    901:"uuid-901-nikto-not-found"   # diagnóstico: nikto ausente
}

# === injected: capture executed shell commands for tagging ===
try:
    from utils import run_cmd as __run_cmd_orig, Timer as __Timer_orig
except Exception:
    __run_cmd_orig = None
    __Timer_orig = None

EXEC_CMDS: List[str] = []

def run_cmd(cmd, timeout=None):
    """
    Wrapper para capturar o comando usado em EXEC_CMDS.
    Usa utils.run_cmd quando disponível, senão subprocess como fallback.
    """
    cmd_str = " ".join(cmd) if isinstance(cmd,(list,tuple)) else str(cmd)
    EXEC_CMDS.append(cmd_str)
    if __run_cmd_orig is None:
        import subprocess
        try:
            p = subprocess.run(cmd, shell=isinstance(cmd,str), capture_output=True, text=True, timeout=(timeout or 30))
            return (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return f"[ERRO run_cmd-fallback] {e}"
    return __run_cmd_orig(cmd, timeout=timeout)

# Timer fallback
class _SimpleTimer:
    def __enter__(self): 
        self._t0=time.time(); return self
    def __exit__(self,exc,exv,tb):
        self.duration=time.time()-self._t0

Timer = __Timer_orig or _SimpleTimer
# === end injected ===

def _run_nikto_json(target: str, timeout: int, plugins: List[str], useragent: str, ssl: bool, root_only: bool) -> Dict[str, Any]:
    """
    Executa Nikto com saída JSON (em arquivo temporário).
    """
    with tempfile.TemporaryDirectory() as td:
        out_path = os.path.join(td, "nikto.json")
        cmd = ["nikto", "-h", target, "-Format", "json", "-o", out_path, "-nointeractive"]
        if useragent:
            cmd += ["-useragent", useragent]
        if plugins:
            cmd += ["-Plugins", ",".join(plugins)]
        if ssl:
            cmd += ["-ssl"]
        if root_only:
            cmd += ["-rootonly"]

        _ = run_cmd(cmd, timeout=timeout)
        try:
            with open(out_path,"r") as f:
                return json.load(f)
        except Exception:
            return {}

def _classify_findings(nikto_json: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    groups = {"sensitive_files": [], "dir_listing": [], "logs_exposed": [], "misc": []}
    if not nikto_json:
        return groups
    vulns = nikto_json.get("vulnerabilities") or nikto_json.get("vuln") or []
    for v in vulns:
        msg = (v.get("msg") or v.get("message") or "").lower()
        url = v.get("url") or v.get("uri") or ""
        entry = {"url": url, "msg": v.get("msg") or v.get("message") or ""}
        if any(x in url for x in [".env",".git",".svn",".bak",".old"]) or "backup" in msg or "config" in msg:
            groups["sensitive_files"].append(entry)
        elif "directory indexing" in msg or "directory listing" in msg:
            groups["dir_listing"].append(entry)
        elif "log" in url or "log" in msg:
            groups["logs_exposed"].append(entry)
        else:
            groups["misc"].append(entry)
    return groups

def _summarize(entries: List[Dict[str, Any]], checklist_name: str, max_lines: int=6) -> str:
    if not entries:
        return f"Nenhum achado para {checklist_name}"
    lines = []
    for e in entries[:max_lines]:
        lines.append(f"- {e.get('url','?')} :: {e.get('msg','').strip()[:160]}")
    extra = len(entries)-len(lines)
    if extra>0:
        lines.append(f"... +{extra} achados")
    return "\n".join(lines)

def build_item(uuid: str, msg: str, severity: str, duration: float, ai_fn, item_name: str) -> Dict[str, Any]:
    return {
        "scan_item_uuid": uuid,
        "result": msg,
        "analysis_ai": ai_fn(PLUGIN_CONFIG_NAME, uuid, msg) if callable(ai_fn) else None,
        "severity": severity,
        "duration": duration,
        "auto": True,
        "item_name": item_name,
        "command": EXEC_CMDS[:]  # histórico completo de comandos desta execução
    }

def _suggest_install_instructions() -> str:
    # instruções básicas para Debian/Ubuntu e RHEL/CentOS; ajustáveis
    return (
        "Sugestão de instalação:\n"
        "  Debian/Ubuntu: sudo apt update && sudo apt install -y nikto\n"
        "  RHEL/CentOS (EPEL): sudo yum install -y epel-release && sudo yum install -y nikto\n"
        "  Alternativa (Perl CPAN / manual): https://cirt.net/Nikto2\n"
    )

def run_plugin(target: str, ai_fn, cfg: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
    cfg = cfg or {}
    timeout   = int(cfg.get("timeout",600))
    plugins   = cfg.get("plugins") or []
    useragent = cfg.get("useragent","Pentest-Auto/1.0")
    ssl       = bool(cfg.get("ssl",False))
    root_only = bool(cfg.get("root_only",False))
    sev_map   = cfg.get("severity_map") or {
        "sensitive_files":"high",
        "dir_listing":"medium",
        "logs_exposed":"medium",
        "misc":"info"
    }

    # 1) Verificar se o nikto está disponível no PATH.
    # Preferimos usar shutil.which para não depender de run_cmd, mas também chamamos run_cmd("which nikto")
    nikto_path = shutil.which("nikto")
    # registrar tentativa via run_cmd (captura em EXEC_CMDS)
    try:
        _ = run_cmd(["which","nikto"], timeout=5)
    except Exception:
        pass

    if not nikto_path:
        # nikto não encontrado: retornar diagnóstico com sugestões e comandos tentados
        diag_lines = [
            "Nikto não encontrado no PATH — não é possível executar a verificação.",
            _suggest_install_instructions(),
            "Comandos tentados (histórico):"
        ]
        for c in EXEC_CMDS:
            diag_lines.append(f"- {c}")
        diag_txt = "\n".join(diag_lines)
        # duração zero (não executamos nikto)
        return {
            "plugin": PLUGIN_CONFIG_NAME,
            "plugin_uuid": "uuid-log-backups-exposure",
            "file_name": "log_backups_exposure.py",
            "description": "Executa Nikto e classifica achados. Retorna diagnóstico se nikto não estiver instalado.",
            "category": "Information Gathering",
            "result": [
                build_item(UUIDS[901], diag_txt, "info", 0.0, ai_fn, "Nikto not found diagnostic")
            ]
        }

    # 2) Nikto existe -> executar normalmente
    with Timer() as t:
        data = _run_nikto_json(target, timeout, plugins, useragent, ssl, root_only)
    duration = getattr(t,"duration",0.0)

    groups = _classify_findings(data)
    items: List[Dict[str,Any]] = []

    # 4: arquivos sensíveis
    g4 = groups["sensitive_files"]
    items.append(build_item(UUIDS[4], _summarize(g4,"Arquivos sensíveis expostos"),
                            sev_map["sensitive_files"] if g4 else "info",
                            duration, ai_fn, "Sensitive files exposed"))

    # 6: dir listing
    g6 = groups["dir_listing"]
    items.append(build_item(UUIDS[6], _summarize(g6,"Listagem de diretórios habilitada"),
                            sev_map["dir_listing"] if g6 else "info",
                            duration, ai_fn, "Directory listing enabled"))

    # 28: logs expostos
    g28 = groups["logs_exposed"]
    items.append(build_item(UUIDS[28], _summarize(g28,"Logs sensíveis acessíveis publicamente"),
                            sev_map["logs_exposed"] if g28 else "info",
                            duration, ai_fn, "Logs exposed"))

    # misc
    gm = groups["misc"]
    items.append(build_item(UUIDS[900], _summarize(gm,"Outros achados de configuração"),
                            sev_map["misc"] if gm else "info",
                            duration, ai_fn, "Misc findings"))

    return {
        "plugin": PLUGIN_CONFIG_NAME,
        "plugin_uuid": "uuid-log-backups-exposure",
        "file_name": "log_backups_exposure.py",
        "description": "Executa Nikto e classifica achados em arquivos sensíveis, diretórios, logs e outros. Registra comandos executados.",
        "category": "Information Gathering",
        "result": items
    }
