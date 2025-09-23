# main.py
import os
import re
import sys
import json
import inspect
import importlib.util
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple


from dotenv import load_dotenv
load_dotenv()  # <--- carrega variáveis do .env

from utils import Timer
from ai_analyzer import analyze_item
from api_adapter import to_controller_payload
from api_client import post_results

import socket, platform
from datetime import datetime

# ---- BASE DIRS robustos ----
BASE_DIR = Path(__file__).resolve().parent
def _abs_path(p: str) -> Path:
    pp = Path(p)
    return pp if pp.is_absolute() else (BASE_DIR / pp)

# =======================
# Configs globais (ENV)
# =======================
TARGET        = os.environ["TARGET"]
API_KEY       = os.environ["API_KEY"]
API_URL       = os.environ["API_URL"]
PLUGINS_DIR   = os.environ.get("PLUGINS_DIR", "plugins")
CONFIGS_DIR   = os.environ.get("CONFIGS_DIR", "configs")
MAX_WORKERS   = int(os.environ.get("MAX_WORKERS", "4"))

# Filtros opcionais (sem extensão .py), ex: "curl_headers,nmap_top_ports"
PLUGINS_INCLUDE = {p.strip().lower() for p in os.getenv("PLUGINS_INCLUDE", "").split(",") if p.strip()}
PLUGINS_EXCLUDE = {p.strip().lower() for p in os.getenv("PLUGINS_EXCLUDE", "").split(",") if p.strip()}

# =======================
# Helpers gerais
# =======================
def ai_wrapper(plugin_name: str, item_uuid: str, result_text: str) -> str:
    """Encapsula a chamada de IA (permite trocar provedor sem mexer plugins)."""
    return analyze_item(TARGET, plugin_name, item_uuid, result_text)

def _load_json(path: Path) -> dict:
    try:
        with path.open("r") as f:
            return json.load(f)
    except Exception:
        return {}

def _norm(s: str) -> str:
    """normaliza: minúsculas + remove tudo que não é [a-z0-9]"""
    return re.sub(r"[^a-z0-9]+", "", s.lower())

def _list_config_candidates() -> List[Path]:
    """lista todos os arquivos .json em configs/"""
    base = Path(CONFIGS_DIR)
    if not base.exists():
        return []
    return sorted([p for p in base.glob("*.json")])

def _best_config_for(module_name: str, mod=None) -> dict:
    """
    Estratégia dinâmica:
      - Coleta chaves:
          * nome do módulo (ex.: 'curl_headers')
          * PLUGIN_CONFIG_NAME (se exposto)
          * PLUGIN_CONFIG_ALIASES (se exposto)
      - Varre configs/*.json e escolhe melhor match por normalização:
          3 = igual; 2 = startswith/endswith; 1 = contains
      - Se múltiplos, escolhe o de maior força, depois o nome mais curto.
    """
    keys = {module_name}
    if mod is not None and hasattr(mod, "PLUGIN_CONFIG_NAME"):
        keys.add(str(getattr(mod, "PLUGIN_CONFIG_NAME")))
    if mod is not None and hasattr(mod, "PLUGIN_CONFIG_ALIASES"):
        for a in getattr(mod, "PLUGIN_CONFIG_ALIASES") or []:
            keys.add(str(a))

    keys_norm = {_norm(k) for k in keys if k}

    candidates = _list_config_candidates()
    if not candidates:
        return {}

    files = [(p, _norm(p.stem)) for p in candidates]

    ranked: List[Tuple[int, int, Path]] = []
    for p, stem_norm in files:
        match_strength = 0
        for k in keys_norm:
            if stem_norm == k:
                match_strength = max(match_strength, 3)
            elif stem_norm.startswith(k) or stem_norm.endswith(k):
                match_strength = max(match_strength, 2)
            elif k in stem_norm or stem_norm in k:
                match_strength = max(match_strength, 1)
        if match_strength > 0:
            ranked.append((match_strength, len(stem_norm), p))

    if not ranked:
        return {}

    ranked.sort(key=lambda x: (-x[0], x[1], str(x[2])))
    best_path = ranked[0][2]
    return _load_json(best_path)

def discover_plugin_files() -> List[Path]:
    """
    Retorna todos os .py em PLUGINS_DIR (exceto __init__.py),
    aplicando INCLUDE/EXCLUDE se configurado.
    """
    base = Path(PLUGINS_DIR)
    if not base.exists():
        return []
    out: List[Path] = []
    for f in base.glob("*.py"):
        if f.name == "__init__.py":
            continue
        name = f.stem.lower()
        if PLUGINS_INCLUDE and name not in PLUGINS_INCLUDE:
            continue
        if name in PLUGINS_EXCLUDE:
            continue
        out.append(f)
    return sorted(out)

def import_module_from_path(path: Path):
    """Importa um módulo python pelo caminho (sem precisar pacote)."""
    mod_name = path.stem  # ex.: curl_headers
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Não foi possível carregar spec para {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod

def call_run_plugin(mod, module_name: str):
    """
    Chama run_plugin do módulo com:
      - (target, ai_fn, cfg) se aceitar 3 args
      - (target, ai_fn)      se aceitar 2 args
    Config é descoberta dinamicamente via _best_config_for(...).
    Retorno esperado do plugin: {"plugin": "Nome", "result": [ {...}, ... ]}
    """
    if not hasattr(mod, "run_plugin"):
        return {"plugin": module_name, "result": [], "error": "run_plugin() não encontrado"}

    fn = mod.run_plugin
    sig = inspect.signature(fn)
    params = list(sig.parameters.keys())

    cfg = _best_config_for(module_name, mod)

    try:
        if len(params) >= 3:
            return fn(TARGET, ai_wrapper, cfg)
        else:
            return fn(TARGET, ai_wrapper)
    except TypeError:
        try:
            return fn(TARGET, ai_wrapper, cfg)
        except Exception as e:
            return {"plugin": module_name, "result": [], "error": str(e)}
    except Exception as e:
        return {"plugin": module_name, "result": [], "error": str(e)}

def compute_finding_count(plugins_output):
    """Conta itens com severity != 'info' como 'achados'."""
    count = 0
    for pr in plugins_output:
        for it in pr.get("result", []):
            if str(it.get("severity", "info")).lower() != "info":
                count += 1
    return count

# =======================
# Execução
# =======================
def main():
    print(f"[+] Iniciando Scan Automático em: {TARGET}")
    os.makedirs("results", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    plugin_paths = discover_plugin_files()
    if not plugin_paths:
        print(f"[!] Nenhum plugin encontrado em {PLUGINS_DIR}")
        return

    modules = []
    for path in plugin_paths:
        try:
            mod = import_module_from_path(path)
            modules.append((path.stem, mod))
            print(f"[+] Plugin carregado: {path.stem}")
        except Exception as e:
            print(f"[ERRO] Falha ao importar {path.name}: {e}")

    with Timer() as t_scan:
        if MAX_WORKERS >= 2:
            futures = {}
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
                for name, mod in modules:
                    futures[ex.submit(call_run_plugin, mod, name)] = name
                plugins_output = []
                for fut in as_completed(futures):
                    name = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = {"plugin": name, "result": [], "error": str(e)}
                    plugins_output.append(res)
        else:
            plugins_output = []
            for name, mod in modules:
                plugins_output.append(call_run_plugin(mod, name))

    finding_count = compute_finding_count(plugins_output)

    hostname = socket.gethostname()
    try:
        ip_origem = socket.gethostbyname(hostname)
    except Exception:
        ip_origem = None  

    login = None
    try:
        login = os.getlogin()
    except Exception:
        login = None

    my_json = {
        "cliente_api": API_KEY,
        "name": "Scan Automático",
        "target": TARGET,
        "description": "Scan automático via API",
        "finding_count": finding_count,
        "duration": t_scan.duration,
        "data_hora": datetime.now().isoformat(),
        "ip_origem": ip_origem,
        "hostname": hostname,
        "usuario": login,
        "sistema": platform.platform(),
        "scan_results": plugins_output
    }

    out_my = Path("results") / f"scan_myjson.json"
 
    with out_my.open("w") as f:
        json.dump(my_json, f, indent=2, ensure_ascii=False)
    print(f"[+] Seu JSON salvo em: {out_my}")

    if(os.getenv("SEND_TO_API", "0")=="0"):
        print("[+] SEND_TO_API=0 ativo, pulando envio para API.")
        return
    
    api_resp = post_results(my_json)
    print("[API]", api_resp)

if __name__ == "__main__":
    main()
