# main.py
import argparse
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, List

# --- Diretórios padrão ---
BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"
CONFIGS_DIR = BASE_DIR / "configs"
OUT_DIR = BASE_DIR / "out"
OUT_DIR.mkdir(exist_ok=True, parents=True)

# --- API (opcional) ---
try:
    from api_client import enviar_resultados  # envia um arquivo JSON para a API
except Exception:
    enviar_resultados = None

# ---------- AI dispatcher (centralizado) ----------
def make_ai_fn(mode: str = "off"):
    """
    AI modes:
      - "off": não usa IA (retorna string fixa)
      - você pode plugar aqui OpenAI/Grok no futuro
    """
    mode = (mode or "off").lower()
    if mode == "off":
        def _ai_fn(plugin_name: str, plugin_uuid: str, text: str) -> str:
            return "[AI desabilitada]"
        return _ai_fn

    # placeholder para futura integração real (mantém compatível)
    def _ai_fn(plugin_name: str, plugin_uuid: str, text: str) -> str:
        return "[AI simulada] " + (text[:240] + "..." if len(text) > 240 else text)
    return _ai_fn

# ---------- Loader dinâmico de plugins ----------
def load_plugins() -> List[Any]:
    loaded = []
    for py in PLUGINS_DIR.glob("*.py"):
        name = py.stem
        spec = importlib.util.spec_from_file_location(f"plugins.{name}", str(py))
        if not spec or not spec.loader:
            print(f"[!] Ignorando {py.name} (spec inválida)")
            continue
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)  # type: ignore
        except Exception as e:
            print(f"[!] Falha ao importar {py.name}: {e}")
            continue

        if not hasattr(mod, "run_plugin"):
            # não é um plugin no nosso padrão
            continue
        loaded.append(mod)
    return loaded

# ---------- Busca config p/ cada plugin ----------
def load_config_for(mod) -> Dict[str, Any]:
    # prioridade: nome, depois aliases
    names = []
    if hasattr(mod, "PLUGIN_CONFIG_NAME"):
        names.append(getattr(mod, "PLUGIN_CONFIG_NAME"))
    if hasattr(mod, "PLUGIN_CONFIG_ALIASES"):
        names += list(getattr(mod, "PLUGIN_CONFIG_ALIASES") or [])

    for nm in names:
        p = CONFIGS_DIR / f"{nm}.json"
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {}  # default vazio

# ---------- Métricas ----------
def count_findings(scan_results: List[Dict[str, Any]]) -> int:
    """
    Conta quantidade de achados relevantes.
    Heurística: itens cujo 'severity' != 'info' e cujo 'result' não inicia com "Nenhum achado".
    """
    cnt = 0
    for block in scan_results:
        for it in block.get("result", []):
            sev = (it.get("severity") or "").lower()
            res = (it.get("result") or "")
            if sev != "info" and not res.startswith("Nenhum achado"):
                cnt += 1
    return cnt

def main():
    ap = argparse.ArgumentParser(description="Runner dinâmico de plugins de pentest")
    ap.add_argument("--target", required=True, help="URL/host alvo (ex.: https://example.com)")
    ap.add_argument("--name", default="Scan Automático", help="Nome do scan")
    ap.add_argument("--description", default="Scan automático via API", help="Descrição")
    ap.add_argument("--cliente_api", default="SUA_API_KEY_AQUI", help="Chave do cliente p/ payload")
    ap.add_argument("--ai", default="off", choices=["off", "mock"], help="Habilita IA (mock por padrão)")
    ap.add_argument("--send", action="store_true", help="Envia o JSON final para a API (usa api_client.enviar_resultados)")
    ap.add_argument("--outfile", default=str(OUT_DIR / "scan_result.json"), help="Caminho p/ salvar o JSON final")
    args = ap.parse_args()

    ai_fn = make_ai_fn(args.ai)

    mods = load_plugins()
    if not mods:
        print("[!] Nenhum plugin carregado de ./plugins")
        sys.exit(1)

    started = time.time()
    blocks: List[Dict[str, Any]] = []

    for mod in mods:
        cfg = load_config_for(mod)
        try:
            block = mod.run_plugin(args.target, ai_fn, cfg)
            # cada plugin retorna: {"plugin": "...", "result": [ ... ]}
            if block and isinstance(block, dict) and "plugin" in block and "result" in block:
                blocks.append(block)
            else:
                print(f"[!] Plugin {getattr(mod, '__name__', '???')} retornou formato inválido")
        except Exception as e:
            print(f"[!] Erro no plugin {getattr(mod, '__name__', '???')}: {e}")

    total_duration = round(time.time() - started, 3)
    findings = count_findings(blocks)

    final_payload = {
        "cliente_api": args.cliente_api,
        "name": args.name,
        "target": args.target,
        "description": args.description,
        "finding_count": findings,
        "analysis": None,
        "duration": total_duration,
        "scan_results": blocks
    }

    # grava arquivo
    outfile = Path(args.outfile)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json.dumps(final_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] JSON salvo em: {outfile}")

    # envia (opcional)
    if args.send:
        if enviar_resultados is None:
            print("[!] api_client.enviar_resultados não disponível. Pulei envio.")
        else:
            resp = enviar_resultados(str(outfile))
            print("[API] Resposta:", resp)

if __name__ == "__main__":
    main()
