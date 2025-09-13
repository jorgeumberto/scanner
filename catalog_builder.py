# catalog_builder.py
import os
import json
from pathlib import Path
from typing import Dict, Any

from api_client import post_catalog

# Caminho do JSON com o catálogo de plugins (padrão: ./plugins.json)
CATALOG_JSON_PATH = os.getenv("CATALOG_JSON_PATH", "plugins.json")

# De onde vem a API key do cliente para empacotar no payload
CLIENTE_API = os.getenv("CLIENTE_API") or os.getenv("API_KEY") or ""

def _validate_catalog(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("Catálogo inválido: não é um objeto JSON.")
    plugins = data.get("plugins")
    if not isinstance(plugins, list):
        raise ValueError('Catálogo inválido: chave "plugins" deve ser uma lista.')

    for idx, p in enumerate(plugins):
        if not isinstance(p, dict):
            raise ValueError('Item plugins[{}] não é um objeto.'.format(idx))
        for key in ("plugin", "file_name", "description", "category", "uuids"):
            if key not in p:
                raise ValueError('plugins[{}] sem chave obrigatória: "{}".'.format(idx, key))
        if not isinstance(p["uuids"], list):
            raise ValueError('plugins[{}].uuids deve ser lista.'.format(idx))
        for j, u in enumerate(p["uuids"]):
            if not isinstance(u, dict):
                raise ValueError('plugins[{}].uuids[{}] não é objeto.'.format(idx, j))
            for k in ("scan_item_uuid", "description"):
                if k not in u:
                    raise ValueError('plugins[{}].uuids[{}] sem chave obrigatória: "{}".'.format(idx, j, k))
    return data

def load_catalog_from_file(path=None) -> Dict[str, Any]:
    path = Path(path or CATALOG_JSON_PATH)
    if not path.exists():
        raise FileNotFoundError("Arquivo de catálogo não encontrado: {}".format(path))
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return _validate_catalog(data)

def _wrap_with_cliente_api(catalog: Dict[str, Any], cliente_api: str = None) -> Dict[str, Any]:
    key = (cliente_api or CLIENTE_API or "").strip()
    if not key:
        # você pode levantar erro ou apenas enviar sem a chave; aqui prefiro errar cedo
        raise ValueError("cliente_api/API_KEY não definido nas variáveis de ambiente.")
    return {
        "cliente_api": key,
        "plugins": catalog.get("plugins", [])
    }

def send_catalog_to_api(catalog: Dict[str, Any], cliente_api: str = None) -> dict:
    payload = _wrap_with_cliente_api(catalog, cliente_api=cliente_api)
    return post_catalog(payload)

def load_and_send_catalog(path=None, cliente_api: str = None) -> dict:
    catalog = load_catalog_from_file(path)
    return send_catalog_to_api(catalog, cliente_api=cliente_api)
