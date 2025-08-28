import requests

import json

API_URL = "http://127.0.0.1:8000/api/scan-results"
API_TOKEN = "seu_token_aqui"   # opcional

def post_results(filepath: str) -> dict:
    """
    Envia o conteúdo do tests_raw.json para a API.
    Retorna a resposta da API como dict (ou erro).
    """
    try:
        with open(filepath, "r") as f:
            data = json.load(f)

        headers = {
            "Content-Type": "application/json"
        }
        if API_TOKEN:
            headers["Authorization"] = f"Bearer {API_TOKEN}"

        resp = requests.post(API_URL, headers=headers, json=data)

        if resp.status_code == 200:
            return {"status": "OK", "resposta": resp.json()}
        else:
            return {"status": "ERRO", "code": resp.status_code, "resposta": resp.text}

    except Exception as e:
        return {"status": "ERRO", "mensagem": str(e)}
