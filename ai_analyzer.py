import os
import time
from typing import Dict, Any

AI_ENABLE   = os.getenv("AI_ENABLE", "false").lower() == "true"
OPENAI_KEY  = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL= os.getenv("OPENAI_MODEL", "gpt-4o-mini")
AI_TIMEOUT  = int(os.getenv("AI_TIMEOUT_S", "30"))

def prompt_for_item(target: str, plugin: str, item_uuid: str, result_text: str) -> str:
    return (
        "Analise o seguinte resultado de teste de segurança web e responda curto:\n"
        "- Risco (1 frase)\n- Impacto (1–2 linhas)\n- Recomendações (bullets curtos)\n\n"
        f"Alvo: {target}\n"
        f"Plugin: {plugin}\n"
        f"Item UUID: {item_uuid}\n"
        f"Resultado:\n{result_text}\n"
    )

def analyze_item(target: str, plugin: str, item_uuid: str, result_text: str) -> str:
    if not AI_ENABLE or not OPENAI_KEY:
        return "[AI desabilitada]"
    try:
        import requests
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"}
        body = {
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": "Você é um assistente de segurança ofensiva, conciso e direto."},
                {"role": "user", "content": prompt_for_item(target, plugin, item_uuid, result_text)}
            ],
            "temperature": 0.2
        }
        resp = requests.post(url, headers=headers, json=body, timeout=AI_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
        return f"[AI erro] HTTP {resp.status_code} {resp.text[:200]}"
    except Exception as e:
        return f"[AI erro] {e}"
