# ai_analyzer.py
import os
import requests

AI_ENABLE     = os.getenv("AI_ENABLE", "false").lower() == "true"
OPENAI_KEY    = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL  = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
AI_TIMEOUT_S  = int(os.getenv("AI_TIMEOUT_S", "30"))
OPENAI_BASE   = os.getenv("OPENAI_BASE_URL", "https://api.openai.com")  # opcional

def _prompt(target: str, plugin: str, item_uuid: str, result_text: str) -> str:
    return (
        "Analise o seguinte resultado de teste de segurança web e responda curto:\n"
        "Se o risco for baixo, não mostre Impacto, recomendações ou explicações.\n"
        "Risco (HIG, MED ou LOW)\n" 
        "- Impacto (1–2 linhas, Por que a falta (ou má configuração) é considerada uma vulnerabilidade, Vetores de ataque comuns mitigados)\n"
        "- Explicação (1 linha, O que é essa técnica utilizada)\n"
        "- Recomendações e Boas práticas de configuração (bullets curtos)\n"
        f"Alvo: {target}\n"
        f"Plugin: {plugin}\n"
        f"Item UUID: {item_uuid}\n"
        f"Resultado:\n{result_text}\n"
        "Explique sobre a técnica utilizada e como mitigar."
    )

def analyze_item(target: str, plugin: str, item_uuid: str, result_text: str) -> str:
    """
    Retorna um texto curto com análise. Se AI_ENABLE=false ou chave ausente, devolve marcador.
    """
    if not AI_ENABLE or not OPENAI_KEY:
        return "[AI desabilitada]"

    try:
        url = f"{OPENAI_BASE}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {OPENAI_KEY}",
            "Content-Type": "application/json",
        }
        body = {
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": "Você é um assistente de segurança ofensiva, conciso e direto."},
                {"role": "user", "content": _prompt(target, plugin, item_uuid, result_text)}
            ],
            "temperature": 0.2
        }
        resp = requests.post(url, headers=headers, json=body, timeout=AI_TIMEOUT_S)
        if resp.status_code == 200:
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
        return f"[AI erro] HTTP {resp.status_code} {resp.text[:200]}"
    except Exception as e:
        return f"[AI erro] {e}"
