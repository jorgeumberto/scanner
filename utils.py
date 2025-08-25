import subprocess
from urllib.parse import urlparse

def run_cmd(cmd: list) -> str:
    """
    Executa um comando no sistema e retorna stdout+stderr.
    Se falhar, retorna a mensagem de erro.
    """
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        output = result.stdout.strip()
        error = result.stderr.strip()
        return (output + "\n" + error).strip()
    except Exception as e:
        return f"[ERRO ao executar {' '.join(cmd)}] {str(e)}"

def extrair_host(target: str) -> str:
    """Extrai apenas o hostname de uma URL ou retorna o alvo cru"""
    try:
        host = urlparse(target).hostname
        if host:
            return host
        return target
    except Exception:
        return target



class BasePlugin:
    """Classe base que padroniza saída de todos os plugins"""

    description = "Sem descrição"  # valor padrão se o plugin não sobrescrever

    def run(self, target: str, cfg: dict) -> str:
        raise NotImplementedError

    def parse_output(self, raw: str) -> dict:
        return {}

    def summarize_output(self, parsed: dict, raw: str) -> str:
        return raw[:200] + "..." if len(raw) > 200 else raw

    def execute(self, target: str, cfg: dict) -> dict:
        try:
            raw = self.run(target, cfg)
            parsed = self.parse_output(raw)
            summary = self.summarize_output(parsed, raw)
            return {
                "plugin": self.__class__.__name__,
                "description": getattr(self, "description", "Sem descrição"),
                "target": target,
                "raw": raw,
                "parsed": parsed,
                "summary": summary,
                "analysis": None,   # reservado p/ ChatGPT
                "status": "OK"
            }
        except Exception as e:
            return {
                "plugin": self.__class__.__name__,
                "description": getattr(self, "description", "Sem descrição"),
                "target": target,
                "raw": "",
                "parsed": {},
                "summary": f"Erro: {str(e)}",
                "analysis": None,
                "status": "ERRO"
            }

