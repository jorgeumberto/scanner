import subprocess
from urllib.parse import urlparse
import time
import uuid
from datetime import datetime

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

    description = "Sem descrição"
    category = "generic"   # cada plugin pode sobrescrever
    tags = []              # cada plugin pode sobrescrever

    def run(self, target: str, cfg: dict) -> str:
        raise NotImplementedError

    def parse_output(self, raw: str) -> dict:
        return {}

    def summarize_output(self, parsed: dict, raw: str) -> str:
        return raw[:200] + "..." if len(raw) > 200 else raw

    def execute(self, target: str, cfg: dict, client_id=None, asset_id=None, scan_id=None) -> dict:
        """Executa o plugin e retorna resultado padronizado em JSON"""

        start_time = time.time()
        if not scan_id:
            scan_id = str(uuid.uuid4())  # gera scan_id se não for passado

        try:
            raw = self.run(target, cfg)
            parsed = self.parse_output(raw)
            summary = self.summarize_output(parsed, raw)
            duration = round(time.time() - start_time, 2)

            return {
                "plugin": self.__class__.__name__,
                "description": getattr(self, "description", "Sem descrição"),
                "category": getattr(self, "category", "generic"),
                "tags": getattr(self, "tags", []),
                "target": target,
                "client_id": client_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "duration": duration,
                "raw": raw,
                "parsed": parsed,
                "summary": summary,
                "analysis": None,
                "status": "OK",
                "severity": getattr(self, "_severity", None),
                "finding_count": getattr(self, "_finding_count", None),
                "reference": getattr(self, "reference", 'owasp'),
            }

        except Exception as e:
            duration = round(time.time() - start_time, 2)
            return {
                "plugin": self.__class__.__name__,
                "description": getattr(self, "description", "Sem descrição"),
                "category": getattr(self, "category", "generic"),
                "tags": getattr(self, "tags", []),
                "target": target,
                "client_id": client_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "duration": duration,
                "raw": "",
                "parsed": {},
                "summary": f"Erro: {str(e)}",
                "analysis": None,
                "status": "ERRO",
                "severity": getattr(self, "_severity", None),
                "finding_count": getattr(self, "_finding_count", None),
                "reference": getattr(self, "reference", 'owasp'),
            }
