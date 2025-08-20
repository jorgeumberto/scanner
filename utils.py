import subprocess
from urllib.parse import urlparse

def extrair_host(target: str) -> str:
    """Extrai apenas o host (sem http/https)."""
    if not target.startswith("http"):
        target = "http://" + target
    return urlparse(target).hostname

def run_cmd(cmd: list, timeout: int = 30) -> str:
    """Executa comando de terminal e captura saída/erros."""
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return output.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        return f"[ERRO CMD] {e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"[FALHA CMD] {str(e)}"
