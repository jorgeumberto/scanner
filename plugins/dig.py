from urllib.parse import urlparse
import subprocess

def run(target):

    if target.startswith("http"):
        target = urlparse(target).hostname
        
    cmd = ["dig", target]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30)
        return output.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        return f"Erro: {e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"Falha: {str(e)}"
