import subprocess

def run(target):
    cmd = ["curl", "-I", target]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30)
        return output.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        return f"Erro: {e.output.decode('utf-8', errors='ignore')}"
    except Exception as e:
        return f"Falha: {str(e)}"
