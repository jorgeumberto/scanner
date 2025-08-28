"""
Template de Plugin
"""

from utils import run_cmd, extrair_host

def run(target):
    host = extrair_host(target)
    return run_cmd(["echo", f"Executando plugin exemplo em {host}"])
