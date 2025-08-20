from utils import run_cmd, extrair_host

def run(target):
    host = extrair_host(target)
    return run_cmd(["nmap", "--script", "http-methods", "-p80,443", host])
