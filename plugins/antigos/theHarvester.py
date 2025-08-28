from utils import run_cmd, extrair_host

def run(target):
    host = extrair_host(target)
    return run_cmd(["theHarvester", "-d", host, "-b", "all", "-l", "100"])
