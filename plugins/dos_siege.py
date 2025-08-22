from utils import run_cmd

def run(target: str, cfg: dict) -> str:
    """Executa teste de stress com Siege."""
    duration = cfg.get("duration", "30s")     # tempo do teste
    concurrency = str(cfg.get("concurrency", 10))  # usuários simultâneos

    cmd = ["siege", "-c", concurrency, "-t", duration, target]

    return run_cmd(cmd, timeout=180)
