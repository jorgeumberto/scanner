from utils import run_cmd

def run(target: str, cfg: dict) -> str:
    """Executa teste de carga com ApacheBench (ab)."""
    requests = str(cfg.get("requests", 100))   # número total de requisições
    concurrency = str(cfg.get("concurrency", 10))  # usuários simultâneos

    cmd = ["ab", "-n", requests, "-c", concurrency, target]

    return run_cmd(cmd, timeout=120)
