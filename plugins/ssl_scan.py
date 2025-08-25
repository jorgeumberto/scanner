from utils import run_cmd, extrair_host, plugin_wrapper

@plugin_wrapper
def run(target: str, cfg: dict) -> str:
    host = extrair_host(target)
    return run_cmd(["sslscan", host])
