from utils import run_cmd, extrair_host

def run(target: str, cfg: dict) -> str:
    """Executa varredura Nmap personalizada usando config externa"""
    host = extrair_host(target)

    ports = cfg.get("ports", "1-1000")
    scripts = cfg.get("scripts", "default")
    extra_flags = cfg.get("extra_flags", "-sV")

    cmd = ["nmap", "-p", ports]
    if scripts:
        cmd += ["--script", scripts]
    if extra_flags:
        cmd += extra_flags.split()
    cmd.append(host)

    return run_cmd(cmd, timeout=300)
