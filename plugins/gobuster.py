from utils import run_cmd

def run(target: str, cfg: dict) -> str:
    """Executa enumeração de diretórios com Gobuster usando config externa"""
    wordlist = cfg.get("wordlist", "configs/wordlists/directories.txt")
    threads = str(cfg.get("threads", 10))
    extra_flags = cfg.get("extra_flags", "")

    cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-t", threads]
    if extra_flags:
        cmd += extra_flags.split()

    return run_cmd(cmd)
