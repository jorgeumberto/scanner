from utils import run_cmd

def run(target: str, cfg: dict) -> str:
    return run_cmd(["curl", "-I", "-k", target])
