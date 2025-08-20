from utils import run_cmd

def run(target):
    return run_cmd(["curl", "-I", "-k", target])
