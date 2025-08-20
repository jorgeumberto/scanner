from utils import run_cmd

def run(target):
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    return run_cmd(["gobuster", "dir", "-u", target, "-w", wordlist, "--no-error"])
