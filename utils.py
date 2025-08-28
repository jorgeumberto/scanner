import subprocess
import shlex
import time
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List

def run_cmd(cmd, timeout: int = 120) -> str:
    """Executa um comando e retorna stdout+stderr (strip)."""
    try:
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        return (out + ("\n" + err if err else "")).strip()
    except Exception as e:
        return f"[ERRO ao executar {' '.join(cmd) if isinstance(cmd, list) else cmd}] {e}"

def extract_host(target: str) -> str:
    try:
        host = urlparse(target).hostname
        return host or target
    except Exception:
        return target

class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self
    def __exit__(self, *exc):
        self.t1 = time.perf_counter()
    @property
    def duration(self) -> float:
        return round(self.t1 - self.t0, 3)
