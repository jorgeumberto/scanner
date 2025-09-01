# plugins/session_id_entropy.py
from typing import Dict, Any, List
from utils import run_cmd, Timer
import re, math

PLUGIN_CONFIG_NAME = "session_id_entropy"
PLUGIN_CONFIG_ALIASES = ["sess_entropy"]
UUID_041 = "uuid-041"  # (41)

COOKIE_RE = re.compile(r"^set-cookie:\s*([^=]+)=([^;]+);", re.I)

def _headers(url: str, timeout: int) -> List[str]:
    raw = run_cmd(["bash","-lc", f'curl -sSI -m {timeout} "{url}"'], timeout=timeout+2)
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]

def _shannon(s: str) -> float:
    if not s: return 0.0
    from collections import Counter
    N = len(s); c = Counter(s)
    return -sum((n/N) * math.log2(n/N) for n in c.values())

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 12))
    samples = int(cfg.get("samples", 6))

    vals = []
    with Timer() as t:
        for _ in range(max(2, samples)):
            for h in _headers(target, timeout):
                m = COOKIE_RE.search(h)
                if m:
                    vals.append(m.group(2))
                    break

    ent = [_shannon(v) for v in vals if v]
    avg = (sum(ent)/len(ent)) if ent else 0.0
    msg = [f"sessões coletadas: {len(vals)}", f"entropia média ≈ {avg:.2f} bits/char"]
    sev = "info" if avg >= 3.5 else ("low" if avg >= 2.5 else "medium")
    txt = "\n".join(f"- {m}" for m in msg) if vals else "Nenhum Set-Cookie coletado"
    item = {"plugin_uuid":UUID_041,"scan_item_uuid":UUID_041,"result":txt,"analysis_ai":ai_fn("SessionIDEntropy",UUID_041,txt),"severity":sev,"duration":t.duration,"auto":True}
    return {"plugin":"SessionIDEntropy","result":[item]}
