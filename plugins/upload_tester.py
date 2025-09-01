# plugins/upload_tester.py
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer
import tempfile, os, base64, json

PLUGIN_CONFIG_NAME = "upload_tester"
PLUGIN_CONFIG_ALIASES = ["upload_check","file_upload"]

UUID_026 = "uuid-026"  # (26) Uploads: validação de extensão/MIME/AV
UUID_058 = "uuid-058"  # (58) Validação de upload aplicada

SMALL_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQYV2P4//8/AwAI"
    "AQMFCW1P5wAAAABJRU5ErkJggg=="  # 1x1 png
)
TINY_PHP = "<?php echo 'x'; ?>"

def _mk_files(tmpdir: str) -> List[Tuple[str,str,str]]:
    paths = []
    png = os.path.join(tmpdir, "pixel.png")
    with open(png, "wb") as f: f.write(base64.b64decode(SMALL_PNG_B64))
    php = os.path.join(tmpdir, "test.php")
    with open(php, "w") as f: f.write(TINY_PHP)
    txt = os.path.join(tmpdir, "test.txt")
    with open(txt, "w") as f: f.write("hello")
    return [
        (png, "image/png", "pixel.png"),
        (php, "application/x-php", "test.php"),
        (txt, "text/plain", "test.txt"),
    ]

def _curl_upload(url: str, field: str, filepath: str, filename: str, mime: str, timeout: int, extra_headers: Dict[str,str], cookie: str) -> str:
    hdrs = []
    for k,v in (extra_headers or {}).items():
        hdrs += ["-H", f"{k}: {v}"]
    if cookie:
        hdrs += ["-H", f"Cookie: {cookie}"]
    cmd = [
        "bash","-lc",
        f'curl -sS -L -m {timeout} {" ".join(hdrs)} -F "{field}=@{filepath};type={mime};filename={filename}" "{url}" -i'
    ]
    return run_cmd(cmd, timeout=timeout+2)

def run_plugin(target: str, ai_fn, cfg: Dict[str,Any]=None):
    """
    cfg:
    {
      "timeout": 25,
      "endpoints": [{"url": "http://site/upload", "field": "file"}],
      "headers": {},
      "cookie": ""
    }
    """
    cfg = cfg or {}
    timeout  = int(cfg.get("timeout", 25))
    endpoints= cfg.get("endpoints") or []
    headers  = cfg.get("headers") or {}
    cookie   = cfg.get("cookie","")

    evid_allow, evid_block = [], []
    issues = 0

    with Timer() as t, tempfile.TemporaryDirectory() as td:
        files = _mk_files(td)

        if not endpoints:
            txt = "Sem endpoints configurados para upload (configs/upload_tester.json)."
            return {"plugin": "UploadTester", "result":[
                {"plugin_uuid": UUID_026, "scan_item_uuid": UUID_026, "result": txt, "analysis_ai": ai_fn("UploadTester", UUID_026, txt), "severity":"info", "duration": t.duration, "auto": True},
                {"plugin_uuid": UUID_058, "scan_item_uuid": UUID_058, "result": txt, "analysis_ai": ai_fn("UploadTester", UUID_058, txt), "severity":"info", "duration": t.duration, "auto": True}
            ]}

        for ep in endpoints:
            url   = ep.get("url")
            field = ep.get("field","file")
            for path, mime, fname in files:
                raw = _curl_upload(url, field, path, fname, mime, timeout, headers, cookie)
                status = next((ln.split()[1] for ln in raw.splitlines() if ln.upper().startswith("HTTP/")), "?")
                # Heurística: 200/201/202 + ausência de mensagens de erro => aceitou
                if status in ("200","201","202") and all(tok not in raw.lower() for tok in ["invalid", "error", "denied", "forbidden", "blocked"]):
                    issues += 1 if fname.endswith(".php") else 0
                    evid_allow.append(f"{url} :: {fname} ({mime}) -> {status}")
                else:
                    evid_block.append(f"{url} :: {fname} ({mime}) -> {status} (bloqueio/erro aparente)")

    res26 = "\n".join(f"- {e}" for e in evid_allow) if evid_allow else "Nenhum upload claramente aceito (ou bloqueado com erro)."
    res58 = "\n".join(f"- {e}" for e in evid_block) if evid_block else "Sem evidência de bloqueio explícito."

    sev26 = "medium" if issues else ("info" if evid_allow else "low")
    sev58 = "info" if evid_block else "low"

    return {"plugin":"UploadTester","result":[
        {"plugin_uuid": UUID_026, "scan_item_uuid": UUID_026, "result": res26, "analysis_ai": ai_fn("UploadTester", UUID_026, res26), "severity": sev26, "duration": t.duration, "auto": True},
        {"plugin_uuid": UUID_058, "scan_item_uuid": UUID_058, "result": res58, "analysis_ai": ai_fn("UploadTester", UUID_058, res58), "severity": sev58, "duration": t.duration, "auto": True}
    ]}
