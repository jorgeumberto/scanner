# plugins/upload_tester.py
import os
import tempfile
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "upload_tester"
PLUGIN_CONFIG_ALIASES = ["uploads", "file_upload"]

UUID_026 = "uuid-026"  # ID 26 — Uploads de arquivos: validação de extensão/MIME/antivírus
# Opcional: se quiser separar o checklist 58 também:
# UUID_058 = "uuid-058"  # ID 58 — Validação de upload (extensão/MIME) aplicada

def _mk_file(path: str, content: bytes) -> None:
    with open(path, "wb") as f:
        f.write(content)

def _curl_multipart(url: str, timeout: int, field: str, file_path: str, filename: str, mime: str, headers: List[str], extra_fields: Dict[str, str]) -> str:
    cmd = ["curl", "-sS", "-i", "-m", str(timeout)]
    for h in headers or []:
        cmd += ["-H", h]
    # campo do arquivo
    file_spec = f"{field}=@{file_path};type={mime};filename={filename}"
    cmd += ["-F", file_spec]
    # campos extras
    for k, v in (extra_fields or {}).items():
        cmd += ["-F", f"{k}={v}"]
    cmd += [url]
    return run_cmd(cmd, timeout=timeout+2)

def _parse_http_code(hdrs: str) -> int:
    # procura o último status na resposta (em caso de redirects)
    for ln in reversed(hdrs.splitlines()):
        if ln.startswith("HTTP/"):
            try:
                return int(ln.split()[1])
            except Exception:
                pass
    return 0

def _extract_location(hdrs: str) -> str:
    for ln in hdrs.splitlines():
        if ln.lower().startswith("location:"):
            return ln.split(":", 1)[1].strip()
    return ""

def _http_get(url: str, timeout: int) -> str:
    return run_cmd(["curl", "-sS", "-m", str(timeout), url], timeout=timeout+2)

def _summarize(lines: List[str], checklist_name: str, max_lines: int = 12) -> str:
    if not lines:
        return f"Nenhum achado para {checklist_name}"
    body = [f"- {l}" for l in lines[:max_lines]]
    extra = len(lines) - len(body)
    if extra > 0:
        body.append(f"... +{extra} evidências")
    return "\n".join(body)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/upload_tester.json):
    {
      "timeout": 30,
      "endpoints": ["/upload"],            # endpoints de upload (POST multipart)
      "field_name": "file",
      "headers": [],
      "extra_fields": {},
      "tests": [
        {"ext": "php", "mime": "image/jpeg"},
        {"ext": "html", "mime": "image/png"},
        {"ext": "svg", "mime": "image/svg+xml"},
        {"ext": "txt", "mime": "text/plain"}
      ],
      "absolute_only": false,
      "verify_public_read": true
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 30))
    endpoints = cfg.get("endpoints") or ["/upload"]
    field = cfg.get("field_name", "file")
    headers = cfg.get("headers") or []
    extra_fields = cfg.get("extra_fields") or {}
    tests = cfg.get("tests") or [
        {"ext": "php", "mime": "image/jpeg"},
        {"ext": "html", "mime": "text/html"},
        {"ext": "svg", "mime": "image/svg+xml"},
        {"ext": "txt", "mime": "text/plain"}
    ]
    absolute_only = bool(cfg.get("absolute_only", False))
    verify_public = bool(cfg.get("verify_public_read", True))

    evidences: List[str] = []
    worst = "info"

    with Timer() as t:
        for ep in endpoints:
            if ep.startswith("http://") or ep.startswith("https://"):
                url = ep
            else:
                if absolute_only:
                    continue
                url = target.rstrip("/") + "/" + ep.lstrip("/")

            for test in tests:
                ext = test.get("ext", "txt")
                mime = test.get("mime", "application/octet-stream")

                with tempfile.TemporaryDirectory() as td:
                    file_path = os.path.join(td, f"probe.{ext}")
                    # conteúdo totalmente inofensivo
                    _mk_file(file_path, b"pentest-upload-probe")

                    hdrs = _curl_multipart(
                        url=url,
                        timeout=timeout,
                        field=field,
                        file_path=file_path,
                        filename=os.path.basename(file_path),
                        mime=mime,
                        headers=headers,
                        extra_fields=extra_fields
                    )
                    code = _parse_http_code(hdrs)
                    loc  = _extract_location(hdrs)

                    msg = f"{url} :: upload {ext} como {mime} -> HTTP {code}"
                    if loc:
                        msg += f" | Location: {loc}"

                    # tentativa de leitura pública (se o servidor devolveu uma URL)
                    if verify_public and loc and (loc.startswith("http://") or loc.startswith("https://")):
                        body = _http_get(loc, timeout)
                        if body:
                            msg += " | leitura pública OK"
                            # heurística de severidade
                            if ext in ("php", "jsp", "asp", "aspx"):
                                worst = "high"
                            elif ext in ("html", "svg"):
                                worst = "medium"
                            else:
                                worst = "low" if worst not in ("high", "medium") else worst
                        else:
                            msg += " | leitura pública FALHOU"

                    # se o código foi 200/201/204, também é um indicador
                    if code in (200, 201, 204):
                        if ext in ("php", "jsp", "asp", "aspx"):
                            worst = "high"
                        elif ext in ("html", "svg"):
                            worst = "medium"
                        else:
                            if worst not in ("high", "medium"):
                                worst = "low"

                    evidences.append(msg)

    duration = t.duration
    checklist = "Uploads de arquivos: validação de extensão/MIME"
    result = _summarize(evidences, checklist)

    return {
        "plugin": "UploadTester",
        "result": [{
            "plugin_uuid": UUID_026,
            "scan_item_uuid": UUID_026,
            "result": result,
            "analysis_ai": ai_fn("UploadTester", UUID_026, result),
            "severity": worst,
            "duration": duration,
            "auto": True
        }]
    }
