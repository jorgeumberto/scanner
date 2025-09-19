# plugins/upload_tester.py
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
from utils import run_cmd  # não usamos mais Timer daqui
import tempfile, os, base64, time

PLUGIN_CONFIG_NAME = "upload_tester"
PLUGIN_CONFIG_ALIASES = ["upload_check", "file_upload"]

# UUIDs (descritores no seu padrão)
UUID_026 = "uuid-026-upload-policy"      # (26) Uploads: validação de extensão/MIME/AV
UUID_058 = "uuid-058-upload-validation"  # (58) Validação de upload aplicada (bloqueios)

# Payloads básicos
SMALL_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQYV2P4//8/AwAI"
    "AQMFCW1P5wAAAABJRU5ErkJggg=="  # 1x1 png
)
TINY_PHP = "<?php echo 'x'; ?>"
PLAIN_TXT = "hello"

# Palavras-chave que indicam bloqueio/erro (pt/en)
NEG_TOKENS = [
    "invalid", "error", "denied", "forbidden", "blocked", "not allowed", "disallowed",
    "unsupported", "mismatch", "token mismatch", "csrf", "too large", "payload too large",
    "conteúdo muito grande", "não permitido", "negado", "proibido", "bloqueado",
    "falhou", "inválido", "erro", "não suportado"
]

# -------------------- helpers de normalização --------------------

def _norm_endpoints(eps: Any) -> List[Dict[str, str]]:
    """
    Aceita:
      - "https://site/upload"
      - {"url": "...", "field": "file"}
      - ["https://a", "https://b"]
      - [{"url": "...", "field":"..."}]
    Retorna: [{"url": "...", "field": "..."}]
    """
    out: List[Dict[str, str]] = []
    if not eps:
        return out
    if isinstance(eps, str):
        return [{"url": eps, "field": "file"}]
    if isinstance(eps, dict):
        url = eps.get("url")
        if url:
            out.append({"url": url, "field": eps.get("field", "file")})
        return out
    if isinstance(eps, list):
        for item in eps:
            if isinstance(item, str):
                out.append({"url": item, "field": "file"})
            elif isinstance(item, dict) and item.get("url"):
                out.append({"url": item["url"], "field": item.get("field", "file")})
        return out
    return out

def _norm_headers(headers: Any) -> Dict[str, str]:
    """
    Aceita:
      - {"X-Token": "...", "Accept":"..."}
      - ["X-Token: ...", "Accept: ..."]
    """
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    if isinstance(headers, list):
        out: Dict[str, str] = {}
        for line in headers:
            if isinstance(line, str) and ":" in line:
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
        return out
    return {}

# -------------------- geração de payloads --------------------

def _mk_default_files(tmpdir: str) -> List[Tuple[str, str, str]]:
    """
    Cria arquivos locais e retorna [(path, mime, filename)].
    """
    files: List[Tuple[str, str, str]] = []

    png = os.path.join(tmpdir, "pixel.png")
    with open(png, "wb") as f:
        f.write(base64.b64decode(SMALL_PNG_B64))
    files.append((png, "image/png", "pixel.png"))

    php = os.path.join(tmpdir, "test.php")
    with open(php, "w") as f:
        f.write(TINY_PHP)
    files.append((php, "application/x-php", "test.php"))

    txt = os.path.join(tmpdir, "test.txt")
    with open(txt, "w") as f:
        f.write(PLAIN_TXT)
    files.append((txt, "text/plain", "test.txt"))

    # Variantes comuns de bypass
    php_txt = os.path.join(tmpdir, "test.php.txt")
    with open(php_txt, "w") as f:
        f.write(TINY_PHP)
    files.append((php_txt, "text/plain", "test.php.txt"))

    php_jpg = os.path.join(tmpdir, "shell.php.jpg")
    with open(php_jpg, "wb") as f:
        f.write(b"\xFF\xD8\xFF\xDB\x00")  # header JPEG mínimo (fake)
    files.append((php_jpg, "image/jpeg", "shell.php.jpg"))

    return files

def _merge_extra_payloads(tmpdir: str, defaults: List[Tuple[str, str, str]], extra: List[Dict[str, str]]) -> List[Tuple[str, str, str]]:
    """
    Adiciona payloads via cfg["payloads"] = [{"filename": "...", "mime":"...", "content_b64":"..."}] ou "content".
    """
    files = list(defaults)
    if not extra:
        return files
    for p in extra:
        try:
            name = p.get("filename", "blob.bin")
            mime = p.get("mime", "application/octet-stream")
            path = os.path.join(tmpdir, name)
            if "content_b64" in p:
                with open(path, "wb") as f:
                    f.write(base64.b64decode(p["content_b64"]))
            else:
                with open(path, "w", encoding="utf-8", newline="") as f:
                    f.write(p.get("content", ""))
            files.append((path, mime, name))
        except Exception:
            # ignora payload mal-formado
            continue
    return files

def _build_headers(headers: Dict[str, str], cookie: str) -> List[str]:
    hdrs: List[str] = []
    for k, v in (headers or {}).items():
        hdrs += ["-H", f"{k}: {v}"]
    if cookie:
        hdrs += ["-H", f"Cookie: {cookie}"]
    return hdrs

# -------------------- HTTP helpers --------------------

def _curl_upload(url: str, field: str, filepath: str, filename: str, mime: str, timeout: int, headers: Dict[str, str], cookie: str) -> str:
    """
    Faz upload multipart (-F) seguindo redirects (-L) e incluindo cabeçalhos (-i).
    Retorna headers+body de TODAS as respostas; depois extraímos a última.
    """
    hdrs = _build_headers(headers, cookie)
    cmd = [
        "bash", "-lc",
        f'curl -sS -i -L --max-redirs 3 -m {timeout} '
        + " ".join(hdrs)
        + f' -F "{field}=@{filepath};type={mime};filename={filename}" '
        + f'"{url}"'
    ]
    return run_cmd(cmd, timeout=timeout + 2)

def _extract_last_response(raw: str) -> Tuple[str, Dict[str, List[str]], str]:
    """
    A partir do texto de resposta de `curl -i -L`, extrai:
    - último status code
    - dict de cabeçalhos (lower, múltiplos valores)
    - corpo (apenas da última resposta)
    """
    lines = raw.splitlines()
    last_http = -1
    for i, ln in enumerate(lines):
        if ln.upper().startswith("HTTP/"):
            last_http = i
    if last_http == -1:
        return "?", {}, raw

    headers: Dict[str, List[str]] = {}
    status = "?"
    end_headers_idx = len(lines) - 1
    for j in range(last_http, len(lines)):
        ln = lines[j]
        if j == last_http:
            parts = ln.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = parts[1]
            continue
        if not ln.strip():
            end_headers_idx = j
            break
        if ":" in ln:
            name, val = ln.split(":", 1)
            key = name.strip().lower()
            val = val.strip()
            headers.setdefault(key, []).append(val)

    body = "\n".join(lines[end_headers_idx + 1:]) if end_headers_idx + 1 < len(lines) else ""
    return status, headers, body

def _looks_accepted(status: str, body_lower: str) -> bool:
    """
    Heurística de aceite: 2xx SEM mensagens típicas de erro.
    """
    if status and status.isdigit():
        code = int(status)
        if 200 <= code < 300:
            return not any(tok in body_lower for tok in NEG_TOKENS)
    return False

def _final_ct(headers: Dict[str, List[str]]) -> str:
    vals = headers.get("content-type", [])
    return vals[0] if vals else ""

# -------------------- run_plugin --------------------

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg exemplos válidos:
      {"endpoints": "https://site/upload"}                         # string
      {"endpoints": ["https://a/upload","https://b/upload"]}       # lista de strings
      {"endpoints": {"url":"https://site/upload","field":"file"}}  # dict único
      {"endpoints": [{"url":"https://site/upload","field":"f"}]}   # lista de dicts

    Campos opcionais:
      "timeout": 25,
      "headers": {"X-CSRF-Token": "..."}  OU  ["X-CSRF-Token: ...", "Accept: ..."]
      "cookie": "session=...",
      "payloads": [ {"filename":"evil.asp","mime":"text/plain","content":"<%...%>"} ]
    """
    cfg = cfg or {}
    timeout   = int(cfg.get("timeout", 25))
    endpoints = _norm_endpoints(cfg.get("endpoints"))
    headers   = _norm_headers(cfg.get("headers"))
    cookie    = str(cfg.get("cookie", "")) if cfg.get("cookie", "") is not None else ""
    extra_p   = cfg.get("payloads") or []

    t0_total = time.perf_counter()

    if not endpoints:
        txt = "Sem endpoints configurados para upload (configs/upload_tester.json)."
        duration = time.perf_counter() - t0_total
        return {
            "plugin": "upload_tester",
            "category": "File Uploads",
            "result": [
                {
                    "plugin_uuid": UUID_026,
                    "scan_item_uuid": UUID_026,
                    "item_name": "Upload policy overview",
                    "result": txt,
                    "analysis_ai": ai_fn("UploadTester", UUID_026, txt),
                    "severity": "info",
                    "duration": duration,
                    "auto": True,
                    "reference": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                },
                {
                    "plugin_uuid": UUID_058,
                    "scan_item_uuid": UUID_058,
                    "item_name": "Upload validation evidence",
                    "result": txt,
                    "analysis_ai": ai_fn("UploadTester", UUID_058, txt),
                    "severity": "info",
                    "duration": duration,
                    "auto": True,
                    "reference": "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                }
            ]
        }

    evid_allow: List[str] = []
    evid_block: List[str] = []
    php_accepted = 0

    with tempfile.TemporaryDirectory() as td:
        defaults = _mk_default_files(td)
        files = _merge_extra_payloads(td, defaults, extra_p)

        for ep in endpoints:
            url   = ep["url"]
            field = ep.get("field", "file")

            up = urlparse(url)
            label = f"{up.scheme}://{up.netloc}{up.path or '/'}"

            for path, mime, fname in files:
                try:
                    raw = _curl_upload(url, field, path, fname, mime, timeout, headers, cookie)
                    status, hdrs, body = _extract_last_response(raw)
                except Exception as e:
                    evid_block.append(f"{label} :: {fname} ({mime}) -> erro ao enviar: {type(e).__name__}")
                    continue

                ct = _final_ct(hdrs)
                bl = body.lower()

                if _looks_accepted(status, bl):
                    if fname.endswith(".php"):
                        php_accepted += 1
                    evid_allow.append(f"{label} :: {fname} ({mime}) -> {status} | ct:{ct or '—'} | body:{len(body)}B")
                else:
                    tag = "bloqueio/erro aparente"
                    try:
                        code = int(status) if status and status.isdigit() else 0
                        if 400 <= code < 500:
                            tag = "bloqueio (4xx)"
                        elif code >= 500:
                            tag = "erro servidor (5xx)"
                    except Exception:
                        pass
                    evid_block.append(f"{label} :: {fname} ({mime}) -> {status or '?'} | {tag}")

    # ---- Montagem dos resultados ----
    if evid_allow:
        res26 = "Uploads aceitos:\n" + "\n".join(f"- {e}" for e in evid_allow)
    else:
        res26 = "Nenhum upload claramente aceito (todas as tentativas indicam bloqueio/erro)."

    if evid_block:
        res58 = "Evidências de bloqueio/erro:\n" + "\n".join(f"- {e}" for e in evid_block)
    else:
        res58 = "Sem evidência de bloqueio explícito (todas as respostas parecem 2xx)."

    # Severidades
    sev26 = "high" if php_accepted > 0 else ("info" if evid_allow else "low")
    sev58 = "info" if evid_block else "low"

    duration_total = time.perf_counter() - t0_total

    return {
        "plugin": "upload_tester",
        "category": "File Uploads",
        "result": [
            {
                "plugin_uuid": UUID_026,
                "scan_item_uuid": UUID_026,
                "item_name": "Upload policy overview",
                "result": res26,
                "analysis_ai": ai_fn("UploadTester", UUID_026, res26),
                "severity": sev26,
                "duration": duration_total,
                "auto": True,
                "reference": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
            },
            {
                "plugin_uuid": UUID_058,
                "scan_item_uuid": UUID_058,
                "item_name": "Upload validation evidence",
                "result": res58,
                "analysis_ai": ai_fn("UploadTester", UUID_058, res58),
                "severity": sev58,
                "duration": duration_total,
                "auto": True,
                "reference": "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
            }
        ]
    }
