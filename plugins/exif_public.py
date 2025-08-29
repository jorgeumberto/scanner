# plugins/exif_public.py
import os
import tempfile
from typing import Dict, Any, List, Tuple
from utils import run_cmd, Timer

PLUGIN_CONFIG_NAME = "exif_public"
PLUGIN_CONFIG_ALIASES = ["exiftool_images", "exif_geo"]

UUID_086 = "uuid-086"  # Item 86 — Metadados EXIF/Geo removidos de imagens públicas

def _download(url: str, timeout: int, out_path: str) -> bool:
    # baixa arquivo binário
    cmd = ["curl", "-sS", "-L", "-m", str(timeout), "-o", out_path, url]
    out = run_cmd(cmd, timeout=timeout+2)
    return os.path.exists(out_path) and os.path.getsize(out_path) > 0

def _exiftool(path: str, timeout: int) -> str:
    return run_cmd(["exiftool", path], timeout=timeout)

def _parse_exif(output: str) -> Tuple[bool, List[str]]:
    """
    Retorna (tem_metadado_sensivel, evidencias)
    Consideramos sensível: GPSLatitude, GPSLongitude, GPSPosition, Creator, Software, DateTimeOriginal, Camera Model, Serial.
    """
    if not output:
        return False, []
    sens = ["gpslatitude", "gpslongitude", "gpsposition", "creator", "artist",
            "datetimeoriginal", "model", "serial", "software"]
    evid = []
    low = output.lower()
    found = False
    for ln in output.splitlines():
        lnl = ln.lower()
        for s in sens:
            if lnl.startswith(s):
                evid.append(ln.strip())
                found = True
                break
    # também busca pelas chaves no blob
    if any(s in low for s in sens):
        found = True
    return found, evid

def _summarize(entries: List[str], checklist_name: str, max_lines: int = 20) -> str:
    if not entries:
        return f"Nenhum achado para {checklist_name}"
    body = [f"- {e}" for e in entries[:max_lines]]
    extra = len(entries) - len(body)
    if extra > 0:
        body.append(f"... +{extra} evidências")
    return "\n".join(body)

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/exif_public.json):
    {
      "timeout": 30,
      "images": ["/images/team.jpg", "/uploads/banner.png"],  # caminhos relativos OU URLs absolutas
      "extra_urls": [],
      "absolute_only": false                                   # se false, prefixa target quando for relativo
    }
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 30))
    imgs = cfg.get("images") or []
    extra_urls = cfg.get("extra_urls") or []
    absolute_only = bool(cfg.get("absolute_only", False))

    urls: List[str] = []
    for i in imgs:
        if i.startswith("http://") or i.startswith("https://"):
            urls.append(i)
        else:
            if not absolute_only:
                urls.append(target.rstrip("/") + "/" + i.lstrip("/"))
    urls += [u for u in extra_urls if u.startswith("http")]

    evid_all: List[str] = []

    with Timer() as t:
        for u in urls:
            try:
                with tempfile.TemporaryDirectory() as td:
                    fpath = os.path.join(td, "img.bin")
                    if not _download(u, timeout, fpath):
                        continue
                    exif = _exiftool(fpath, timeout=timeout)
                    has, evid = _parse_exif(exif)
                    if has:
                        if not evid:
                            evid = ["metadados sensíveis presentes (detalhe no arquivo completo)"]
                        for e in evid:
                            evid_all.append(f"{u} :: {e}")
            except Exception:
                continue

    duration = t.duration
    sev = "medium" if evid_all else "info"
    result = _summarize(evid_all, "Metadados EXIF/Geo em imagens públicas")

    return {
        "plugin": "ExifPublic",
        "result": [{
            "plugin_uuid": UUID_086,
            "scan_item_uuid": UUID_086,
            "result": result,
            "analysis_ai": ai_fn("ExifPublic", UUID_086, result),
            "severity": sev,
            "duration": duration,
            "auto": True
        }]
    }
