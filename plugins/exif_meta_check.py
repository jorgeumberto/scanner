# plugins/exif_meta_check.py
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import run_cmd, Timer
import os, tempfile, re

PLUGIN_CONFIG_NAME = "exif_meta_check"
PLUGIN_CONFIG_ALIASES = ["exif", "metadata"]

UUID_086 = "uuid-086"  # (86) Metadados EXIF/Geo removidos

IMG_EXT = (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp")

SENSITIVE_KEYS = ["GPS", "GPSPosition", "GPSLatitude", "GPSLongitude", "Camera", "Make", "Model", "Serial", "Author", "Artist", "Creator"]

def _download(url: str, timeout: int) -> str:
    fd, path = tempfile.mkstemp(prefix="img_", suffix=".bin"); os.close(fd)
    _ = run_cmd(["curl", "-sS", "-L", "-m", str(timeout), "-o", path, url], timeout=timeout+2)
    return path

def _extract_img_urls(html: str, base: str) -> List[str]:
    urls = []
    # pega tokens simples src/href
    for token in re.findall(r'(?:src|href)=["\']([^"\']+)["\']', html, flags=re.I):
        if any(token.lower().endswith(ext) for ext in IMG_EXT):
            u = token if token.startswith("http") else urljoin(base, token)
            urls.append(u)
    return urls

def run_plugin(target: str, ai_fn, cfg: Dict[str, Any] = None):
    """
    cfg (configs/exif_meta_check.json):
    { "paths": ["/images/", "/img/", "/media/"], "max_files": 5, "timeout": 25 }
    """
    cfg = cfg or {}
    paths = cfg.get("paths") or ["/images/", "/img/", "/media/"]
    max_files = int(cfg.get("max_files", 5))
    timeout = int(cfg.get("timeout", 25))

    evid: List[str] = []
    checked = 0

    with Timer() as t:
        for p in paths:
            base = urljoin(target.rstrip("/") + "/", p.lstrip("/"))
            html = run_cmd(["curl", "-sS", "-L", "-m", "10", base], timeout=12)
            urls = _extract_img_urls(html, base)
            for img_url in urls:
                try:
                    path = _download(img_url, timeout)
                    meta = run_cmd(["exiftool", "-s", "-s", "-s", path], timeout=10)
                    os.remove(path)
                    low = meta.lower()
                    if meta.strip():
                        if any(k.lower() in low for k in (k for k in SENSITIVE_KEYS)):
                            evid.append(f"{img_url} :: EXIF com campos sensíveis presentes")
                        else:
                            evid.append(f"{img_url} :: EXIF presente (sem campos sensíveis)")
                    else:
                        evid.append(f"{img_url} :: sem metadados EXIF")
                    checked += 1
                    if checked >= max_files: break
                except Exception as e:
                    evid.append(f"{img_url} :: erro ao checar EXIF ({e})")
            if checked >= max_files: break

    sev = "medium" if any("sensíveis" in e for e in evid) else ("low" if any("EXIF presente" in e for e in evid) else "info")
    summary = "\n".join(f"- {e}" for e in evid) if evid else "Nenhum achado para EXIF/Geo em imagens públicas"

    item = {
        "plugin_uuid": UUID_086,
        "scan_item_uuid": UUID_086,
        "result": summary,
        "analysis_ai": ai_fn("ExifMetaCheck", UUID_086, summary),
        "severity": sev,
        "duration": t.duration,
        "auto": True
    }
    return {"plugin": "ExifMetaCheck", "result": [item]}
