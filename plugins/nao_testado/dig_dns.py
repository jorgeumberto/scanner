# plugins/dig_dns.py
from utils import run_cmd, Timer, extract_host
from typing import Dict, Any, List

# UUIDs placeholders – troque pelos reais dos IDs 10–13
UUIDS = {
    10: "uuid-010",  # DNS A/AAAA/MX/TXT
    11: "uuid-011",  # DNS reverso (PTR)
    12: "uuid-012",  # SPF (TXT v=spf1)
    13: "uuid-013",  # DMARC (TXT v=DMARC1)
}

def run_plugin(target: str, ai_fn):
    host = extract_host(target)
    items: List[Dict, Any] = []

    # 10) A/AAAA/MX/TXT
    with Timer() as t_a:
        out_a = []
        for rr in ["A", "AAAA", "MX", "TXT"]:
            cmd = ["dig", "+short", host, rr]
            out = run_cmd(cmd, timeout=10)
            out_a.append(f"== {rr} ==\n{out if out else '(vazio)'}")
        res10 = "\n".join(out_a).strip()
        uuid10 = UUIDS[10]
        items.append({
            "plugin_uuid": uuid10,
            "scan_item_uuid": uuid10,
            "result": res10,
            "analysis_ai": ai_fn("Dig", uuid10, res10),
            "severity": "info",
            "duration": t_a.duration,
            "auto": True
        })

    # 11) PTR
    with Timer() as t_ptr:
        ip = run_cmd(["dig", "+short", host], timeout=10).splitlines()
        ptrs: List[str] = []
        for ipaddr in ip:
            if ipaddr.strip():
                ptr = run_cmd(["dig", "+short", "-x", ipaddr.strip()], timeout=10)
                ptrs.append(f"{ipaddr} -> {ptr if ptr else '(sem PTR)'}")
        res11 = "\n".join(ptrs) if ptrs else "Não foi possível resolver A/AAAA"
        uuid11 = UUIDS[11]
        items.append({
            "plugin_uuid": uuid11,
            "scan_item_uuid": uuid11,
            "result": res11,
            "analysis_ai": ai_fn("Dig", uuid11, res11),
            "severity": "info",
            "duration": t_ptr.duration,
            "auto": True
        })

    # 12) SPF
    with Timer() as t_spf:
        spf = run_cmd(["dig", "+short", "TXT", host], timeout=10)
        hit_spf = ""
        for line in spf.splitlines():
            if "v=spf1" in line.lower():
                hit_spf = line
                break
        res12 = hit_spf if hit_spf else "SPF não encontrado"
        uuid12 = UUIDS[12]
        items.append({
            "plugin_uuid": uuid12,
            "scan_item_uuid": uuid12,
            "result": res12,
            "analysis_ai": ai_fn("Dig", uuid12, res12),
            "severity": "low" if not hit_spf else "info",
            "duration": t_spf.duration,
            "auto": True
        })

    # 13) DMARC
    with Timer() as t_dmarc:
        dmarc = run_cmd(["dig", "+short", "TXT", f"_dmarc.{host}"], timeout=10)
        hit_dm = ""
        for line in dmarc.splitlines():
            if "v=dmarc1" in line.lower():
                hit_dm = line
                break
        res13 = hit_dm if hit_dm else "DMARC não encontrado"
        uuid13 = UUIDS[13]
        items.append({
            "plugin_uuid": uuid13,
            "scan_item_uuid": uuid13,
            "result": res13,
            "analysis_ai": ai_fn("Dig", uuid13, res13),
            "severity": "low" if not hit_dm else "info",
            "duration": t_dmarc.duration,
            "auto": True
        })

    return {"plugin": "Dig", "result": items}
