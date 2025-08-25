from utils import run_cmd, plugin_wrapper

@plugin_wrapper
def run(target: str, cfg: dict) -> str:
    """Fingerprint de tecnologias web (WhatWeb)"""
    return run_cmd(["whatweb", target])

def format_output(raw_output: str) -> str:
    """Formata saída do WhatWeb para relatório"""
    if " " in raw_output:
        url_status, detalhes = raw_output.split(" ", 1)
    else:
        url_status, detalhes = raw_output, ""

    detalhes_fmt = []
    for item in detalhes.split(","):
        item = item.strip()
        if item:
            detalhes_fmt.append(f"- {item}")

    saida = [f"Alvo: {url_status}"]
    if detalhes_fmt:
        saida.append("Tecnologias detectadas:")
        saida.extend(detalhes_fmt)

    return "\n".join(saida)
