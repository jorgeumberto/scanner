from utils import run_cmd, extrair_host

def run(target):
    host = extrair_host(target)
    resultados = []
    comandos = [
        ["dig", host],
        ["dig", "A", host],
        ["dig", "MX", host],
        ["dig", "TXT", host],
    ]
    for cmd in comandos:
        resultados.append(f"=== {' '.join(cmd)} ===")
        resultados.append(run_cmd(cmd))
    return "\n".join(resultados)
