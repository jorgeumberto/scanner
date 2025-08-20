from utils import run_cmd

def run(target):
    arquivos = ["robots.txt", "sitemap.xml", "humans.txt", "security.txt"]
    resultados = []
    for a in arquivos:
        resultados.append(f"=== {a} ===")
        resultados.append(run_cmd(["curl", "-k", f"{target}/{a}"]))
    return "\n".join(resultados)
