from utils import run_cmd

def run(target):
    # Exemplo: verificar imagem teste.jpg baixada do alvo
    return run_cmd(["exiftool", "teste.jpg"])
