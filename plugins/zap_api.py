from zapv2 import ZAPv2
import time

def run(target: str) -> str:
    """
    Executa um scan no ZAP (spider + active scan).
    É necessário que o ZAP esteja rodando em modo daemon:
      zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.key=12345
    """

    api_key = "12345"  # configure a sua api.key no zap.sh
    zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8080',
                                         'https': 'http://127.0.0.1:8080'})

    resultado = []

    # Spider (crawler)
    spider_scan_id = zap.spider.scan(target)
    while int(zap.spider.status(spider_scan_id)) < 100:
        time.sleep(2)
    resultado.append(f"[+] Spider concluído para {target}")

    # Active Scan
    ascan_scan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(ascan_scan_id)) < 100:
        time.sleep(5)
    resultado.append(f"[+] Active Scan concluído para {target}")

    # Coleta de alertas
    alerts = zap.core.alerts(baseurl=target)
    if alerts:
        resultado.append("\n=== ALERTAS ENCONTRADOS ===")
        for a in alerts:
            resultado.append(f"- {a['alert']} | Risco: {a['risk']} | {a['url']}")
    else:
        resultado.append("\nNenhum alerta encontrado pelo ZAP.")

    return "\n".join(resultado)
