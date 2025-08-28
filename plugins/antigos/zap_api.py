from zapv2 import ZAPv2
import time

def run(target: str, cfg: dict) -> str:
    """
    Executa scan com OWASP ZAP via API.
    Necessário rodar:
      zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.key=<apikey>
    """

    api_key = cfg.get("apikey", None)
    mode = cfg.get("mode", "baseline")
    timeout = int(cfg.get("timeout", 600))

    zap = ZAPv2(apikey=api_key,
                proxies={'http': 'http://127.0.0.1:8080',
                         'https': 'http://127.0.0.1:8080'})

    resultado = []
    start_time = time.time()

    if mode == "baseline":
        # Apenas spider
        spider_scan_id = zap.spider.scan(target)
        while int(zap.spider.status(spider_scan_id)) < 100:
            if time.time() - start_time > timeout:
                return "[ERRO] Timeout no Spider do ZAP"
            time.sleep(2)
        resultado.append(f"[+] Spider concluído para {target}")

    elif mode == "full":
        # Spider
        spider_scan_id = zap.spider.scan(target)
        while int(zap.spider.status(spider_scan_id)) < 100:
            if time.time() - start_time > timeout:
                return "[ERRO] Timeout no Spider do ZAP"
            time.sleep(2)
        resultado.append(f"[+] Spider concluído para {target}")

        # Active Scan
        ascan_scan_id = zap.ascan.scan(target)
        while int(zap.ascan.status(ascan_scan_id)) < 100:
            if time.time() - start_time > timeout:
                return "[ERRO] Timeout no Active Scan do ZAP"
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
