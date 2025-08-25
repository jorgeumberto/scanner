source venv/bin/activate

pip install --upgrade pip
pip install python-dotenv openai
pip install python-owasp-zap-v2.4



zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.key=12345
python main.py


    "plugins.curl_headers",
    "plugins.curl_files",
    "plugins.nmap_services",
    "plugins.nmap_http_methods",
    "plugins.dig_dns",
    "plugins.ssl_scan",
    "plugins.whatweb",
    "plugins.wafw00f",
    "plugins.nikto",
    "plugins.gobuster",
    "plugins.theHarvester",
    "plugins.sublist3r",
    "plugins.dnsrecon",
    "plugins.testssl",
    "plugins.hydra_login",
    "plugins.zap_api",
    "plugins.dos_ab",
    "plugins.dos_siege",
    "plugins.dos_slowloris"
]