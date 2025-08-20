source venv/bin/activate

pip install --upgrade pip
pip install python-dotenv openai
pip install python-owasp-zap-v2.4
zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.key=12345