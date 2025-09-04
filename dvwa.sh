#!/usr/bin/env bash
set -euo pipefail

NAME="dvwa"
IMAGE="vulnerables/web-dvwa:latest"
HOST_IP="${HOST_IP:-192.168.248.111}"   # <- se não definir, usa todas as interfaces
PORT="8080"

need_docker() { command -v docker >/dev/null 2>&1 || { echo "[ERRO] Docker não encontrado."; exit 1; }; }
running() { docker ps --format '{{.Names}}' | grep -qx "$NAME"; }

up() {
  need_docker
  docker pull "$IMAGE"
  if running; then
    echo "[i] $NAME já está rodando."
  else
    docker run -d --name "$NAME" -p "${HOST_IP}:${PORT}:80" --restart unless-stopped -e TZ=UTC "$IMAGE"
    echo "[+] $NAME iniciado."
  fi
  echo "URL: http://${HOST_IP}:${PORT}"
  echo "- Acesse /setup.php e clique 'Create / Reset Database'"
  echo "- Credenciais: admin / password"
}

down() { running && docker rm -f "$NAME" >/dev/null && echo "[+] $NAME removido." || echo "[i] $NAME não está rodando."; }
logs() { docker logs -f "$NAME"; }
restart() { down; up; }
status() { docker ps -a --filter "name=$NAME"; }

case "${1:-}" in
  up) up ;;
  down) down ;;
  logs) logs ;;
  restart) restart ;;
  status) status ;;
  *) echo "uso: $0 {up|down|logs|restart|status}"; exit 1 ;;
esac
