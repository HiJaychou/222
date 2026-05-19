#!/bin/bash
set -u

APP_DIR="/opt/iwantrun-vpn-webui"
DATA_DIR="/etc/freedom-vpn/web"
SERVICE_FILE="/etc/systemd/system/iwantrun-vpn-web.service"
PANEL_PORT="$(shuf -i 20000-60000 -n 1)"
ADMIN_PASS="$(openssl rand -base64 18 | tr -d '=+/')"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

[[ "$EUID" -ne 0 ]] && echo -e "${RED}请使用 root 运行安装脚本。${NC}" && exit 1

echo -e "${YELLOW}正在安装 iwantrun VPN Web Manager...${NC}"

if command -v apt >/dev/null 2>&1; then
  apt update -y
  apt install -y python3 python3-venv python3-pip curl wget jq openssl iproute2
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 python3-pip curl wget jq openssl iproute
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 python3-pip curl wget jq openssl iproute
else
  echo -e "${RED}暂不支持当前系统。推荐 Ubuntu 22.04。${NC}"
  exit 1
fi

mkdir -p "$APP_DIR" "$DATA_DIR"
cp -r app requirements.txt "$APP_DIR/"

cd "$APP_DIR"
python3 -m venv venv
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r requirements.txt

cat > "$DATA_DIR/settings.json" <<EOF2
{
  "panel_port": ${PANEL_PORT},
  "panel_name": "自由档案馆 VPN Web Manager"
}
EOF2

"$APP_DIR/venv/bin/python" -m app.main --init-admin admin "$ADMIN_PASS"

cat > "$SERVICE_FILE" <<EOF2
[Unit]
Description=iwantrun VPN Web Manager
After=network.target

[Service]
User=root
WorkingDirectory=$APP_DIR
Environment=IWANTRUN_PANEL_HOST=0.0.0.0
Environment=IWANTRUN_PANEL_PORT=$PANEL_PORT
ExecStart=$APP_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PANEL_PORT
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF2

systemctl daemon-reload
systemctl enable iwantrun-vpn-web >/dev/null 2>&1
systemctl restart iwantrun-vpn-web

if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
fi

if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

SERVER_IP="$(curl -s4 --max-time 6 https://api.ipify.org || hostname -I | awk '{print $1}')"

echo
echo -e "${GREEN}安装完成！${NC}"
echo
echo "Web 面板地址： http://${SERVER_IP}:${PANEL_PORT}"
echo "管理员账号： admin"
echo "管理员密码： ${ADMIN_PASS}"
echo
echo -e "${YELLOW}重要提醒：请到 VPS 后台防火墙 / 安全组放行：${PANEL_PORT}/TCP${NC}"
echo
