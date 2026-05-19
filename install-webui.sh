#!/bin/bash
set -e

# ========================================================
# 自由档案馆 | iwantrun.com VPN Web Manager 安装脚本
# 仓库地址：https://github.com/HiJaychou/222
# ========================================================

REPO_ZIP_URL="https://github.com/HiJaychou/222/archive/refs/heads/main.zip"

APP_DIR="/opt/iwantrun-vpn-webui"
DATA_DIR="/etc/freedom-vpn/web"
SERVICE_NAME="iwantrun-vpn-web"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TMP_DIR="/tmp/iwantrun-vpn-webui-install"

SB_BIN="/usr/local/bin/sing-box"

PANEL_PORT="$(shuf -i 20000-60000 -n 1)"
ADMIN_PASS="$(openssl rand -base64 18 | tr -d '=+/')"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo_line() {
  echo -e "${CYAN}============================================================${NC}"
}

die() {
  echo -e "${RED}错误：$1${NC}"
  exit 1
}

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    die "请使用 root 用户运行此脚本。"
  fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      echo "amd64"
      ;;
    aarch64|arm64)
      echo "arm64"
      ;;
    *)
      die "暂不支持当前架构：$(uname -m)"
      ;;
  esac
}

install_dependencies() {
  echo -e "${YELLOW}正在安装系统依赖...${NC}"

  if command -v apt >/dev/null 2>&1; then
    apt update -y
    apt install -y python3 python3-venv python3-pip curl wget jq openssl iproute2 unzip tar ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip curl wget jq openssl iproute unzip tar ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip curl wget jq openssl iproute unzip tar ca-certificates
  else
    die "暂不支持当前系统。推荐 Ubuntu 22.04。"
  fi
}

install_singbox_core() {
  local arch sb_ver url

  if [[ -x "$SB_BIN" ]]; then
    echo -e "${GREEN}检测到 sing-box 已安装：$($SB_BIN version | head -n 1)${NC}"
    return
  fi

  echo -e "${YELLOW}未检测到 sing-box，正在安装 sing-box 最新版...${NC}"

  arch="$(detect_arch)"

  sb_ver="$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name | sed 's/^v//')"

  if [[ -z "$sb_ver" || "$sb_ver" == "null" ]]; then
    die "无法获取 sing-box 最新版本。"
  fi

  url="https://github.com/SagerNet/sing-box/releases/download/v${sb_ver}/sing-box-${sb_ver}-linux-${arch}.tar.gz"

  rm -rf /tmp/sing-box-install
  mkdir -p /tmp/sing-box-install

  wget -qO /tmp/sing-box-install/sb.tar.gz "$url" || die "下载 sing-box 失败。"
  tar -xzf /tmp/sing-box-install/sb.tar.gz -C /tmp/sing-box-install || die "解压 sing-box 失败。"

  find /tmp/sing-box-install -type f -name sing-box -exec mv {} "$SB_BIN" \;
  chmod +x "$SB_BIN"

  rm -rf /tmp/sing-box-install

  if [[ ! -x "$SB_BIN" ]]; then
    die "sing-box 安装失败。"
  fi

  echo -e "${GREEN}sing-box 安装完成：v${sb_ver}${NC}"
}

cleanup_old_install() {
  echo -e "${YELLOW}正在清理旧的 Web 面板安装文件...${NC}"

  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true

  rm -f "$SERVICE_FILE"
  systemctl daemon-reload || true

  rm -rf "$APP_DIR"
  mkdir -p "$APP_DIR" "$DATA_DIR"
}

download_project() {
  echo -e "${YELLOW}正在下载 Web 面板完整项目...${NC}"

  rm -rf "$TMP_DIR"
  mkdir -p "$TMP_DIR"

  wget -O "$TMP_DIR/source.zip" "$REPO_ZIP_URL"

  unzip -q "$TMP_DIR/source.zip" -d "$TMP_DIR"

  SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name '222-*' | head -n 1)"

  if [[ -z "$SRC_DIR" ]]; then
    die "没有找到解压后的项目目录。"
  fi

  if [[ ! -d "$SRC_DIR/app" ]]; then
    die "GitHub 仓库里没有 app 目录，请确认 app/ 已经上传。"
  fi

  if [[ ! -f "$SRC_DIR/requirements.txt" ]]; then
    die "GitHub 仓库里没有 requirements.txt，请确认已经上传。"
  fi

  cp -r "$SRC_DIR/app" "$APP_DIR/"
  cp "$SRC_DIR/requirements.txt" "$APP_DIR/"
}

install_python_env() {
  echo -e "${YELLOW}正在创建 Python 虚拟环境...${NC}"

  cd "$APP_DIR"

  python3 -m venv venv

  echo -e "${YELLOW}正在安装 Python 依赖...${NC}"

  "$APP_DIR/venv/bin/pip" install --upgrade pip
  "$APP_DIR/venv/bin/pip" install -r requirements.txt
}

init_settings_and_admin() {
  echo -e "${YELLOW}正在初始化 Web 面板配置...${NC}"

  mkdir -p "$DATA_DIR"

  cat > "$DATA_DIR/settings.json" <<EOF
{
  "panel_port": ${PANEL_PORT},
  "panel_name": "自由档案馆 VPN Web Manager"
}
EOF

  echo -e "${YELLOW}正在初始化管理员账号...${NC}"

  "$APP_DIR/venv/bin/python" -m app.main --init-admin admin "$ADMIN_PASS"
}

create_service() {
  echo -e "${YELLOW}正在创建 systemd 服务...${NC}"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=iwantrun VPN Web Manager
After=network.target

[Service]
User=root
WorkingDirectory=${APP_DIR}
Environment=IWANTRUN_PANEL_HOST=0.0.0.0
Environment=IWANTRUN_PANEL_PORT=${PANEL_PORT}
ExecStart=${APP_DIR}/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PANEL_PORT}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
  systemctl restart "$SERVICE_NAME"

  sleep 2

  if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${RED}Web 面板启动失败，最近日志如下：${NC}"
    journalctl -u "$SERVICE_NAME" -n 100 --no-pager
    exit 1
  fi
}

open_firewall() {
  echo -e "${YELLOW}正在尝试放行系统防火墙端口：${PANEL_PORT}/TCP${NC}"

  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
  fi

  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

get_server_ip() {
  SERVER_IP="$(curl -s4 --max-time 6 https://api.ipify.org || true)"

  if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(hostname -I | awk '{print $1}')"
  fi

  if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="你的服务器IP"
  fi
}

print_result() {
  echo_line
  echo -e "${GREEN}Web 管理面板安装完成！${NC}"
  echo_line
  echo
  echo -e "访问地址：${GREEN}http://${SERVER_IP}:${PANEL_PORT}${NC}"
  echo
  echo -e "管理员账号：${GREEN}admin${NC}"
  echo -e "管理员密码：${GREEN}${ADMIN_PASS}${NC}"
  echo

  if [[ -x "$SB_BIN" ]]; then
    echo -e "sing-box：${GREEN}$($SB_BIN version | head -n 1)${NC}"
  else
    echo -e "sing-box：${RED}未安装${NC}"
  fi

  echo
  echo -e "${YELLOW}重要提醒：${NC}"
  echo -e "请到 VPS 后台防火墙 / 安全组手动放行：${GREEN}${PANEL_PORT}/TCP${NC}"
  echo
  echo -e "${YELLOW}如果无法打开网页，请运行下面命令检查：${NC}"
  echo
  echo "systemctl status ${SERVICE_NAME} --no-pager"
  echo "journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  echo "ss -lntup | grep ${PANEL_PORT}"
  echo
  echo_line
}

main() {
  check_root

  echo_line
  echo -e "${GREEN}自由档案馆 | iwantrun.com VPN Web Manager 安装脚本${NC}"
  echo_line

  install_dependencies
  install_singbox_core
  cleanup_old_install
  download_project
  install_python_env
  init_settings_and_admin
  create_service
  open_firewall
  get_server_ip

  rm -rf "$TMP_DIR"

  print_result
}

main "$@"
