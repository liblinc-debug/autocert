#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="autocert"
SERVICE_USER_WAS_SET="${AUTOCERT_USER+x}"
INSTALL_DIR_WAS_SET="${AUTOCERT_INSTALL_DIR+x}"
SERVICE_HOST_WAS_SET="${AUTOCERT_HOST+x}"
SERVICE_PORT_WAS_SET="${AUTOCERT_PORT+x}"
SERVICE_USER="${AUTOCERT_USER:-autocert}"
INSTALL_DIR="${AUTOCERT_INSTALL_DIR:-/opt/autocert}"
DATA_DIR="${AUTOCERT_DATA_DIR:-/var/lib/autocert}"
DATA_DIR_WAS_SET="${AUTOCERT_DATA_DIR+x}"
BACKUP_DIR="${AUTOCERT_BACKUP_DIR:-/var/backups/autocert}"
SERVICE_HOST="${AUTOCERT_HOST:-0.0.0.0}"
SERVICE_PORT="${AUTOCERT_PORT:-5000}"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXISTING_SERVICE=0

usage() {
  cat <<'EOF'
AutoCert systemd 一键安装脚本

用法：
  sudo ./install.sh

可选环境变量：
  AUTOCERT_USER          运行用户，默认 autocert
  AUTOCERT_INSTALL_DIR   程序目录，默认 /opt/autocert
  AUTOCERT_DATA_DIR      数据目录，默认 /var/lib/autocert
  AUTOCERT_BACKUP_DIR    升级备份目录，默认 /var/backups/autocert
  AUTOCERT_HOST          监听地址，默认 0.0.0.0
  AUTOCERT_PORT          监听端口，默认 5000

示例：
  sudo AUTOCERT_PORT=5005 ./install.sh
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "错误：install.sh 仅支持 Linux。" >&2
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "错误：请使用 sudo ./install.sh 运行。" >&2
  exit 1
fi
if [[ -f "${UNIT_FILE}" ]]; then
  EXISTING_SERVICE=1
  EXISTING_USER="$(sed -n 's/^User=//p' "${UNIT_FILE}" | tail -n 1)"
  EXISTING_INSTALL_DIR="$(sed -n 's/^WorkingDirectory=//p' "${UNIT_FILE}" | tail -n 1)"
  EXISTING_DATA_DIR="$(sed -n 's/^Environment=APP_DATA_DIR=//p' "${UNIT_FILE}" | tail -n 1)"
  EXISTING_HOST="$(sed -n 's/^ExecStart=.*--host=\([^ ]*\).*$/\1/p' "${UNIT_FILE}" | tail -n 1)"
  EXISTING_PORT="$(sed -n 's/^ExecStart=.*--port=\([^ ]*\).*$/\1/p' "${UNIT_FILE}" | tail -n 1)"
  if [[ -z "${SERVICE_USER_WAS_SET}" && -n "${EXISTING_USER}" ]]; then
    SERVICE_USER="${EXISTING_USER}"
  fi
  if [[ -z "${INSTALL_DIR_WAS_SET}" && -n "${EXISTING_INSTALL_DIR}" ]]; then
    INSTALL_DIR="${EXISTING_INSTALL_DIR}"
  fi
  if [[ -z "${SERVICE_HOST_WAS_SET}" && -n "${EXISTING_HOST}" ]]; then
    SERVICE_HOST="${EXISTING_HOST}"
  fi
  if [[ -z "${SERVICE_PORT_WAS_SET}" && -n "${EXISTING_PORT}" ]]; then
    SERVICE_PORT="${EXISTING_PORT}"
  fi
  if [[ -n "${EXISTING_DATA_DIR}" ]]; then
    if [[ -n "${DATA_DIR_WAS_SET}" && "${DATA_DIR}" != "${EXISTING_DATA_DIR}" ]]; then
      echo "错误：现有服务使用数据目录 ${EXISTING_DATA_DIR}，升级时不能改为 ${DATA_DIR}。" >&2
      exit 1
    fi
    DATA_DIR="${EXISTING_DATA_DIR}"
  fi
fi
for command in systemctl python3 useradd tar; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "错误：系统缺少 ${command}。" >&2
    exit 1
  fi
done
if [[ ! -d /run/systemd/system ]]; then
  echo "错误：当前 Linux 未使用 systemd 启动。" >&2
  exit 1
fi
if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
  echo "错误：需要 Python 3.10 或更高版本。" >&2
  exit 1
fi
if [[ ! "${SERVICE_PORT}" =~ ^[0-9]+$ ]] || ((SERVICE_PORT < 1 || SERVICE_PORT > 65535)); then
  echo "错误：AUTOCERT_PORT 必须在 1–65535 之间。" >&2
  exit 1
fi
if [[ ! "${SERVICE_HOST}" =~ ^[A-Za-z0-9.:-]+$ ]]; then
  echo "错误：AUTOCERT_HOST 格式无效。" >&2
  exit 1
fi
if [[ ! "${SERVICE_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "错误：AUTOCERT_USER 格式无效。" >&2
  exit 1
fi
for path in "${INSTALL_DIR}" "${DATA_DIR}" "${BACKUP_DIR}"; do
  if [[ ! "${path}" =~ ^/[A-Za-z0-9._/-]+$ || "${path}" == "/" ]]; then
    echo "错误：程序、数据和备份目录必须是仅含字母、数字、点、下划线、横线和斜线的绝对路径，且不能为根目录。" >&2
    exit 1
  fi
done
if [[ "${INSTALL_DIR}" == "${DATA_DIR}" || "${DATA_DIR}" == "${INSTALL_DIR}/"* || "${INSTALL_DIR}" == "${DATA_DIR}/"* ]]; then
  echo "错误：程序目录和数据目录不能相同或互相包含。" >&2
  exit 1
fi
for required in app.py requirements.txt templates static crt; do
  if [[ ! -e "${SOURCE_DIR}/${required}" ]]; then
    echo "错误：安装包缺少 ${required}。" >&2
    exit 1
  fi
done

echo "[1/6] 创建运行用户和目录"
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "${DATA_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
SERVICE_GROUP="$(id -gn "${SERVICE_USER}")"
install -d -m 0755 -o root -g root "${INSTALL_DIR}"
install -d -m 0700 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${DATA_DIR}"

TARGET_HAS_DATA=0
if [[ -f "${DATA_DIR}/cert_deployer.db" ]]; then
  TARGET_HAS_DATA=1
elif ((EXISTING_SERVICE)); then
  for item in app.secret credentials.key uploads; do
    if [[ -e "${DATA_DIR}/${item}" ]]; then
      TARGET_HAS_DATA=1
      break
    fi
  done
fi
if ((TARGET_HAS_DATA)); then
  echo "      检测到现有服务数据，保持 ${DATA_DIR} 不变"
elif [[ -d "${SOURCE_DIR}/data" ]]; then
  echo "      首次安装：迁移当前项目 data 到 ${DATA_DIR}"
  tar -C "${SOURCE_DIR}/data" --exclude='./cert_deployer.db' --exclude='./cert_deployer.db-*' -cf - . | tar -C "${DATA_DIR}" -xf -
  if [[ -f "${SOURCE_DIR}/data/cert_deployer.db" ]]; then
    db_tmp="${DATA_DIR}/.cert_deployer.db.migrating.$$"
    python3 - "${SOURCE_DIR}/data/cert_deployer.db" "${db_tmp}" <<'PY'
import sqlite3
import sys

source = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
target = sqlite3.connect(sys.argv[2])
with target:
    source.backup(target)
source.close()
target.close()
PY
    mv "${db_tmp}" "${DATA_DIR}/cert_deployer.db"
  fi
else
  echo "      首次安装：未发现现有 data，服务启动时将自动初始化"
fi
install -d -m 0700 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${DATA_DIR}/.ssh"
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${DATA_DIR}"
chmod 0700 "${DATA_DIR}"
find "${DATA_DIR}" -type d -exec chmod 0700 {} +
find "${DATA_DIR}" -type f -exec chmod 0600 {} +

echo "[2/6] 安装程序文件"
if [[ "${SOURCE_DIR}" != "${INSTALL_DIR}" ]]; then
  tar -C "${SOURCE_DIR}" \
    --exclude='./data' \
    --exclude='./.venv' \
    --exclude='./.git' \
    --exclude='./__pycache__' \
    --exclude='./.pytest_cache' \
    --exclude='./.DS_Store' \
    -cf - . | tar -C "${INSTALL_DIR}" -xf -
else
  echo "      当前已在安装目录中，跳过程序文件复制"
fi
chown -R root:root "${INSTALL_DIR}"

echo "[3/6] 创建 Python 虚拟环境"
if [[ ! -x "${INSTALL_DIR}/.venv/bin/python" ]]; then
  if ! python3 -m venv "${INSTALL_DIR}/.venv"; then
    echo "错误：无法创建虚拟环境，请安装 python3-venv 后重试。" >&2
    exit 1
  fi
fi
"${INSTALL_DIR}/.venv/bin/python" -m pip install --disable-pip-version-check -r "${INSTALL_DIR}/requirements.txt"
chown -R root:root "${INSTALL_DIR}/.venv"

echo "[4/6] 写入 systemd 服务"
unit_tmp="$(mktemp)"
SERVICE_STOPPED=0
cleanup() {
  rm -f "${unit_tmp}"
  if ((SERVICE_STOPPED)); then
    echo "安装中断，正在尝试恢复 ${SERVICE_NAME} 服务……" >&2
    systemctl start "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
cat >"${unit_tmp}" <<EOF
[Unit]
Description=AutoCert Digital Certificate Deployment Center
Documentation=https://github.com/liblinc-debug/autocert
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${INSTALL_DIR}
Environment=APP_DATA_DIR=${DATA_DIR}
Environment=HOME=${DATA_DIR}
Environment=TZ=Asia/Shanghai
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=-/etc/default/autocert
ExecStart=${INSTALL_DIR}/.venv/bin/waitress-serve --host=${SERVICE_HOST} --port=${SERVICE_PORT} app:app
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF
install -m 0644 -o root -g root "${unit_tmp}" "${UNIT_FILE}"

echo "[5/6] 启用并启动服务"
if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
  systemctl stop "${SERVICE_NAME}.service"
  SERVICE_STOPPED=1
fi
if ((TARGET_HAS_DATA)); then
  install -d -m 0700 -o root -g root "${BACKUP_DIR}"
  backup_file="${BACKUP_DIR}/autocert-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
  echo "      升级前备份数据到 ${backup_file}"
  tar -C "${DATA_DIR}" -czf "${backup_file}" .
  chmod 0600 "${backup_file}"
fi
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"
SERVICE_STOPPED=0

echo "[6/6] 验证服务"
if ! systemctl is-active --quiet "${SERVICE_NAME}.service"; then
  echo "安装失败，最近的服务日志如下：" >&2
  journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager >&2 || true
  exit 1
fi

echo
echo "AutoCert 安装完成。"
if [[ "${SERVICE_HOST}" == "0.0.0.0" ]]; then
  echo "访问地址：http://<服务器IP>:${SERVICE_PORT}"
else
  echo "访问地址：http://${SERVICE_HOST}:${SERVICE_PORT}"
fi
echo "初始账号：libin / admin（首次登录后请立即修改密码）"
echo "服务状态：systemctl status ${SERVICE_NAME}"
echo "实时日志：journalctl -u ${SERVICE_NAME} -f"
echo "数据目录：${DATA_DIR}"
if ((TARGET_HAS_DATA)); then
  echo "升级备份：${backup_file}"
fi
