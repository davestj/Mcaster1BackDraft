#!/bin/bash
# ============================================================================
# Mcaster1BackDraft — Service Installer
#
# Installs the systemd unit, creates required directories, sets permissions,
# and enables the service for auto-start on boot.
#
# Usage: sudo bash installer/install-service.sh
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SERVICE_NAME="mcaster1backdraft"
SERVICE_FILE="${SCRIPT_DIR}/${SERVICE_NAME}.service"
SYSTEMD_DIR="/etc/systemd/system"
BINARY="${PROJECT_DIR}/src/Mcaster1BackDraft"
CONFIG="${PROJECT_DIR}/etc/Mcaster1BackDraft.yaml"
LOGS_DIR="${PROJECT_DIR}/logs"
USER="mediacast1"

echo "============================================"
echo " Mcaster1BackDraft Service Installer"
echo "============================================"
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Check binary exists
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    echo "Run 'make -j\$(nproc)' first."
    exit 1
fi

# Check config exists
if [ ! -f "$CONFIG" ]; then
    echo "ERROR: Config not found at $CONFIG"
    exit 1
fi

# Create PID directory permissions
echo "[1/6] Setting up /var/run permissions..."
touch /var/run/Mcaster1BackDraft.pid 2>/dev/null || true
chown ${USER}:${USER} /var/run/Mcaster1BackDraft.pid 2>/dev/null || true

# Create logs directory
echo "[2/6] Setting up logs directory..."
mkdir -p "$LOGS_DIR"
chown -R ${USER}:${USER} "$LOGS_DIR"

# Kill any running instance
echo "[3/6] Stopping any running instance..."
pkill -f Mcaster1BackDraft 2>/dev/null || true
sleep 2

# Install systemd unit
echo "[4/6] Installing systemd unit..."
cp "$SERVICE_FILE" "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
systemctl daemon-reload

# Enable for auto-start
echo "[5/6] Enabling service..."
systemctl enable "$SERVICE_NAME"

# Start service
echo "[6/6] Starting service..."
systemctl start "$SERVICE_NAME"
sleep 2

# Status check
echo ""
echo "============================================"
echo " Service Status"
echo "============================================"
systemctl status "$SERVICE_NAME" --no-pager -l

echo ""
echo "============================================"
echo " Commands"
echo "============================================"
echo "  sudo systemctl start ${SERVICE_NAME}"
echo "  sudo systemctl stop ${SERVICE_NAME}"
echo "  sudo systemctl restart ${SERVICE_NAME}"
echo "  sudo systemctl reload ${SERVICE_NAME}"
echo "  sudo systemctl status ${SERVICE_NAME}"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "  Ports: 9432 (WAF), 8862 (Web UI), 8832 (API)"
echo "  Config: ${CONFIG}"
echo "  Logs:   ${LOGS_DIR}/"
echo "  Binary: ${BINARY}"
echo ""
