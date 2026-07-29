#!/usr/bin/env bash
set -e

echo "=== Adaptive Cognitive Firewall (ACF) Installer ==="

# 1. System packages check
echo "[*] Checking system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq libcap2-bin iptables python3 python3-venv

# 2. Set up Python virtual environment
if [ ! -d "acf-env" ]; then
    echo "[*] Creating virtual environment 'acf-env'..."
    python3 -m venv acf-env
fi

echo "[*] Installing Python dependencies..."
./acf-env/bin/pip install --upgrade pip -q
./acf-env/bin/pip install -r requirements.txt -q

# 3. Grant raw network socket capabilities to Python binary
echo "[*] Setting capabilities on Python executable..."
PYTHON_BIN="$(readlink -f ./acf-env/bin/python3)"
sudo setcap 'cap_net_raw,cap_net_admin=+eip' "$PYTHON_BIN" || echo "[!] Notice: Failed to setcap, fallback to running with sudo when needed."

# 4. Interactive Configuration
if [ ! -f "config.yml" ] && [ -f "config.yml.example" ]; then
    echo "[*] Creating config.yml from template..."
    cp config.yml.example config.yml

    read -p "Enter default network interface (e.g. eth0, lo, wlan0) [lo]: " IFACE
    IFACE=${IFACE:-lo}
    sed -i "s/interface: .*/interface: \"$IFACE\"/" config.yml

    echo "[+] Configuration saved to config.yml"
else
    echo "[!] Skipping config creation (config.yml exists or config.yml.example missing)."
fi

# 5. Create Systemd Service File (Optional)
read -p "Do you want to install ACF as a systemd service? (y/N): " INSTALL_SERVICE
if [[ "$INSTALL_SERVICE" =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/acf.service"
    sudo bash -c "cat <<SERVICE_EOF > $SERVICE_FILE
[Unit]
Description=Adaptive Cognitive Firewall (ACF) Engine
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/acf-env/bin/python3 main.py --mode detect
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF"

    sudo systemctl daemon-reload
    echo "[+] Service created at $SERVICE_FILE"
    echo "    To start: sudo systemctl start acf"
    echo "    To enable on boot: sudo systemctl enable acf"
fi

echo "=== Installation Complete! ==="
