#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  PRISM — Azure VM Deployment Script
#  Run this ON the Azure VM after uploading the repo
# ═══════════════════════════════════════════════════════════
set -e

APP_DIR="$HOME/APTRACE-Malware-retrace"

echo "════════════════════════════════════════"
echo "  PRISM Azure Deployment"
echo "════════════════════════════════════════"

# ── 1. System packages ──
echo "[1/6] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv nginx

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "       Python $PY_VER"

# ── 2. Virtual environment ──
echo "[2/6] Setting up Python venv..."
cd "$APP_DIR"
python3 -m venv venv
source venv/bin/activate

# ── 3. Install dependencies ──
echo "[3/6] Installing Python packages..."
pip install --upgrade pip -q
pip install -r backend/requirements.txt -q
pip install -r requirements.txt -q

# ── 4. Verify config ──
echo "[4/6] Checking configuration..."
if [ ! -f backend/.env ]; then
    echo "  ERROR: backend/.env not found! Copy it to the VM first."
    exit 1
fi
echo "  .env found"

if [ -f ml/models/PRISM_model.pkl ]; then
    echo "  ML model found"
else
    echo "  WARNING: ml/models/PRISM_model.pkl missing — ML predictions won't work"
fi

# ── 5. Systemd service ──
echo "[5/6] Creating systemd service..."
sudo tee /etc/systemd/system/prism.service > /dev/null << EOF
[Unit]
Description=PRISM APT Attribution Dashboard
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR/backend
Environment="PATH=$APP_DIR/venv/bin:/usr/bin"
ExecStart=$APP_DIR/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable prism
sudo systemctl restart prism

# ── 6. Nginx reverse proxy (port 80 → 8000) ──
echo "[6/6] Configuring Nginx..."
sudo tee /etc/nginx/sites-available/prism > /dev/null << 'NGINX'
server {
    listen 80;
    server_name 57.159.31.206;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 180s;
        proxy_connect_timeout 10s;
    }
}
NGINX

sudo ln -sf /etc/nginx/sites-available/prism /etc/nginx/sites-enabled/prism
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx

echo ""
echo "════════════════════════════════════════"
echo "  PRISM deployed!"
echo "════════════════════════════════════════"
echo ""
echo "  Dashboard:  http://57.159.31.206/dashboard.html"
echo "  Health:     http://57.159.31.206/health"
echo ""
echo "  Commands:"
echo "    sudo systemctl status prism"
echo "    sudo systemctl restart prism"
echo "    sudo journalctl -u prism -f"
echo ""
