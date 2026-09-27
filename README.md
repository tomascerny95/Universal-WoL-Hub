# 🌐 Universal-WoL-Hub

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Raspberry%20Pi-brightgreen.svg)]()
[![Framework: FastAPI](https://img.shields.io/badge/framework-FastAPI-teal.svg)](https://fastapi.tiangolo.com/)

A lightweight, driverless, cross-platform **LAN Watchdog & Wake-on-LAN (WoL)** web hub.

Continuously monitors connected devices on your local network (LAN) in real-time, displays their online/offline state, and allows you to wake up PCs with a single click — all through a modern dark-mode web dashboard.

---

## ✨ Features

- **🚀 Truly Cross-Platform:** Runs seamlessly on **Windows** and **Linux / Raspberry Pi**.
- **🛡️ Driverless & Rootless:**
  - **Windows:** Uses native `iphlpapi.dll` (`SendARP`) — **no Npcap or WinPcap required**.
  - **Linux / Raspberry Pi:** Uses kernel-level `/proc/net/arp` and standard ICMP — **no `sudo` or root permissions required**.
- **🔒 Tailscale Aware:** Smart IP detection automatically filters out virtual VPN adapters (`100.x.y.z`) and routes Wake-on-LAN packets via the physical network interface using directed subnet broadcasts.
- **⚡ In-Memory Watchdog:** All scanning state is kept in RAM (`discovered_devices`), preventing wear and tear on Raspberry Pi microSD cards.
- **⭐ Persistent Favorites:** Save your most-used devices with custom names (stored in browser `localStorage`).
- **🎨 Sleek Web UI:** Responsive dark teal dashboard with live polling on port **2222**.

---

## 🛠️ Requirements

- **Python 3.8+**
- Dependencies: `fastapi`, `uvicorn`

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/tomascerny95/Universal-WoL-Hub.git
cd Universal-WoL-Hub
```

### 2. Install dependencies
```bash
pip install fastapi uvicorn
```

### 3. Run the application
```bash
python universal-woL-hub.py
```

### 4. Access the Dashboard
Open your web browser and navigate to:
```text
http://localhost:2222
```
*(If running on a Raspberry Pi or remote server, access it via `http://<DEVICE_IP>:2222` or through your Tailscale IP).*

---

## ⚙️ Configuration

You can easily adjust the port and host settings directly in `universal-woL-hub.py`:

```python
SERVER_PORT = 2222       # Default web port
SERVER_HOST = "0.0.0.0"   # Binds to all network interfaces
```

---

## 🍓 Optional: Run as a Systemd Service (Raspberry Pi / Linux)

To keep the hub running 24/7 in the background and start automatically on boot:

1. Create a systemd service file:
```bash
sudo nano /etc/systemd/system/wol-hub.service
```

2. Paste the following configuration (adjust path/user if needed):
```ini
[Unit]
Description=Universal WoL Hub & LAN Watchdog
After=network.target

[Service]
User=pi
WorkingDirectory=/home/pi/Universal-WoL-Hub
ExecStart=/usr/bin/python3 /home/pi/Universal-WoL-Hub/universal-woL-hub.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable wol-hub
sudo systemctl start wol-hub
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
