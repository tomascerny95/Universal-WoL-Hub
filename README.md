# 🌐 Universal-WoL-Hub

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Raspberry%20Pi-brightgreen.svg)](#)
[![Framework: FastAPI](https://img.shields.io/badge/framework-FastAPI-teal.svg)](https://fastapi.tiangolo.com/)

A lightweight, driverless, cross-platform **LAN Watchdog & Wake-on-LAN (WoL)** web hub.

Continuously monitors connected devices on your local network (LAN) in real-time, displays their online/offline state, and allows you to wake up PCs with a single click — all through a modern dark-mode web dashboard.

---

## ✨ Features
- **🚀 Truly Cross-Platform:** Runs seamlessly on **Windows** and **Linux / Raspberry Pi**.
- **🛡️ Driverless & Rootless:**
  - **Windows:** Uses native `iphlpapi.dll` (`SendARP`) — no Npcap or WinPcap required.
  - **Linux / Raspberry Pi:** Uses kernel-level `/proc/net/arp` and standard ICMP — no root permissions required.
- **🔒 Tailscale Aware:** Smart IP detection automatically filters out virtual VPN adapters (`100.x.y.z`) and routes Wake-on-LAN packets via the physical network interface using directed subnet broadcasts.
- **⚡ In-Memory Watchdog:** All scanning state is kept in RAM, preventing wear and tear on Raspberry Pi microSD cards.
- **⭐ Persistent Favorites:** Save your most-used devices with custom names (stored in browser `localStorage`).
- **🎨 Sleek Web UI:** Responsive dark teal dashboard with live polling on port **2222**.

---

## 🚀 Quick Start on Raspberry Pi / Linux

### Automated In-Place Installation (Recommended)

```bash
# 1. Clone the repository
cd ~
git clone https://github.com/tomascerny95/Universal-WoL-Hub.git

# 2. Enter folder, make script executable, and run installer
cd Universal-WoL-Hub
chmod +x setup_wol_hub.sh
sudo bash ./setup_wol_hub.sh
```

The script automatically detects your username, sets up an isolated virtual environment, configures the systemd background service, and starts the hub immediately.

---

## 🌐 Accessing the Dashboard

Open your web browser and navigate to:
```text
http://<DEVICE_IP>:2222
```
*(Also accessible via your Tailscale IP or `http://<hostname>.local:2222`).*

---

## 🔄 Updating to the Latest Version

To update the hub to the latest GitHub version without losing settings:

```bash
cd ~/Universal-WoL-Hub
git fetch origin && git reset --hard origin/main && chmod +x setup_wol_hub.sh && sudo bash ./setup_wol_hub.sh
```

---

## 🖥️ Running on Windows

1. Clone or download the repository.
2. Install Python 3.8+ and dependencies:
   ```bash
   pip install fastapi uvicorn
   ```
3. Run the application:
   ```bash
   python universal-woL-hub.py
   ```
4. Open `http://localhost:2222` in your browser.

---

## 🛠️ Service Management (systemd on Linux)

```bash
# Check service status
sudo systemctl status wol-hub

# Restart service
sudo systemctl restart wol-hub

# View live application logs
journalctl -u wol-hub -f
```

---

## 📄 License
This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
