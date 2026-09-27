from concurrent.futures import ThreadPoolExecutor
import ctypes
from datetime import datetime
import os
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

# --- CONFIGURATION ---
SERVER_PORT = 2222
SERVER_HOST = "0.0.0.0"

# --- OPERATING SYSTEM DETECTION ---
CURRENT_OS = platform.system()  # 'Windows' or 'Linux'
print(f"[*] Detected Operating System: {CURRENT_OS}")

app = FastAPI(title="Universal LAN Watchdog & Wake-on-LAN Hub")

# --- THREAD-SAFE IN-MEMORY STORAGE ---
devices_lock = threading.Lock()
discovered_devices = {}
name_cache = {}  # MAC -> Hostname cache
SUBNET_PREFIX = ""
DEFAULT_BROADCAST = "255.255.255.255"

# --- EMBEDDED OUI VENDOR DATABASE ---
MAC_VENDORS = {
    # Apple
    "60:9B:B4": "Apple Device",
    "C8:E7:D8": "Apple Device",
    "F0:18:98": "Apple Device",
    "AC:BC:32": "Apple Device",
    "BC:D0:74": "Apple Device",
    "70:EE:50": "Apple Device",
    "9A:3B:EF": "Apple (Private MAC)",
    # Raspberry Pi
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    # Espressif (IoT smart plugs, sensors, ESP32/ESP8266)
    "3C:3B:AD": "Espressif Smart Home",
    "24:62:AB": "Espressif Smart Home",
    "30:AE:A4": "Espressif Smart Home",
    "84:F3:EB": "Espressif Smart Home",
    "C4:4F:33": "Espressif Smart Home",
    # Samsung
    "88:49:2D": "Samsung Device",
    "50:01:D9": "Samsung Smart TV",
    "A4:77:33": "Samsung Device",
    "BC:44:86": "Samsung Mobile",
    # Networking / Routers (TP-Link, Xiaomi, Asus, Netgear)
    "78:84:3C": "Router / Gateway",
    "50:C7:BF": "TP-Link Smart Device",
    "70:4F:57": "TP-Link Device",
    "C0:06:C3": "Xiaomi Device",
    "00:1F:C6": "ASUS Device",
    # Intel / PC Components
    "00:1E:67": "Intel PC",
    "A4:4C:C8": "Intel PC",
    "68:05:CA": "Intel PC",
    "F8:63:3F": "Intel PC",
    "C8:5B:76": "Intel PC",
    # Gaming & Smart Media
    "00:04:1F": "Sony PlayStation",
    "F8:46:1C": "Sony PlayStation",
    "00:1C:62": "LG Electronics",
    "A8:23:FE": "LG Smart TV",
    "44:65:0D": "Amazon Echo",
    "68:54:5A": "Amazon FireTV",
    "F4:F5:D8": "Google / Nest",
    # Virtualization
    "00:50:56": "VMware Virtual",
    "00:15:5D": "Hyper-V Virtual",
}


# --- 1. NETWORK INTERFACE RESOLUTION (TAILSCALE-AWARE) ---
def get_lan_network_info():
    """Finds physical LAN IP, ignoring Tailscale (100.x.y.z) and loopbacks."""
    detected_ip = None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        temp_ip = s.getsockname()[0]
        s.close()
        if not temp_ip.startswith("100.") and not temp_ip.startswith("127."):
            detected_ip = temp_ip
    except Exception:
        pass

    if not detected_ip and CURRENT_OS == "Linux":
        try:
            output = subprocess.check_output(
                ["hostname", "-I"], text=True
            ).strip()
            for ip in output.split():
                if not ip.startswith("100.") and not ip.startswith("127."):
                    detected_ip = ip
                    break
        except Exception:
            pass

    if not detected_ip:
        detected_ip = "192.168.0.4"

    parts = detected_ip.split(".")
    subnet_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."
    broadcast_ip = f"{subnet_prefix}255"
    return subnet_prefix, broadcast_ip


# --- 2. MULTI-PROTOCOL HOSTNAME RESOLVER ---
def query_netbios_name(ip: str, timeout: float = 0.3) -> str | None:
    """Queries Windows NetBIOS Name Service (UDP 137)."""
    # NetBIOS status request packet for '*'
    packet = (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(1024)
            if len(data) > 56:
                num_names = data[56]
                if num_names > 0 and len(data) >= 57 + 18:
                    raw_name = data[57 : 57 + 15]
                    name = raw_name.decode("ascii", errors="ignore").strip()
                    if name and all(c.isprintable() for c in name):
                        return name
    except Exception:
        pass
    return None


def query_mdns_name(ip: str, timeout: float = 0.4) -> str | None:
    """Queries mDNS / Bonjour (UDP 5353) via PTR reverse lookup for Apple/Linux/IoT."""
    try:
        parts = ip.split(".")
        rev_ip = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"

        # Build DNS PTR packet
        query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for label in rev_ip.split("."):
            query += bytes([len(label)]) + label.encode("ascii")
        query += b"\x00\x00\x0c\x00\x01"  # Type PTR (12), Class IN (1)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, ("224.0.0.251", 5353))
            data, _ = s.recvfrom(1024)

            # Look for '.local' in response
            if b".local" in data:
                idx = data.find(b".local")
                # Step backwards to find start of domain label
                start = max(0, idx - 30)
                sub = data[start:idx]
                clean = re.sub(r"[^a-zA-Z0-9\-_]", " ", sub.decode("latin1"))
                words = clean.strip().split()
                if words:
                    cand = words[-1]
                    if len(cand) >= 2 and not cand.lower().startswith("arpa"):
                        return cand
    except Exception:
        pass
    return None


def smart_resolve_hostname(ip: str, mac: str) -> str:
    """Smart resolver hierarchy:

    1. Cache -> 2. NetBIOS (Windows) -> 3. mDNS (Apple/IoT) -> 4. Reverse DNS -> 5. MAC Vendor -> 6. Fallback
    """
    if mac in name_cache:
        return name_cache[mac]

    # Layer 1: NetBIOS (Best for Windows PCs)
    nb_name = query_netbios_name(ip)
    if nb_name:
        name_cache[mac] = nb_name
        return nb_name

    # Layer 2: mDNS / Bonjour (Apple, Linux, IoT)
    mdns_name = query_mdns_name(ip)
    if mdns_name:
        name_cache[mac] = mdns_name
        return mdns_name

    # Layer 3: Standard DNS
    try:
        dns_name = socket.gethostbyaddr(ip)[0]
        if dns_name and not dns_name.startswith("192.168."):
            clean_dns = dns_name.split(".")[0]
            name_cache[mac] = clean_dns
            return clean_dns
    except Exception:
        pass

    # Layer 4: MAC OUI Vendor lookup
    mac_prefix = mac.upper()[:8]
    if mac_prefix in MAC_VENDORS:
        vendor_name = f"{MAC_VENDORS[mac_prefix]} (.{ip.split('.')[-1]})"
        name_cache[mac] = vendor_name
        return vendor_name

    # Layer 5: Clean fallback
    fallback = f"Device .{ip.split('.')[-1]}"
    return fallback


# --- 3. OS-SPECIFIC ARP RESOLUTION ---
def get_mac_windows(ip_str: str) -> str | None:
    try:
        dest_ip = struct.unpack("<I", socket.inet_aton(ip_str))[0]
        mac_buffer = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.iphlpapi.SendARP(
            dest_ip, 0, ctypes.byref(mac_buffer), ctypes.byref(mac_len)
        )
        if res == 0:
            return ":".join(f"{b:02X}" for b in mac_buffer)
    except Exception:
        pass
    return None


def ping_ip_linux(ip_str: str):
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_str],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def read_linux_arp_table():
    devices = {}
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        flags = parts[2]
                        mac = parts[3].upper()
                        if (
                            flags == "0x2"
                            and mac != "00:00:00:00:00:00"
                            and len(mac) == 17
                        ):
                            devices[mac] = ip
    except Exception as e:
        print(f"[Linux ARP Error] {e}")
    return devices


# --- 4. WAKE-ON-LAN ENGINE ---
def send_wol_packet(mac: str, broadcast_ip: str, port: int = 9):
    clean_mac = re.sub(r"[:\.-]", "", mac)
    if len(clean_mac) != 12:
        raise ValueError("Invalid MAC address! Must contain exactly 12 hex characters.")

    magic_packet = bytes.fromhex("FF" * 6 + clean_mac * 16)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic_packet, (broadcast_ip, port))


# --- 5. BACKGROUND WATCHDOG THREAD ---
def watchdog_background_loop():
    global discovered_devices, SUBNET_PREFIX, DEFAULT_BROADCAST
    SUBNET_PREFIX, DEFAULT_BROADCAST = get_lan_network_info()
    print(f"[Watchdog] Active on subnet {SUBNET_PREFIX}0/24 (Broadcast: {DEFAULT_BROADCAST})")

    while True:
        try:
            target_ips = [f"{SUBNET_PREFIX}{i}" for i in range(1, 255)]
            current_scan = {}
            now_str = datetime.now().strftime("%H:%M:%S")

            if CURRENT_OS == "Windows":
                with ThreadPoolExecutor(max_workers=60) as executor:
                    results = executor.map(
                        lambda ip: (ip, get_mac_windows(ip)), target_ips
                    )
                    for ip, mac in results:
                        if mac:
                            current_scan[mac] = ip
            else:
                with ThreadPoolExecutor(max_workers=60) as executor:
                    executor.map(ping_ip_linux, target_ips)
                current_scan = read_linux_arp_table()

            with devices_lock:
                for mac, ip in current_scan.items():
                    if mac not in discovered_devices:
                        name = smart_resolve_hostname(ip, mac)
                        discovered_devices[mac] = {
                            "mac": mac,
                            "ip": ip,
                            "name": name,
                            "online": True,
                            "last_seen": now_str,
                        }
                        print(f"[Watchdog] 🟢 New Device: {ip} | {mac} | {name}")
                    else:
                        if not discovered_devices[mac]["online"]:
                            print(f"[Watchdog] 🟡 Back Online: {ip} | {mac} | {discovered_devices[mac]['name']}")
                        discovered_devices[mac]["online"] = True
                        discovered_devices[mac]["ip"] = ip
                        discovered_devices[mac]["last_seen"] = now_str

                # Detect offline devices
                for mac, info in discovered_devices.items():
                    if mac not in current_scan and info["online"]:
                        info["online"] = False
                        print(f"[Watchdog] 🔴 Disconnected: {info['ip']} | {mac} | {info['name']}")

        except Exception as e:
            print(f"[Watchdog Exception] {e}")

        time.sleep(10)


# --- 6. FASTAPI REST API ---
class WakeRequest(BaseModel):
    mac: str
    ip: str = "255.255.255.255"
    port: int = 9


@app.post("/api/wake")
async def api_wake(data: WakeRequest):
    try:
        target_ip = DEFAULT_BROADCAST if data.ip == "255.255.255.255" else data.ip
        send_wol_packet(data.mac, target_ip, data.port)
        return {"success": True, "message": f"Magic Packet sent to {data.mac} via {target_ip}:{data.port}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/devices")
async def api_get_devices():
    with devices_lock:
        device_list = list(discovered_devices.values())
        device_list.sort(key=lambda d: (not d["online"], d["ip"]))
        return {
            "os": CURRENT_OS,
            "subnet": f"{SUBNET_PREFIX}0/24",
            "broadcast": DEFAULT_BROADCAST,
            "devices": device_list,
        }


# --- 7. DASHBOARD HTML ---
@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>LAN Watchdog & WoL Hub</title>
        <style>
            body {
                background-color: #030712; color: #f3f4f6;
                font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                margin: 0; padding: 0; display: flex; flex-direction: column; min-height: 100vh;
            }
            .container { max-width: 42rem; margin: 0 auto; padding: 1.5rem; width: 100%; box-sizing: border-box; }
            header { text-align: center; padding: 1.5rem 0; border-bottom: 1px solid #1f2937; margin-bottom: 1.5rem; }
            h1 { font-size: 1.875rem; font-weight: 900; color: #2dd4bf; margin: 0; }
            .subtitle { font-size: 0.875rem; color: #9ca3af; margin-top: 0.5rem; }
            .card {
                background-color: #111827; padding: 1.25rem; border-radius: 0.75rem;
                border: 1px solid #1f2937; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3); margin-bottom: 1.5rem;
            }
            .card-header {
                display: flex; justify-content: space-between; align-items: center;
                border-bottom: 1px solid #1f2937; padding-bottom: 0.75rem; margin-bottom: 1rem;
            }
            .badge-live {
                display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.75rem;
                background-color: rgba(45, 212, 191, 0.1); color: #2dd4bf; padding: 0.25rem 0.6rem;
                border-radius: 9999px; border: 1px solid rgba(45, 212, 191, 0.3);
            }
            .pulse { width: 8px; height: 8px; background-color: #2dd4bf; border-radius: 50%; box-shadow: 0 0 8px #2dd4bf; }
            .device-item {
                background-color: #030712; padding: 0.85rem 1rem; border-radius: 0.5rem;
                border: 1px solid #1f2937; display: flex; justify-content: space-between; align-items: center;
                margin-bottom: 0.6rem; transition: border-color 0.2s;
            }
            .device-item:hover { border-color: #115e59; }
            .device-info h3 { margin: 0; color: #f3f4f6; font-size: 1rem; display: flex; align-items: center; gap: 0.5rem; }
            .status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
            .dot-online { background-color: #10b981; box-shadow: 0 0 6px #10b981; }
            .dot-offline { background-color: #ef4444; }
            .device-info p { margin: 0.25rem 0 0 0; font-size: 0.75rem; font-family: monospace; color: #9ca3af; }
            .btn-action {
                background-color: #1f2937; color: white; font-weight: bold; padding: 0.45rem 0.8rem;
                border-radius: 0.5rem; font-size: 0.75rem; border: 1px solid #374151; cursor: pointer;
                transition: background-color 0.2s, border-color 0.2s;
            }
            .btn-action:hover { background-color: #0d9488; border-color: #0d9488; }
            .btn-delete {
                background-color: #ef4444; color: white; font-weight: bold; padding: 0.45rem 0.75rem;
                border-radius: 0.5rem; font-size: 0.75rem; border: none; cursor: pointer; transition: background-color 0.2s;
            }
            .btn-delete:hover { background-color: #dc2626; }
            .btn-submit {
                background-color: #0d9488; color: white; font-weight: bold; padding: 0.75rem 1rem;
                border-radius: 0.5rem; font-size: 0.875rem; border: none; cursor: pointer; width: 100%;
                transition: background-color 0.2s; margin-top: 0.5rem;
            }
            .btn-submit:hover { background-color: #0f766e; }
            .placeholder { color: #6b7280; text-align: center; padding: 1.5rem 0; font-size: 0.875rem; margin: 0; }
            .text-input {
                background-color: #030712; color: #f3f4f6; border: 1px solid #1f2937; border-radius: 0.5rem;
                padding: 0.5rem 0.75rem; width: 100%; box-sizing: border-box; font-size: 0.875rem; margin-top: 0.25rem;
            }
            .text-input:focus { outline: none; border-color: #0d9488; }
            .form-group { margin-bottom: 0.85rem; text-align: left; }
            .form-group label { font-size: 0.75rem; color: #9ca3af; font-weight: 600; text-transform: uppercase; }
            #status-banner { display: none; padding: 0.75rem 1rem; border-radius: 0.5rem; margin-bottom: 1rem; font-size: 0.875rem; text-align: center; }
            .status-success { background-color: #064e3b; color: #6ee7b7; border: 1px solid #047857; }
            .status-error { background-color: #7f1d1d; color: #fca5a5; border: 1px solid #b91c1c; }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>LAN Watchdog & WoL</h1>
                <p class="subtitle" id="net-info">Discovering network parameters...</p>
            </header>

            <div id="status-banner"></div>

            <div class="card">
                <div class="card-header">
                    <h2 style="font-size: 1.1rem; font-weight: bold; margin: 0;">Discovered Devices (Watchdog)</h2>
                    <div class="badge-live"><span class="pulse"></span> Live Monitor</div>
                </div>
                <div id="live-device-list">
                    <p class="placeholder">Scanning subnet for active clients...</p>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2 style="font-size: 1.1rem; font-weight: bold; margin: 0;">Favorite Devices</h2>
                </div>
                <div id="saved-device-list">
                    <p class="placeholder">No saved devices yet. Add them from the live list or the form below.</p>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2 style="font-size: 1.1rem; font-weight: bold; margin: 0;">Manual Wake-on-LAN</h2>
                </div>
                <div class="form-group">
                    <label>Device Name (Optional)</label>
                    <input type="text" id="manual-name" placeholder="Desktop PC" class="text-input">
                </div>
                <div class="form-group">
                    <label>MAC Address (Required)</label>
                    <input type="text" id="manual-mac" placeholder="AA:BB:CC:DD:EE:FF" class="text-input">
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
                    <div class="form-group">
                        <label>Broadcast IP</label>
                        <input type="text" id="manual-ip" value="255.255.255.255" class="text-input">
                    </div>
                    <div class="form-group">
                        <label>Port</label>
                        <input type="number" id="manual-port" value="9" class="text-input">
                    </div>
                </div>
                <button onclick="handleManualWake()" class="btn-submit">Send Magic Packet</button>
            </div>
        </div>

        <script>
            let currentBroadcast = '255.255.255.255';

            function showStatus(text, isSuccess) {
                const banner = document.getElementById('status-banner');
                banner.className = isSuccess ? 'status-success' : 'status-error';
                banner.innerText = text;
                banner.style.display = 'block';
                setTimeout(() => { banner.style.display = 'none'; }, 4000);
            }

            function getSavedDevices() {
                const data = localStorage.getItem('wol_fav_devices');
                return data ? JSON.parse(data) : [];
            }

            function saveDevice(name, mac, ip) {
                let list = getSavedDevices();
                if (!list.some(d => d.mac === mac)) {
                    list.push({ name: name || 'Device', mac, ip: ip || currentBroadcast });
                    localStorage.setItem('wol_fav_devices', JSON.stringify(list));
                    renderSavedDevices();
                    showStatus('Device added to favorites.', true);
                } else {
                    showStatus('Device already in favorites.', false);
                }
            }

            function deleteDevice(mac) {
                let list = getSavedDevices().filter(d => d.mac !== mac);
                localStorage.setItem('wol_fav_devices', JSON.stringify(list));
                renderSavedDevices();
            }

            function renderSavedDevices() {
                const container = document.getElementById('saved-device-list');
                const list = getSavedDevices();
                if (list.length === 0) {
                    container.innerHTML = '<p class="placeholder">No saved devices yet.</p>';
                    return;
                }
                container.innerHTML = '';
                list.forEach(d => {
                    const el = document.createElement('div');
                    el.className = 'device-item';
                    el.innerHTML = `
                        <div class="device-info">
                            <h3>${d.name}</h3>
                            <p>MAC: ${d.mac} | IP: ${d.ip}</p>
                        </div>
                        <div style="display: flex; gap: 0.5rem;">
                            <button onclick="triggerWake('${d.mac}', '${d.ip}', 9)" class="btn-action">Wake</button>
                            <button onclick="deleteDevice('${d.mac}')" class="btn-delete">Delete</button>
                        </div>
                    `;
                    container.appendChild(el);
                });
            }

            async function triggerWake(mac, ip, port) {
                try {
                    const res = await fetch('/api/wake', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ mac, ip: ip || currentBroadcast, port: parseInt(port) || 9 })
                    });
                    const data = await res.json();
                    if (res.ok) showStatus(data.message, true);
                    else showStatus('Error: ' + data.detail, false);
                } catch(e) {
                    showStatus('Failed to communicate with backend.', false);
                }
            }

            async function handleManualWake() {
                const name = document.getElementById('manual-name').value.trim();
                const mac = document.getElementById('manual-mac').value.trim();
                const ip = document.getElementById('manual-ip').value.trim() || currentBroadcast;
                const port = document.getElementById('manual-port').value.trim() || 9;
                if (!mac) { showStatus('Please enter a MAC address!', false); return; }
                await triggerWake(mac, ip, port);
            }

            async function fetchWatchdogDevices() {
                try {
                    const res = await fetch('/api/devices');
                    const data = await res.json();
                    
                    if (data.subnet) {
                        currentBroadcast = data.broadcast;
                        document.getElementById('net-info').innerText = 'OS: ' + data.os + ' | Monitored Subnet: ' + data.subnet;
                    }

                    const listContainer = document.getElementById('live-device-list');
                    if (data.devices.length === 0) {
                        listContainer.innerHTML = '<p class="placeholder">Scanning subnet for active clients...</p>';
                        return;
                    }

                    listContainer.innerHTML = '';
                    data.devices.forEach(d => {
                        const div = document.createElement('div');
                        div.className = 'device-item';
                        const dotClass = d.online ? 'dot-online' : 'dot-offline';
                        const statusTxt = d.online ? 'ONLINE' : 'OFFLINE';

                        div.innerHTML = `
                            <div class="device-info">
                                <h3>
                                    <span class="status-dot ${dotClass}" title="${statusTxt}"></span>
                                    ${d.name}
                                </h3>
                                <p>IP: ${d.ip} | MAC: ${d.mac} | Last Seen: ${d.last_seen}</p>
                            </div>
                            <div style="display: flex; gap: 0.4rem;">
                                <button onclick="triggerWake('${d.mac}', '${currentBroadcast}', 9)" class="btn-action">Wake</button>
                                <button onclick="saveDevice('${d.name}', '${d.mac}', '${currentBroadcast}')" class="btn-action">+ Save</button>
                            </div>
                        `;
                        listContainer.appendChild(div);
                    });
                } catch(e) {
                    console.error('Watchdog update failed:', e);
                }
            }

            window.onload = function() {
                renderSavedDevices();
                fetchWatchdogDevices();
                setInterval(fetchWatchdogDevices, 3000);
            };
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


# --- APPLICATION ENTRY POINT ---
if __name__ == "__main__":
    watchdog_thread = threading.Thread(
        target=watchdog_background_loop, daemon=True
    )
    watchdog_thread.start()

    print("\n" + "=" * 65)
    print(
        f"🚀 LAN Watchdog & WoL Server started on: http://{SERVER_HOST}:{SERVER_PORT}"
    )
    print("=" * 65 + "\n")
    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT)
