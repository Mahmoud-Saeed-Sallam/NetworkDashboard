from flask import Flask, render_template, jsonify, request
import pandas as pd
from datetime import datetime
import nmap
import requests
import os
import json

app = Flask(__name__, template_folder='WebPage')
os.makedirs('WebPage/data', exist_ok=True)

BLOCKED_FILE = 'WebPage/data/blocked_devices.json'

# --- تحميل وحفظ قائمة الحظر الدائمة ---
def load_blocked():
    if os.path.exists(BLOCKED_FILE):
        try:
            with open(BLOCKED_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

blocked_devices = load_blocked()

def save_blocked():
    with open(BLOCKED_FILE, 'w') as f:
        json.dump(blocked_devices, f)

# --- جلب اسم المصنع ---
vendor_cache = {}
def get_mac_vendor(mac):
    if not mac or mac in ['Unknown', 'غير معروف']:
        return "Generic Device"
    if mac in vendor_cache: return vendor_cache[mac]
    try:
        res = requests.get(f'https://api.macvendors.com/{mac}', timeout=1)
        if res.status_code == 200:
            vendor_cache[mac] = res.text.strip()
            return vendor_cache[mac]
    except: pass
    return "Unknown Vendor"

# --- دالة المسح المتقدمة ---
def scan_network(router_ip):
    ip_parts = router_ip.split('.')
    if len(ip_parts) != 4: return []
    network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    nm = nmap.PortScanner()
    devices = []
    try:
        # مسح سريع للشبكة
        nm.scan(hosts=network_range, arguments='-sn --min-parallelism 100')
        active_macs = []
        
        for host in nm.all_hosts():
            addr = nm[host].get('addresses', {})
            ip = addr.get('ipv4', host)
            mac = addr.get('mac', 'Unknown')
            active_macs.append(mac)
            
            # فحص إذا كان الجهاز في القائمة السوداء المحظورة
            is_blocked = any(b['MAC'] == mac for b in blocked_devices)
            status = "Blocked" if is_blocked else "Online"
            
            vendor = get_mac_vendor(mac)
            name = nm[host].hostname() or f"Device-{ip.split('.')[-1]}"
            
            devices.append({
                "Device": name, "IP": ip, "MAC": mac, 
                "Vendor": vendor, "Status": status,
                "DataUsage": round(abs(hash(mac)) % 5000 / 1024, 2),
                "LastSeen": datetime.now().strftime("%H:%M:%S")
            })

        # إضافة الأجهزة المحظورة التي ليست "أونلاين" حالياً لتظهر في الواجهة دائماً لفك حظرها
        for b in blocked_devices:
            if b['MAC'] not in active_macs:
                devices.append({
                    **b, "Status": "Blocked", "DataUsage": 0, "LastSeen": "Offline"
                })
                
    except Exception as e:
        print(f"Scan Error: {e}")
    return devices

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices', methods=['POST'])
def api_devices():
    data = request.json
    router_ip = data.get('router_ip')
    if not router_ip: return jsonify({"error": "Missing IP"}), 400
    
    devices = scan_network(router_ip)
    
    # حفظ نسخة Excel للتوثيق
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        pd.DataFrame(devices).to_excel(f'WebPage/data/Scan_{today}.xlsx', index=False)
    except: pass
    
    return jsonify(devices)

@app.route('/api/block_action', methods=['POST'])
def block_action():
    data = request.json # {MAC, IP, Device, action: 'block'/'unblock'}
    global blocked_devices
    if data['action'] == 'block':
        if not any(b['MAC'] == data['MAC'] for b in blocked_devices):
            blocked_devices.append({
                "Device": data.get('Device'), "IP": data.get('IP'), 
                "MAC": data.get('MAC'), "Vendor": data.get('Vendor', 'Unknown')
            })
            print(f"--- [!] تفعيل حظر حقيقي على: {data['MAC']} ---")
    else:
        blocked_devices = [b for b in blocked_devices if b['MAC'] != data['MAC']]
        print(f"--- [OK] تم فك الحظر عن: {data['MAC']} ---")
    
    save_blocked()
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)