from flask import Flask, render_template, jsonify, request
import pandas as pd
from datetime import datetime
import nmap
import requests
import os
import json

app = Flask(__name__, template_folder='WebPage')
# التأكد من وجود مجلد البيانات
os.makedirs('WebPage/data', exist_ok=True)

BLOCKED_FILE = 'WebPage/data/blocked_devices.json'

# --- تحميل وحفظ قائمة الحظر الدائمة ---
def load_blocked():
    if os.path.exists(BLOCKED_FILE):
        try:
            with open(BLOCKED_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

# تحميل القائمة عند بدء التشغيل
blocked_devices = load_blocked()

def save_blocked():
    with open(BLOCKED_FILE, 'w', encoding='utf-8') as f:
        json.dump(blocked_devices, f, indent=4, ensure_ascii=False)

# --- جلب اسم المصنع عبر API ---
vendor_cache = {}
def get_mac_vendor(mac):
    if not mac or mac == 'Unknown':
        return "Generic Device"
    if mac in vendor_cache: return vendor_cache[mac]
    try:
        res = requests.get(f'https://api.macvendors.com/{mac}', timeout=1)
        if res.status_code == 200:
            vendor_cache[mac] = res.text.strip()
            return vendor_cache[mac]
    except: pass
    return "Unknown Vendor"

# --- دالة المسح الذكي (تعتمد على IP المدخل فقط) ---
def scan_network(router_ip):
    ip_parts = router_ip.split('.')
    if len(ip_parts) != 4: return []
    
    # بناء نطاق الشبكة بناءً على الـ IP المدخل (مثلاً 192.168.1.0/24)
    network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    nm = nmap.PortScanner()
    devices = []
    active_macs = []
    
    try:
        print(f"[*] جاري فحص النطاق: {network_range}")
        # استخدام -sn للفحص السريع (Ping Scan)
        nm.scan(hosts=network_range, arguments='-sn --min-parallelism 100')
        
        for host in nm.all_hosts():
            addr = nm[host].get('addresses', {})
            ip = addr.get('ipv4', host)
            mac = addr.get('mac', 'Unknown')
            active_macs.append(mac)
            
            # فحص حالة الحظر من الذاكرة
            is_blocked = any(b['MAC'] == mac for b in blocked_devices)
            status = "Blocked" if is_blocked else "Online"
            
            vendor = get_mac_vendor(mac)
            # محاولة جلب اسم الجهاز من الشبكة
            hostname = nm[host].hostname() or f"Device-{ip.split('.')[-1]}"
            
            devices.append({
                "Device": hostname, "IP": ip, "MAC": mac, 
                "Vendor": vendor, "Status": status,
                "DataUsage": round(abs(hash(mac)) % 5000 / 1024, 2), # استهلاك وهمي للبيانات
                "LastSeen": datetime.now().strftime("%H:%M:%S")
            })

        # دمج الأجهزة المحظورة التي ليست متصلة حالياً لتظهر في اللوحة
        for b in blocked_devices:
            if b['MAC'] not in active_macs:
                devices.append({
                    "Device": b['Device'], "IP": b['IP'], "MAC": b['MAC'],
                    "Vendor": b.get('Vendor', 'Unknown'), "Status": "Blocked", 
                    "DataUsage": 0, "LastSeen": "Offline"
                })
                
    except Exception as e:
        print(f"[!] خطأ في الفحص: {e}")
    return devices

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices', methods=['POST'])
def api_devices():
    data = request.json
    router_ip = data.get('router_ip')
    username = data.get('username')
    password = data.get('password')

    # منع البحث التلقائي إذا كانت البيانات ناقصة
    if not router_ip or not username or not password:
        return jsonify({"error": "يرجى إدخال بيانات الدخول كاملة أولاً"}), 400

    # اختبار وصول بسيط للـ IP قبل البدء (اختياري لزيادة الأمان)
    # يمكن إضافة اختبار Ping هنا إذا أردت

    devices = scan_network(router_ip)
    
    # حفظ نسخة Excel يومية للتوثيق
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        pd.DataFrame(devices).to_excel(f'WebPage/data/Scan_{today}.xlsx', index=False)
    except Exception as e:
        print(f"Excel Export Error: {e}")
    
    return jsonify(devices)

@app.route('/api/block_action', methods=['POST'])
def block_action():
    data = request.json # {MAC, IP, Device, action: 'block'/'unblock'}
    global blocked_devices
    
    if data['action'] == 'block':
        # التأكد من عدم تكرار الجهاز في قائمة الحظر
        if not any(b['MAC'] == data['MAC'] for b in blocked_devices):
            blocked_devices.append({
                "Device": data.get('Device'), 
                "IP": data.get('IP'), 
                "MAC": data.get('MAC'), 
                "Vendor": data.get('Vendor', 'Unknown')
            })
            print(f"--- [!] تم إضافة الجهاز للقائمة السوداء: {data['MAC']} ---")
    else:
        # فك الحظر: إزالة الجهاز من القائمة
        blocked_devices = [b for b in blocked_devices if b['MAC'] != data['MAC']]
        print(f"--- [OK] تم إزالة الجهاز من القائمة السوداء: {data['MAC']} ---")
    
    save_blocked()
    return jsonify({"success": True})

if __name__ == "__main__":
    # تشغيل السيرفر على المنفذ 5000
    print("--- [سيرفر مراقبة الشبكة يعمل الآن] ---")
    app.run(debug=True, host='0.0.0.0', port=5000)