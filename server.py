"""
PROJECT FALCON - AI-Powered Network Intrusion Detection System
Run: python server.py
Requires: pip install flask flask-cors psutil
"""

import os, time, threading, datetime, socket, collections, random, webbrowser

import psutil
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

# ============================================================
# APP SETUP — NO static_folder conflict
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
CORS(app)

# ============================================================
# SHARED STATE
# ============================================================
LOCK              = threading.Lock()
connection_history = collections.defaultdict(list)
port_scan_tracker  = collections.defaultdict(set)
blocked_ips        = set()
threat_log         = []
traffic_log        = []
stats_history      = collections.deque(maxlen=60)
seen_connections   = set()

SUSPICIOUS_PORTS = {
    4444:"Metasploit",1337:"Backdoor",31337:"Elite backdoor",
    12345:"NetBus",27374:"Sub7",6667:"IRC C2",6666:"IRC C2",
    9001:"Tor relay",9050:"Tor SOCKS",65535:"Suspicious port",
}
SUSPICIOUS_PROCESSES = [
    "netcat","nc.exe","ncat","nmap","masscan",
    "mimikatz","msfconsole","meterpreter","empire",
    "cobaltstrike","psexec","wce","fgdump",
]

# ============================================================
# HELPERS
# ============================================================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

def add_threat(ttype, severity, src, desc, dest="", port=0):
    with LOCK:
        threat_log.insert(0, {
            "id": len(threat_log)+1,
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "timestamp": time.time(),
            "type": ttype, "severity": severity,
            "source_ip": src, "dest_ip": dest,
            "port": port, "description": desc, "status": "detected"
        })
        if len(threat_log) > 100: threat_log.pop()

# ============================================================
# BACKGROUND MONITORS
# ============================================================
def monitor_connections():
    global seen_connections
    while True:
        try:
            conns = psutil.net_connections(kind='inet')
            now = time.time(); current = set()
            for c in conns:
                if c.status not in ('ESTABLISHED','SYN_SENT') or not c.raddr: continue
                rip, rport = c.raddr.ip, c.raddr.port
                lport = c.laddr.port if c.laddr else 0
                key = (rip, rport, lport); current.add(key)
                if key not in seen_connections:
                    entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"),
                             "src_ip": get_local_ip(), "dst_ip": rip,
                             "protocol": "TCP", "src_port": lport,
                             "dst_port": rport, "status": "allowed", "flag": False}
                    if rport in SUSPICIOUS_PORTS:
                        entry["status"] = "flagged"; entry["flag"] = True
                        add_threat("Suspicious Port", "high", rip,
                                   f"Connection to {SUSPICIOUS_PORTS[rport]} (port {rport})",
                                   get_local_ip(), rport)
                    port_scan_tracker[rip].add(rport)
                    if len(port_scan_tracker[rip]) > 10 and rip not in blocked_ips:
                        blocked_ips.add(rip); entry["status"] = "blocked"
                        add_threat("Port Scan", "critical", rip,
                                   f"{len(port_scan_tracker[rip])} ports probed", get_local_ip(), rport)
                    connection_history[rip] = [t for t in connection_history[rip]+[now] if now-t < 60]
                    if len(connection_history[rip]) > 20:
                        entry["flag"] = True
                        add_threat("Connection Flood", "high", rip,
                                   f"{len(connection_history[rip])} conns/min", get_local_ip(), rport)
                    with LOCK:
                        traffic_log.insert(0, entry)
                        if len(traffic_log) > 200: traffic_log.pop()
            seen_connections = current
        except: pass
        time.sleep(2)

def monitor_processes():
    seen = set()
    while True:
        try:
            for p in psutil.process_iter(['pid','name','exe']):
                try:
                    pid=p.info['pid']; name=(p.info['name'] or '').lower()
                    if pid in seen: continue
                    for s in SUSPICIOUS_PROCESSES:
                        if s in name:
                            seen.add(pid)
                            add_threat("Suspicious Process","critical","localhost",
                                       f"Detected: {p.info['name']} (PID {pid})")
                            break
                except: pass
        except: pass
        time.sleep(10)

def collect_stats():
    while True:
        try:
            n1 = psutil.net_io_counters()
            cpu = psutil.cpu_percent(interval=1)
            n2 = psutil.net_io_counters()
            mem = psutil.virtual_memory()
            with LOCK:
                stats_history.append({
                    "timestamp": time.time(), "cpu": cpu, "memory": mem.percent,
                    "bytes_sent": n2.bytes_sent, "bytes_recv": n2.bytes_recv,
                    "sent_rate": max(0, n2.bytes_sent - n1.bytes_sent),
                    "recv_rate": max(0, n2.bytes_recv - n1.bytes_recv),
                })
        except: pass
        time.sleep(1)

# ============================================================
# STATIC FILE ROUTES
# ============================================================

@app.route('/')
def root():
    return send_from_directory(BASE_DIR, 'login.html')

@app.route('/login.html')
def login_page():
    return send_from_directory(BASE_DIR, 'login.html')

@app.route('/index.html')
def dashboard_page():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/app.js')
def serve_appjs():
    return send_from_directory(BASE_DIR, 'app.js')

@app.route('/styles.css')
def serve_css():
    return send_from_directory(BASE_DIR, 'styles.css')

@app.route('/<path:filename>')
def serve_file(filename):
    fp = os.path.join(BASE_DIR, filename)
    if os.path.isfile(fp):
        return send_from_directory(BASE_DIR, filename)
    return jsonify({"error": f"Not found: {filename}"}), 404

# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def handle_404(e):
    print(f"  [404] {request.path}")
    if request.path.startswith('/api/'):
        return jsonify({"error": "API route not found", "path": request.path}), 404
    return send_from_directory(BASE_DIR, 'login.html')

@app.errorhandler(500)
def handle_500(e):
    print(f"  [500] {request.path} — {e}")
    return jsonify({"error": "Server error", "detail": str(e)}), 500

# ============================================================
# API ENDPOINTS
# ============================================================

@app.route('/api/health')
def api_health():
    return jsonify({"status": "ok", "time": datetime.datetime.now().isoformat()})

@app.route('/api/stats')
def api_stats():
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()
    freq = psutil.cpu_freq()
    return jsonify({
        "cpu": {"percent": cpu, "cores": psutil.cpu_count(),
                "per_core": psutil.cpu_percent(percpu=True),
                "freq_mhz": freq.current if freq else 0},
        "memory": {"percent": mem.percent,
                   "used_gb": round(mem.used/1e9,1),
                   "total_gb": round(mem.total/1e9,1),
                   "available_gb": round(mem.available/1e9,1)},
        "disk": {"percent": disk.percent,
                 "used_gb": round(disk.used/1e9,1),
                 "total_gb": round(disk.total/1e9,1)},
        "network": {"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv,
                    "packets_sent": net.packets_sent, "packets_recv": net.packets_recv},
        "local_ip": get_local_ip(), "timestamp": time.time()
    })

@app.route('/api/stats/history')
def api_stats_history():
    with LOCK: return jsonify(list(stats_history))

@app.route('/api/overview')
def api_overview():
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    net = psutil.net_io_counters()
    with LOCK:
        tc = {"critical":0,"high":0,"medium":0,"low":0}
        for t in threat_log:
            s = t.get("severity","low")
            if s in tc: tc[s] += 1
        try: ac = len([c for c in psutil.net_connections() if c.status=='ESTABLISHED'])
        except: ac = 0
        hist = list(stats_history)
    return jsonify({
        "cpu_percent": cpu, "memory_percent": mem.percent,
        "active_connections": ac,
        "bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv,
        "threats_total": len(threat_log),
        "threats_critical": tc["critical"], "threats_high": tc["high"],
        "blocked_ips": len(blocked_ips), "traffic_history": hist
    })

@app.route('/api/connections')
def api_connections():
    conns = []
    try:
        for c in psutil.net_connections(kind='inet'):
            if not c.raddr: continue
            try:
                pname = psutil.Process(c.pid).name() if c.pid else ""
            except: pname = ""
            conns.append({
                "pid": c.pid, "process": pname,
                "local_ip": c.laddr.ip if c.laddr else "",
                "local_port": c.laddr.port if c.laddr else 0,
                "remote_ip": c.raddr.ip, "remote_port": c.raddr.port,
                "status": c.status, "protocol": "TCP"
            })
    except: pass
    return jsonify(conns[:50])

@app.route('/api/traffic')
def api_traffic():
    with LOCK: return jsonify(traffic_log[:50])

@app.route('/api/threats')
def api_threats():
    with LOCK: return jsonify(threat_log[:50])

@app.route('/api/threats/summary')
def api_threats_summary():
    with LOCK:
        c = {"critical":0,"high":0,"medium":0,"low":0,"total":0}
        for t in threat_log:
            s = t.get("severity","low")
            if s in c: c[s] += 1
            c["total"] += 1
        return jsonify(c)

@app.route('/api/processes')
def api_processes():
    procs = []
    try:
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent','status']):
            try: procs.append(p.info)
            except: pass
        procs.sort(key=lambda x: x.get('cpu_percent',0), reverse=True)
    except: pass
    return jsonify(procs[:20])

@app.route('/api/network/interfaces')
def api_interfaces():
    ifaces = []
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        io    = psutil.net_io_counters(pernic=True)
        for name, stat in stats.items():
            ip = next((a.address for a in addrs.get(name,[]) if a.family==socket.AF_INET), "")
            n = io.get(name)
            ifaces.append({"name":name,"ip":ip,"is_up":stat.isup,
                           "speed_mbps":stat.speed,
                           "bytes_sent": n.bytes_sent if n else 0,
                           "bytes_recv": n.bytes_recv if n else 0})
    except: pass
    return jsonify(ifaces)

# ============================================================
# AI CHAT
# ============================================================
def get_snap():
    try:
        cpu = psutil.cpu_percent(interval=0.2)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net = psutil.net_io_counters()
        with LOCK:
            tc = sum(1 for t in threat_log if t.get('severity')=='critical')
            th = sum(1 for t in threat_log if t.get('severity')=='high')
            try: ac = len([c for c in psutil.net_connections() if c.status=='ESTABLISHED'])
            except: ac = 0
        return {"cpu":cpu,"memory":mem.percent,"disk":disk.percent,
                "mem_used":round(mem.used/1e9,1),"mem_total":round(mem.total/1e9,1),
                "threats_total":len(threat_log),"threats_critical":tc,"threats_high":th,
                "active_connections":ac,"bytes_sent":net.bytes_sent,"bytes_recv":net.bytes_recv,
                "blocked_ips":len(blocked_ips)}
    except: return {}

def falcon_chat(msg):
    m = msg.lower().strip()
    s = get_snap()
    now = datetime.datetime.now().strftime("%H:%M:%S")
    if any(w in m for w in ['cpu','processor']):
        v=s.get('cpu',0); lvl='NORMAL' if v<70 else 'HIGH' if v<90 else 'CRITICAL'
        return f"🖥️ CPU: {v:.1f}% — {lvl}\n8 cores active."
    if any(w in m for w in ['memory','ram','mem']):
        v=s.get('memory',0)
        return f"💾 Memory: {v:.1f}% — {s.get('mem_used',0)} / {s.get('mem_total',0)} GB used."
    if any(w in m for w in ['disk','storage']):
        return f"💽 Disk: {s.get('disk',0):.1f}% used."
    if any(w in m for w in ['threat','attack','malware']):
        t=s.get('threats_total',0); c=s.get('threats_critical',0)
        rt=threat_log[:3]
        r=f"🛡️ Threats: {t} total, {c} critical, {len(blocked_ips)} IPs blocked."
        if rt: r+="\nRecent: "+", ".join(f"{x['type']} from {x['source_ip']}" for x in rt)
        return r
    if any(w in m for w in ['network','traffic','connection']):
        return f"🌐 Connections: {s.get('active_connections',0)} active — Sent: {round(s.get('bytes_sent',0)/1e6,1)} MB, Recv: {round(s.get('bytes_recv',0)/1e6,1)} MB"
    if any(w in m for w in ['status','health','system']):
        c=s.get('cpu',0); me=s.get('memory',0); t=s.get('threats_total',0)
        st='🟢 HEALTHY' if c<80 and me<85 and t==0 else '🟡 CAUTION' if c<90 else '🔴 ALERT'
        return f"📊 System {st} at {now}\nCPU: {c:.1f}% | RAM: {me:.1f}% | Threats: {t}"
    if any(w in m for w in ['hi','hello','help','hey']):
        return "👋 FALCON AI here! Ask me about CPU, memory, disk, threats, network, or system status."
    return random.choice(["🤖 Ask me: CPU usage, memory, threats, network status, or system health.",
                           "🛡️ Try: 'What is my CPU usage?' or 'Any threats detected?'"])

@app.route('/api/chat', methods=['POST'])
def api_chat():
    try:
        data = request.get_json()
        msg = (data or {}).get('message','').strip()
        if not msg: return jsonify({"error":"No message"}), 400
        return jsonify({"reply": falcon_chat(msg),
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "agent": "FALCON AI"})
    except Exception as e:
        return jsonify({"reply": "⚠️ Error. Try again.", "timestamp": "", "agent": "FALCON AI"})

# ============================================================
# START
# ============================================================
def start_threads():
    for fn in [monitor_connections, monitor_processes, collect_stats]:
        threading.Thread(target=fn, daemon=True).start()
    print("  ✅ Background monitors started")

if __name__ == '__main__':
    print("=" * 56)
    print("  PROJECT FALCON — AI Threat Detection System")
    print("=" * 56)
    print(f"  Base dir  : {BASE_DIR}")
    print(f"  Local IP  : {get_local_ip()}")
    print(f"  URL       : http://localhost:5000")
    print("=" * 56)

    # Verify files exist
    for f in ['login.html','index.html','app.js','styles.css']:
        fp = os.path.join(BASE_DIR, f)
        status = "✅" if os.path.isfile(fp) else "❌ MISSING"
        print(f"  {status}  {f}")

    print("\n  📌 Routes:")
    start_threads()

    with app.app_context():
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
            print(f"     {rule.rule}")

    print()
    threading.Thread(target=lambda: (time.sleep(1.5), webbrowser.open('http://localhost:5000')), daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
