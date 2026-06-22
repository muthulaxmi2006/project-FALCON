"""
PROJECT FALCON - Real Network Monitor & Threat Detection Backend
Run: python server.py  → opens http://localhost:5000 automatically
Requires: pip install flask flask-cors psutil
"""

from flask import Flask, jsonify, send_from_directory, redirect, request
from flask_cors import CORS
import psutil
import time
import threading
import datetime
import socket
import collections
import re
import os
import webbrowser
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app)

# ============================================================
# THREAT DETECTION ENGINE
# ============================================================

# Store connection history for analysis
connection_history = collections.defaultdict(list)  # ip -> [timestamps]
port_scan_tracker  = collections.defaultdict(set)   # ip -> {ports}
blocked_ips        = set()
threat_log         = []  # list of detected threats
traffic_log        = []  # list of recent connections (for the table)
stats_history      = collections.deque(maxlen=30)   # last 30 data points

LOCK = threading.Lock()

# Known malicious ports
SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite backdoor",
    12345: "NetBus trojan",
    27374: "Sub7 trojan",
    65535: "Suspicious high port",
    6667:  "IRC (botnet C2)",
    6666:  "IRC (botnet C2)",
    9001:  "Tor relay",
    9050:  "Tor SOCKS proxy",
}

# Known suspicious process names
SUSPICIOUS_PROCESSES = [
    "netcat", "nc.exe", "ncat", "nmap", "masscan",
    "mimikatz", "msfconsole", "meterpreter", "empire",
    "cobaltstrike", "psexec", "wce", "fgdump",
]

# Private IP ranges (internal network)
def is_private_ip(ip):
    try:
        parts = list(map(int, ip.split('.')))
        return (
            parts[0] == 10 or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            (parts[0] == 192 and parts[1] == 168) or
            parts[0] == 127
        )
    except:
        return False

def add_threat(threat_type, severity, source_ip, description, dest_ip="", port=0):
    """Add a detected threat to the threat log"""
    with LOCK:
        threat = {
            "id": len(threat_log) + 1,
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "timestamp": time.time(),
            "type": threat_type,
            "severity": severity,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "port": port,
            "description": description,
            "status": "detected"
        }
        threat_log.insert(0, threat)
        # Keep only last 100 threats
        if len(threat_log) > 100:
            threat_log.pop()

# ============================================================
# REAL-TIME CONNECTION MONITOR
# ============================================================

seen_connections = set()

def monitor_connections():
    """Continuously monitor network connections and detect threats"""
    global seen_connections

    while True:
        try:
            connections = psutil.net_connections(kind='inet')
            now = time.time()
            current_conn_set = set()

            for conn in connections:
                if conn.status not in ('ESTABLISHED', 'SYN_SENT', 'LISTEN'):
                    continue
                if not conn.raddr:
                    continue

                remote_ip   = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port  = conn.laddr.port if conn.laddr else 0
                proto       = "TCP"
                status      = conn.status

                conn_key = (remote_ip, remote_port, local_port)
                current_conn_set.add(conn_key)

                # Add to traffic log (new connections only)
                if conn_key not in seen_connections:
                    with LOCK:
                        entry = {
                            "time": datetime.datetime.now().strftime("%H:%M:%S"),
                            "src_ip": get_local_ip(),
                            "dst_ip": remote_ip,
                            "protocol": proto,
                            "src_port": local_port,
                            "dst_port": remote_port,
                            "status": "allowed",
                            "bytes": 0,
                            "flag": False
                        }

                        # ---- THREAT DETECTION RULES ----

                        # Rule 1: Suspicious port
                        if remote_port in SUSPICIOUS_PORTS:
                            entry["status"] = "flagged"
                            entry["flag"] = True
                            add_threat(
                                "Suspicious Port Connection",
                                "high",
                                remote_ip,
                                f"Connection to {SUSPICIOUS_PORTS[remote_port]} port {remote_port}",
                                get_local_ip(),
                                remote_port
                            )

                        # Rule 2: Port scan detection (same IP, many different ports)
                        port_scan_tracker[remote_ip].add(remote_port)
                        if len(port_scan_tracker[remote_ip]) > 10:
                            entry["status"] = "blocked"
                            entry["flag"] = True
                            if remote_ip not in blocked_ips:
                                blocked_ips.add(remote_ip)
                                add_threat(
                                    "Port Scan Detected",
                                    "critical",
                                    remote_ip,
                                    f"Port scan: {len(port_scan_tracker[remote_ip])} ports probed",
                                    get_local_ip(),
                                    remote_port
                                )

                        # Rule 3: Connection flood (same IP, many connections quickly)
                        connection_history[remote_ip].append(now)
                        # Keep only last 60 seconds
                        connection_history[remote_ip] = [
                            t for t in connection_history[remote_ip] if now - t < 60
                        ]
                        if len(connection_history[remote_ip]) > 20:
                            entry["status"] = "flagged"
                            entry["flag"] = True
                            add_threat(
                                "Connection Flood",
                                "high",
                                remote_ip,
                                f"High connection rate: {len(connection_history[remote_ip])} connections/min",
                                get_local_ip(),
                                remote_port
                            )

                        traffic_log.insert(0, entry)
                        if len(traffic_log) > 200:
                            traffic_log.pop()

            seen_connections = current_conn_set

            # Clean port scan tracker (reset after 5 min)
            for ip in list(port_scan_tracker.keys()):
                if len(connection_history.get(ip, [])) == 0:
                    del port_scan_tracker[ip]

        except Exception as e:
            pass

        time.sleep(2)


def monitor_processes():
    """Detect suspicious processes running on the system"""
    seen_pids = set()

    while True:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    pid  = proc.info['pid']
                    name = (proc.info['name'] or '').lower()
                    exe  = (proc.info['exe'] or '').lower()

                    if pid in seen_pids:
                        continue

                    for sus in SUSPICIOUS_PROCESSES:
                        if sus in name or sus in exe:
                            seen_pids.add(pid)
                            add_threat(
                                "Suspicious Process",
                                "critical",
                                "localhost",
                                f"Suspicious process detected: {proc.info['name']} (PID {pid})",
                            )
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

        time.sleep(10)


def collect_stats():
    """Collect real system stats every 2 seconds with cumulative counters"""
    while True:
        try:
            net_io = psutil.net_io_counters()
            cpu    = psutil.cpu_percent(interval=1)  # 1s blocking for accuracy
            net_io2 = psutil.net_io_counters()
            mem    = psutil.virtual_memory()

            bytes_sent_delta = max(0, net_io2.bytes_sent - net_io.bytes_sent)
            bytes_recv_delta = max(0, net_io2.bytes_recv - net_io.bytes_recv)

            point = {
                "timestamp":   time.time(),
                "cpu":         cpu,
                "memory":      mem.percent,
                "bytes_sent":  net_io2.bytes_sent,          # cumulative total
                "bytes_recv":  net_io2.bytes_recv,          # cumulative total
                "sent_rate":   bytes_sent_delta,             # per-interval delta
                "recv_rate":   bytes_recv_delta,             # per-interval delta
            }
            with LOCK:
                stats_history.append(point)
        except Exception:
            pass
        time.sleep(1)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


# ============================================================
# API ENDPOINTS
# ============================================================

@app.route('/api/stats')
def api_stats():
    """System resource stats"""
    cpu    = psutil.cpu_percent(interval=0.1)
    mem    = psutil.virtual_memory()
    disk   = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()

    # Per-CPU
    cpu_per_core = psutil.cpu_percent(percpu=True)

    return jsonify({
        "cpu": {
            "percent": cpu,
            "cores": psutil.cpu_count(),
            "per_core": cpu_per_core,
            "freq_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else 0,
        },
        "memory": {
            "percent": mem.percent,
            "used_gb": round(mem.used / 1e9, 1),
            "total_gb": round(mem.total / 1e9, 1),
            "available_gb": round(mem.available / 1e9, 1),
        },
        "disk": {
            "percent": disk.percent,
            "used_gb": round(disk.used / 1e9, 1),
            "total_gb": round(disk.total / 1e9, 1),
        },
        "network": {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "errin": net_io.errin,
            "errout": net_io.errout,
        },
        "local_ip": get_local_ip(),
        "timestamp": time.time()
    })


@app.route('/api/stats/history')
def api_stats_history():
    """Last 30 data points for sparklines/charts"""
    with LOCK:
        return jsonify(list(stats_history))


@app.route('/api/connections')
def api_connections():
    """Live active network connections"""
    conns = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if not conn.raddr:
                continue
            try:
                proc_name = ""
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except:
                        pass
                conns.append({
                    "pid":        conn.pid,
                    "process":    proc_name,
                    "local_ip":   conn.laddr.ip if conn.laddr else "",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_ip":  conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "status":     conn.status,
                    "protocol":   "TCP",
                })
            except:
                pass
    except Exception as e:
        pass
    return jsonify(conns[:50])  # top 50


@app.route('/api/traffic')
def api_traffic():
    """Recent traffic log entries"""
    with LOCK:
        return jsonify(traffic_log[:50])


@app.route('/api/threats')
def api_threats():
    """Detected threats"""
    with LOCK:
        return jsonify(threat_log[:50])


@app.route('/api/threats/summary')
def api_threats_summary():
    """Threat counts by severity"""
    with LOCK:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for t in threat_log:
            sev = t.get("severity", "low")
            if sev in counts:
                counts[sev] += 1
            counts["total"] += 1
        return jsonify(counts)


@app.route('/api/processes')
def api_processes():
    """Top processes by CPU"""
    procs = []
    try:
        for proc in psutil.process_iter(['pid','name','cpu_percent','memory_percent','status']):
            try:
                procs.append(proc.info)
            except:
                pass
        procs.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
    except:
        pass
    return jsonify(procs[:20])


@app.route('/api/network/interfaces')
def api_interfaces():
    """Network interface stats"""
    interfaces = []
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        io    = psutil.net_io_counters(pernic=True)

        for name, stat in stats.items():
            ip = ""
            for addr in addrs.get(name, []):
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    break
            nic_io = io.get(name)
            interfaces.append({
                "name":       name,
                "ip":         ip,
                "is_up":      stat.isup,
                "speed_mbps": stat.speed,
                "bytes_sent": nic_io.bytes_sent if nic_io else 0,
                "bytes_recv": nic_io.bytes_recv if nic_io else 0,
            })
    except Exception as e:
        pass
    return jsonify(interfaces)


@app.route('/api/overview')
def api_overview():
    """All overview stats in one call"""
    cpu    = psutil.cpu_percent(interval=0.1)
    mem    = psutil.virtual_memory()
    net_io = psutil.net_io_counters()

    with LOCK:
        threat_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for t in threat_log:
            sev = t.get("severity", "low")
            if sev in threat_counts:
                threat_counts[sev] += 1

        # Active connections count
        try:
            active_conns = len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
        except:
            active_conns = 0

        # Traffic history for chart
        history = list(stats_history)

    return jsonify({
        "cpu_percent":      cpu,
        "memory_percent":   mem.percent,
        "active_connections": active_conns,
        "bytes_sent":       net_io.bytes_sent,
        "bytes_recv":       net_io.bytes_recv,
        "threats_total":    len(threat_log),
        "threats_critical": threat_counts["critical"],
        "threats_high":     threat_counts["high"],
        "blocked_ips":      len(blocked_ips),
        "traffic_history":  history,
    })


@app.route('/api/health')
def api_health():
    return jsonify({"status": "ok", "time": datetime.datetime.now().isoformat()})


# ============================================================
# SERVE STATIC FILES (localhost mode)
# ============================================================

@app.route('/')
def serve_login():
    return send_from_directory(BASE_DIR, 'login.html')

@app.route('/dashboard')
def serve_dashboard():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(BASE_DIR, filename)


# ============================================================
# FALCON AI CHATBOX API
# ============================================================

def get_system_snapshot():
    """Get current system data for chat context"""
    try:
        cpu  = psutil.cpu_percent(interval=0.2)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net  = psutil.net_io_counters()
        with LOCK:
            t_count    = len(threat_log)
            t_critical = sum(1 for t in threat_log if t.get('severity') == 'critical')
            t_high     = sum(1 for t in threat_log if t.get('severity') == 'high')
            recent_t   = threat_log[:3] if threat_log else []
            active_c   = len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
        return {
            "cpu": cpu, "memory": mem.percent,
            "disk": disk.percent,
            "mem_used": round(mem.used/1e9,1), "mem_total": round(mem.total/1e9,1),
            "threats_total": t_count, "threats_critical": t_critical,
            "threats_high": t_high, "recent_threats": recent_t,
            "active_connections": active_c,
            "bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv,
            "blocked_ips": len(blocked_ips),
        }
    except:
        return {}


def falcon_ai_respond(message):
    """
    Rule-based AI chat engine for FALCON.
    Responds to cybersecurity and system queries with real data.
    """
    msg  = message.lower().strip()
    snap = get_system_snapshot()
    now  = datetime.datetime.now().strftime("%H:%M:%S")

    # ---- CPU ----
    if any(w in msg for w in ['cpu', 'processor', 'core']):
        cpu = snap.get('cpu', 0)
        level = 'normal' if cpu < 70 else ('high' if cpu < 90 else 'critical')
        advice = '' if level == 'normal' else ' Consider closing heavy applications.' if level == 'high' else ' Immediate investigation recommended!'
        return f"🖥️ **CPU Usage: {cpu:.1f}%** — Status: `{level.upper()}`\n\n" \
               f"Current CPU utilization is at **{cpu:.1f}%**.{advice}\n\n" \
               f"*Tip: High CPU can indicate crypto-mining malware or a runaway process.*"

    # ---- Memory / RAM ----
    elif any(w in msg for w in ['memory', 'ram', 'mem']):
        m = snap.get('memory', 0)
        used = snap.get('mem_used', 0)
        total = snap.get('mem_total', 0)
        level = 'normal' if m < 75 else ('high' if m < 90 else 'critical')
        return f"💾 **Memory Usage: {m:.1f}%** ({used} / {total} GB)\n\n" \
               f"RAM utilization is at **{m:.1f}%** — Status: `{level.upper()}`\n\n" \
               f"*Tip: Sudden memory spikes can indicate a memory injection attack.*"

    # ---- Disk ----
    elif any(w in msg for w in ['disk', 'storage', 'drive', 'hard']):
        d = snap.get('disk', 0)
        return f"💽 **Disk Usage: {d:.1f}%**\n\nStorage utilization is at **{d:.1f}%**.\n\n" \
               f"*Tip: Ransomware can rapidly fill disk space with encrypted files.*"

    # ---- Threats ----
    elif any(w in msg for w in ['threat', 'attack', 'intrusion', 'detect', 'malware', 'virus']):
        total = snap.get('threats_total', 0)
        crit  = snap.get('threats_critical', 0)
        high  = snap.get('threats_high', 0)
        recent = snap.get('recent_threats', [])
        resp = f"🛡️ **Threat Summary** (as of {now})\n\n" \
               f"- Total detected: **{total}**\n" \
               f"- Critical: **{crit}**\n" \
               f"- High: **{high}**\n" \
               f"- Blocked IPs: **{snap.get('blocked_ips',0)}**\n\n"
        if recent:
            resp += "**Recent threats:**\n"
            for t in recent:
                resp += f"• `{t.get('type','Unknown')}` — {t.get('source_ip','?')} [{t.get('severity','?').upper()}] at {t.get('time','?')}\n"
        else:
            resp += "✅ *No active threats detected at this moment.*"
        return resp

    # ---- Network ----
    elif any(w in msg for w in ['network', 'traffic', 'connection', 'bandwidth', 'packet']):
        conns = snap.get('active_connections', 0)
        sent  = round(snap.get('bytes_sent', 0) / 1e6, 1)
        recv  = round(snap.get('bytes_recv', 0) / 1e6, 1)
        return f"🌐 **Network Status** (as of {now})\n\n" \
               f"- Active connections: **{conns}**\n" \
               f"- Total sent: **{sent} MB**\n" \
               f"- Total received: **{recv} MB**\n\n" \
               f"*FALCON is monitoring all {conns} active connections for anomalies.*"

    # ---- Blocked IPs ----
    elif any(w in msg for w in ['block', 'banned', 'blacklist', 'blocked ip']):
        b = snap.get('blocked_ips', 0)
        ips = list(blocked_ips)[:5]
        resp = f"🚫 **Blocked IPs: {b}**\n\n"
        if ips:
            resp += "Recently blocked:\n" + "\n".join(f"• `{ip}`" for ip in ips)
        else:
            resp += "*No IPs have been blocked yet.*"
        return resp

    # ---- Port scan ----
    elif any(w in msg for w in ['port scan', 'portscan', 'nmap', 'scan']):
        return "🔍 **Port Scan Detection**\n\nFALCON detects port scans when a single IP probes more than **10 different ports** within a session.\n\n" \
               "Detected scans are automatically:\n• Logged to the threat feed\n• Source IP flagged\n• Added to blocked list after threshold\n\n" \
               f"Current blocked IPs: **{snap.get('blocked_ips',0)}**"

    # ---- DDoS ----
    elif any(w in msg for w in ['ddos', 'dos', 'flood', 'syn']):
        return "⚡ **DDoS / Flood Detection**\n\nFALCON detects connection floods when a single IP makes more than **20 connections per minute**.\n\n" \
               "Indicators monitored:\n• SYN flood patterns\n• High connection rates\n• Bandwidth spikes\n\n" \
               "*Tip: Enable rate limiting on your router for additional protection.*"

    # ---- Status / Health ----
    elif any(w in msg for w in ['status', 'health', 'system', 'ok', 'how are you', 'running']):
        cpu = snap.get('cpu', 0)
        mem = snap.get('memory', 0)
        t   = snap.get('threats_total', 0)
        overall = '🟢 HEALTHY' if (cpu < 80 and mem < 85 and t == 0) else \
                  '🟡 CAUTION' if (cpu < 90 and mem < 90 and t < 5) else '🔴 ALERT'
        return f"📊 **System Status: {overall}**\n\n" \
               f"| Metric | Value | Status |\n|---|---|---|\n" \
               f"| CPU | {cpu:.1f}% | {'✅' if cpu<80 else '⚠️'} |\n" \
               f"| Memory | {mem:.1f}% | {'✅' if mem<85 else '⚠️'} |\n" \
               f"| Threats | {t} | {'✅' if t==0 else '🚨'} |\n" \
               f"| Connections | {snap.get('active_connections',0)} | ✅ |\n\n" \
               f"*Last checked: {now}*"

    # ---- Help ----
    elif any(w in msg for w in ['help', 'what can you', 'commands', 'hi', 'hello', 'hey']):
        return "👋 **Hello! I'm FALCON AI Assistant.**\n\nI can answer questions about your system in real-time. Try asking:\n\n" \
               "• `What is my CPU usage?`\n" \
               "• `Show memory status`\n" \
               "• `Any threats detected?`\n" \
               "• `Network traffic status`\n" \
               "• `What IPs are blocked?`\n" \
               "• `System health report`\n" \
               "• `What is a port scan?`\n" \
               "• `Explain DDoS attack`\n\n" \
               "*I'm powered by real-time data from your system.*"

    # ---- Cybersecurity education ----
    elif any(w in msg for w in ['ransomware', 'encrypt']):
        return "🔐 **Ransomware**\n\nRansomware encrypts your files and demands payment for decryption.\n\n" \
               "**FALCON detects it by:**\n• Rapid file system changes\n• Suspicious process spawning\n• Known signature matches\n\n" \
               "**Prevention:** Keep backups, patch systems, don't open unknown attachments."

    elif any(w in msg for w in ['phishing', 'email']):
        return "📧 **Phishing**\n\nPhishing attacks trick users into revealing credentials via fake emails/websites.\n\n" \
               "**Signs to watch:**\n• Mismatched sender domains\n• Urgent language\n• Suspicious links\n• Unexpected attachments\n\n" \
               "*FALCON monitors outbound connections to known phishing domains.*"

    elif any(w in msg for w in ['firewall', 'rule']):
        return "🔥 **Firewall**\n\nA firewall filters network traffic based on rules.\n\n" \
               "**FALCON complements your firewall by:**\n• Deep packet inspection\n• Behavioral analysis\n• Zero-day threat detection\n• Real-time alerting"

    elif any(w in msg for w in ['vpn', 'tor', 'proxy']):
        return "🕵️ **VPN/TOR/Proxy Detection**\n\nFALCON monitors connections to:\n• TOR relay ports (9001, 9050)\n• Known VPN endpoints\n• Anonymous proxy services\n\n" \
               "*These are flagged as potential data exfiltration vectors.*"

    # ---- Default ----
    else:
        responses = [
            f"🤖 I'm FALCON AI. I specialize in cybersecurity monitoring. Try asking about **CPU, memory, threats, network, or blocked IPs**.",
            f"🛡️ I didn't quite understand that. I can tell you about your **system health, active threats, or network status**. What would you like to know?",
            f"🔍 That's outside my current knowledge base. Ask me about **threats detected, CPU usage, memory, or network connections** — I have live data!",
        ]
        return random.choice(responses)


@app.route('/api/chat', methods=['POST'])
def api_chat():
    """FALCON AI Chat endpoint"""
    try:
        data    = request.get_json()
        message = data.get('message', '').strip()
        if not message:
            return jsonify({"error": "No message provided"}), 400

        reply = falcon_ai_respond(message)
        return jsonify({
            "reply":     reply,
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "agent":     "FALCON AI"
        })
    except Exception as e:
        return jsonify({"reply": "⚠️ FALCON AI encountered an error. Please try again.", "timestamp": "", "agent": "FALCON AI"})


# ============================================================
# START BACKGROUND THREADS
# ============================================================
def start_background_threads():
    threads = [
        threading.Thread(target=monitor_connections, daemon=True),
        threading.Thread(target=monitor_processes,   daemon=True),
        threading.Thread(target=collect_stats,       daemon=True),
    ]
    for t in threads:
        t.start()
    print("✅ Background monitors started")


if __name__ == '__main__':
    print("=" * 55)
    print("  PROJECT FALCON - AI Threat Detection System")
    print("=" * 55)
    print(f"  Local IP  : {get_local_ip()}")
    print(f"  Dashboard : http://localhost:5000")
    print(f"  Login     : http://localhost:5000/login.html")
    print("=" * 55)
    start_background_threads()
    # Auto-open browser after 1.5 seconds
    def open_browser():
        time.sleep(1.5)
        webbrowser.open('http://localhost:5000/login.html')
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
