"""
PROJECT FALCON - Real Network Monitor & Threat Detection Backend
Run: python server.py
Requires: pip install flask flask-cors psutil scapy
"""

from flask import Flask, jsonify
from flask_cors import CORS
import psutil
import time
import threading
import datetime
import socket
import collections
import re
import os

app = Flask(__name__)
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
    """Collect system stats every 3 seconds"""
    while True:
        try:
            net_io = psutil.net_io_counters()
            time.sleep(1)
            net_io2 = psutil.net_io_counters()

            bytes_sent = net_io2.bytes_sent - net_io.bytes_sent
            bytes_recv = net_io2.bytes_recv - net_io.bytes_recv

            point = {
                "timestamp": time.time(),
                "cpu":       psutil.cpu_percent(interval=None),
                "memory":    psutil.virtual_memory().percent,
                "bytes_sent": max(0, bytes_sent),
                "bytes_recv": max(0, bytes_recv),
            }
            with LOCK:
                stats_history.append(point)
        except Exception:
            pass
        time.sleep(2)


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
    print("  PROJECT FALCON - AI Threat Detection Backend")
    print("=" * 55)
    print(f"  Local IP : {get_local_ip()}")
    print(f"  API URL  : http://localhost:5000")
    print(f"  Dashboard: open index.html in your browser")
    print("=" * 55)
    start_background_threads()
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
