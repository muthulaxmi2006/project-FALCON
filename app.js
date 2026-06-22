/* =========================================================
   PROJECT FALCON – Dashboard JavaScript
   ========================================================= */

'use strict';

// ---- Utility helpers ----
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];
const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const randF = (min, max, dp = 1) => +(Math.random() * (max - min) + min).toFixed(dp);

// ============================================================
// BACKEND API CONFIG
// ============================================================
const API = 'http://localhost:5000/api';
let backendOnline = false;

async function apiFetch(endpoint) {
  try {
    const res = await fetch(API + endpoint, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } catch (e) {
    return null;
  }
}

async function checkBackend() {
  const data = await apiFetch('/health');
  backendOnline = !!data;
  updateBackendStatus(backendOnline);
  return backendOnline;
}

function updateBackendStatus(online) {
  const dot = $('.status-dot');
  const label = dot?.nextElementSibling;
  if (online) {
    dot?.classList.remove('offline');
    dot?.classList.add('online');
    if (label) label.textContent = 'Backend Online';
  } else {
    dot?.classList.remove('online');
    dot?.classList.add('offline');
    if (label) label.textContent = 'Demo Mode (No Backend)';
  }
}

function fmtBytes(bytes) {
  if (bytes < 1024) return bytes + ' B/s';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB/s';
  return (bytes / 1024 / 1024).toFixed(2) + ' MB/s';
}

function fmtBytesTotal(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 ** 2) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 ** 3) return (bytes / 1024 ** 2).toFixed(2) + ' MB';
  return (bytes / 1024 ** 3).toFixed(2) + ' GB';
}

// ============================================================
// LOADING SCREEN
// ============================================================
(function initLoader() {
  const overlay = $('#loadingOverlay');
  const bar = $('#loaderProgress');
  let prog = 0;
  const iv = setInterval(() => {
    prog += rand(4, 12);
    if (prog >= 100) { prog = 100; clearInterval(iv); }
    bar.style.width = prog + '%';
    if (prog === 100) {
      setTimeout(() => {
        overlay.classList.add('hidden');
        setTimeout(() => overlay.remove(), 400);
        initDashboard();
      }, 300);
    }
  }, 80);
})();

// ============================================================
// NAVIGATION
// ============================================================
function initNav() {
  const navItems = $$('.nav-item[data-section]');
  const sections = $$('.section');

  navItems.forEach(item => {
    item.addEventListener('click', e => {
      e.preventDefault();
      const target = item.dataset.section;

      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');

      sections.forEach(s => s.classList.remove('active'));
      const sec = $(`#section-${target}`);
      if (sec) sec.classList.add('active');

      $('#pageTitle').querySelector('span').textContent = item.querySelector('span').textContent;
      $('.crumb-active').textContent = item.querySelector('span').textContent;

      // Close mobile sidebar
      $('#sidebar').classList.remove('open');
      $('.sidebar-overlay')?.classList.remove('active');

      // Lazy-init section charts
      initSectionCharts(target);
    });
  });

  // Mobile toggle
  $('#menuToggle').addEventListener('click', () => {
    $('#sidebar').classList.toggle('open');
    let overlay = $('.sidebar-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.className = 'sidebar-overlay';
      document.body.appendChild(overlay);
      overlay.addEventListener('click', () => {
        $('#sidebar').classList.remove('open');
        overlay.classList.remove('active');
      });
    }
    overlay.classList.toggle('active');
  });

  // Chip buttons
  $$('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const siblings = chip.closest('.card-actions').querySelectorAll('.chip');
      siblings.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
    });
  });
}

// ============================================================
// MAIN INIT
// ============================================================
async function initDashboard() {
  initNav();
  buildTicker();

  const online = await checkBackend();

  // Always build chart skeletons first (they need canvas to exist)
  buildSparklines();
  buildTrafficChart();
  buildProtocolChart();

  if (online) {
    // ---- REAL DATA ----
    await refreshOverviewStats();
    await loadRealRecentThreats();
    await loadRealGeoConnections();
    await loadRealTrafficChart();
    startRealDataPolling();
  } else {
    // ---- DEMO FALLBACK ----
    animateCounters();
    buildRecentEventsTable();
    buildGeoList();
    startLiveUpdates();
  }
}

// ============================================================
// LIVE TICKER
// ============================================================
const TICKER_EVENTS = [
  { cls: 'ti-threat', msg: '⚠ SQL Injection attempt blocked — 192.168.44.21' },
  { cls: 'ti-safe',   msg: '✔ Scan complete — 0 threats on segment 10.0.0.0/24' },
  { cls: 'ti-warn',   msg: '◉ Port scan detected — src: 45.33.32.156' },
  { cls: 'ti-threat', msg: '⚠ Brute-force SSH detected — 198.51.100.42 (47 attempts)' },
  { cls: 'ti-safe',   msg: '✔ Firewall rules updated — policy v12.4' },
  { cls: 'ti-warn',   msg: '◉ Anomalous traffic spike — VLAN 30 (+340%)' },
  { cls: 'ti-threat', msg: '⚠ DDoS mitigation active — 2.4 Gbps absorbed' },
  { cls: 'ti-safe',   msg: '✔ Threat actor 185.220.101.x blacklisted' },
  { cls: 'ti-warn',   msg: '◉ Suspicious outbound on port 4444 — workstation WS-041' },
  { cls: 'ti-threat', msg: '⚠ Ransomware signature detected — quarantined' },
];

function buildTicker() {
  const container = $('#tickerContent');
  // Duplicate for seamless loop
  const doubled = [...TICKER_EVENTS, ...TICKER_EVENTS];
  container.innerHTML = doubled.map(e =>
    `<span class="${e.cls}">${e.msg}</span>`
  ).join('');
}

// ============================================================
// COUNTER ANIMATION
// ============================================================
function animateCounters() {
  $$('.stat-value[data-target]').forEach(el => {
    const target = parseInt(el.dataset.target);
    const duration = 1600;
    const start = performance.now();
    const raf = (ts) => {
      const p = Math.min((ts - start) / duration, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(ease * target).toLocaleString();
      if (p < 1) requestAnimationFrame(raf);
    };
    requestAnimationFrame(raf);
  });
}

// ============================================================
// SPARKLINES
// ============================================================
function buildSparklines() {
  const configs = [
    { id: 'spark1', color: '#1565c0', data: [40,55,45,62,58,70,65,72,68,80] },
    { id: 'spark2', color: '#0288d1', data: [30,35,40,38,45,50,48,55,52,60] },
    { id: 'spark3', color: '#e65100', data: [10,15,12,20,25,18,30,22,28,35] },
    { id: 'spark4', color: '#c62828', data: [5,3,7,4,8,6,10,8,11,12] },
  ];
  configs.forEach(cfg => {
    const ctx = $(`#${cfg.id}`).getContext('2d');
    new Chart(ctx, {
      type: 'line',
      data: {
        labels: cfg.data.map(() => ''),
        datasets: [{ data: cfg.data, borderColor: cfg.color, borderWidth: 2, pointRadius: 0, fill: true,
          backgroundColor: ctx => {
            const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 36);
            g.addColorStop(0, cfg.color + '40');
            g.addColorStop(1, cfg.color + '00');
            return g;
          }
        }]
      },
      options: { animation: false, responsive: false, plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false } } }
    });
  });
}

// ============================================================
// TRAFFIC AREA CHART
// ============================================================
function buildTrafficChart() {
  const labels = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2,'0')}:00`);
  const legit = [120,145,132,160,175,148,190,220,245,280,310,295,320,340,300,280,260,290,310,330,295,270,248,220];
  const threat = [12,8,15,10,18,22,25,30,28,35,42,38,45,52,40,35,30,42,48,55,38,30,25,18];

  const ctx = $('#trafficChart').getContext('2d');
  const g1 = ctx.createLinearGradient(0, 0, 0, 200);
  g1.addColorStop(0, 'rgba(21,101,192,0.18)');
  g1.addColorStop(1, 'rgba(21,101,192,0)');
  const g2 = ctx.createLinearGradient(0, 0, 0, 200);
  g2.addColorStop(0, 'rgba(198,40,40,0.15)');
  g2.addColorStop(1, 'rgba(198,40,40,0)');

  window._trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'Legitimate Traffic', data: legit, borderColor: '#1565c0', borderWidth: 2.5,
          backgroundColor: g1, fill: true, tension: 0.4, pointRadius: 0, pointHoverRadius: 5,
          pointHoverBackgroundColor: '#1565c0' },
        { label: 'Threat Traffic', data: threat, borderColor: '#c62828', borderWidth: 2,
          backgroundColor: g2, fill: true, tension: 0.4, pointRadius: 0, pointHoverRadius: 5,
          pointHoverBackgroundColor: '#c62828' }
      ]
    },
    options: {
      responsive: true,
      animation: { duration: 800 },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { labels: { color: '#2c5282', font: { size: 12 }, boxWidth: 12, usePointStyle: true, pointStyle: 'circle' } },
        tooltip: { backgroundColor: '#ffffff', borderColor: '#d0e4f7', borderWidth: 1, titleColor: '#0d1b2a', bodyColor: '#2c5282', padding: 12 }
      },
      scales: {
        x: { grid: { color: 'rgba(21,101,192,0.06)' }, ticks: { color: '#7a9fc0', maxTicksLimit: 12, font: { size: 11 } } },
        y: { grid: { color: 'rgba(21,101,192,0.06)' }, ticks: { color: '#7a9fc0', font: { size: 11 } }, beginAtZero: true }
      }
    }
  });
}

// ============================================================
// PROTOCOL PIE CHART
// ============================================================
function buildProtocolChart() {
  const ctx = $('#protocolChart').getContext('2d');
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['HTTPS', 'HTTP', 'DNS', 'SSH', 'FTP', 'Other'],
      datasets: [{
        data: [42, 18, 15, 10, 7, 8],
        backgroundColor: ['#1565c0','#0288d1','#2e7d32','#e65100','#c62828','#6a1b9a'],
        borderColor: '#ffffff',
        borderWidth: 3,
        hoverOffset: 8
      }]
    },
    options: {
      responsive: true,
      cutout: '68%',
      plugins: {
        legend: { position: 'bottom', labels: { color: '#2c5282', font: { size: 11 }, padding: 12, boxWidth: 10, usePointStyle: true, pointStyle: 'circle' } },
        tooltip: {
          backgroundColor: '#ffffff', borderColor: '#d0e4f7', borderWidth: 1,
          titleColor: '#0d1b2a', bodyColor: '#2c5282',
          callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw}%` }
        }
      }
    }
  });
}

// ============================================================
// RECENT EVENTS TABLE
// ============================================================
const EVENT_TYPES = ['Port Scan','SQL Injection','Brute Force','DDoS','Phishing','XSS','MITM','Ransomware','Zero-Day','Recon'];
const IPS = ['192.168.1.101','10.0.0.45','172.16.0.22','203.0.113.5','198.51.100.42','45.33.32.156','185.220.101.33','104.21.55.10','8.8.4.4','1.1.1.1'];

function buildRecentEventsTable() {
  const tbody = $('#recentEventsTable');
  const now = new Date();
  tbody.innerHTML = Array.from({ length: 10 }, (_, i) => {
    const d = new Date(now - i * rand(180000, 600000));
    const time = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const type = EVENT_TYPES[rand(0, EVENT_TYPES.length - 1)];
    const src  = IPS[rand(0, IPS.length - 1)];
    const sevMap = ['critical','critical','high','high','high','medium','medium','medium','low','low'];
    const statusMap = ['blocked','flagged','blocked','flagged','scanning'];
    const sev = sevMap[i];
    const status = statusMap[rand(0, statusMap.length - 1)];
    return `<tr>
      <td>${time}</td>
      <td style="color:var(--text-primary);font-weight:500">${type}</td>
      <td><span class="ip-tag">${src}</span></td>
      <td><span class="pill ${sev}">${sev.toUpperCase()}</span></td>
      <td><span class="pill ${status}">${status.toUpperCase()}</span></td>
    </tr>`;
  }).join('');
}

// ============================================================
// GEO / ATTACK SOURCES
// ============================================================
const GEO_DATA = [
  { flag: '🇨🇳', country: 'China', count: 1240, pct: 88 },
  { flag: '🇷🇺', country: 'Russia', count: 987, pct: 72 },
  { flag: '🇺🇸', country: 'United States', count: 654, pct: 48 },
  { flag: '🇧🇷', country: 'Brazil', count: 432, pct: 35 },
  { flag: '🇩🇪', country: 'Germany', count: 321, pct: 26 },
  { flag: '🇮🇳', country: 'India', count: 278, pct: 22 },
  { flag: '🇰🇵', country: 'North Korea', count: 198, pct: 16 },
];

function buildGeoList() {
  const el = $('#geoList');
  el.innerHTML = GEO_DATA.map(g => `
    <div class="geo-item">
      <div class="geo-flag">${g.flag}</div>
      <div class="geo-bar-wrap">
        <div class="geo-label">
          <span class="geo-country">${g.country}</span>
          <span class="geo-count">${g.count.toLocaleString()} attacks</span>
        </div>
        <div class="geo-bar"><div class="geo-fill" style="width:0%" data-w="${g.pct}"></div></div>
      </div>
    </div>
  `).join('');

  // Animate bars after render
  setTimeout(() => {
    $$('.geo-fill').forEach(el => {
      el.style.width = el.dataset.w + '%';
    });
  }, 200);
}

// ============================================================
// TRAFFIC TABLE (Live Monitoring)
// ============================================================
const PROTOCOLS = ['TCP','UDP','ICMP','HTTP','HTTPS','DNS','SSH','FTP','SMTP'];
const STATUSES  = ['allowed','allowed','allowed','blocked','flagged','scanning'];

function generateRow(i) {
  const src  = `${rand(1,254)}.${rand(0,255)}.${rand(0,255)}.${rand(1,254)}`;
  const dst  = `${rand(1,254)}.${rand(0,255)}.${rand(0,255)}.${rand(1,254)}`;
  const proto = PROTOCOLS[rand(0, PROTOCOLS.length - 1)];
  const port  = [80,443,22,21,53,8080,3306,1433,25,110][rand(0,9)];
  const bytes = `${rand(64, 65536)} B`;
  const status = STATUSES[rand(0, STATUSES.length - 1)];
  const now = new Date();
  const ts = now.toLocaleTimeString('en-US', { hour12: false });
  return `<tr class="${status === 'blocked' ? 'row-blocked' : ''}">
    <td style="color:var(--text-muted);font-size:0.72rem">${i}</td>
    <td style="font-size:0.75rem;color:var(--text-muted)">${ts}</td>
    <td><span class="ip-tag">${src}</span></td>
    <td><span class="ip-tag">${dst}</span></td>
    <td><span class="protocol-tag">${proto}</span></td>
    <td style="color:var(--text-secondary)">${port}</td>
    <td style="color:var(--text-secondary)">${bytes}</td>
    <td><span class="pill ${status}">${status.toUpperCase()}</span></td>
    <td>
      <button class="action-btn" title="Inspect"><i class="fas fa-magnifying-glass"></i></button>
      <button class="action-btn" title="Block" style="margin-left:4px"><i class="fas fa-ban"></i></button>
    </td>
  </tr>`;
}

function buildTrafficTable() {
  const tbody = $('#trafficTableBody');
  tbody.innerHTML = Array.from({ length: 20 }, (_, i) => generateRow(i + 1)).join('');

  // Filter
  $('#tableFilter').addEventListener('input', function() {
    const q = this.value.toLowerCase();
    $$('#trafficTableBody tr').forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

// ============================================================
// LIVE TRAFFIC CHART (streaming)
// ============================================================
let liveChart;
const LIVE_LABELS = Array.from({ length: 30 }, (_, i) => '');
const liveInbound  = Array.from({ length: 30 }, () => rand(40, 120));
const liveOutbound = Array.from({ length: 30 }, () => rand(20, 80));

function buildLiveTrafficChart() {
  const ctx = $('#liveTrafficChart').getContext('2d');
  const g1 = ctx.createLinearGradient(0, 0, 0, 120);
  g1.addColorStop(0, 'rgba(2,136,209,0.25)'); g1.addColorStop(1, 'rgba(2,136,209,0)');
  const g2 = ctx.createLinearGradient(0, 0, 0, 120);
  g2.addColorStop(0, 'rgba(21,101,192,0.18)'); g2.addColorStop(1, 'rgba(21,101,192,0)');

  liveChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [...LIVE_LABELS],
      datasets: [
        { label: 'Inbound', data: [...liveInbound], borderColor: '#0288d1', borderWidth: 2, backgroundColor: g1, fill: true, tension: 0.4, pointRadius: 0 },
        { label: 'Outbound', data: [...liveOutbound], borderColor: '#1565c0', borderWidth: 2, backgroundColor: g2, fill: true, tension: 0.4, pointRadius: 0 },
      ]
    },
    options: {
      animation: { duration: 200 },
      responsive: true,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { labels: { color: '#2c5282', font: { size: 11 }, boxWidth: 10, usePointStyle: true } },
        tooltip: { backgroundColor: '#ffffff', borderColor: '#d0e4f7', borderWidth: 1, titleColor: '#0d1b2a', bodyColor: '#2c5282' }
      },
      scales: {
        x: { display: false },
        y: { grid: { color: 'rgba(21,101,192,0.06)' }, ticks: { color: '#7a9fc0', font: { size: 10 } }, beginAtZero: true }
      }
    }
  });
}

// ============================================================
// THREAT ANALYSIS CHARTS
// ============================================================
let riskGaugeChart;

function buildRiskGauge() {
  const ctx = $('#riskGauge').getContext('2d');
  const score = 64;

  riskGaugeChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, 100 - score],
        backgroundColor: ['#e65100', 'rgba(21,101,192,0.08)'],
        borderColor: ['#e65100', 'transparent'],
        borderWidth: [3, 0],
        hoverOffset: 0,
      }]
    },
    options: {
      responsive: false,
      rotation: -90, circumference: 180,
      cutout: '75%',
      animation: { animateRotate: true, duration: 1200 },
      plugins: { legend: { display: false }, tooltip: { enabled: false } }
    }
  });
}

function buildAttackChart() {
  const ctx = $('#attackChart').getContext('2d');
  const labels = ['Port Scan','Brute Force','DDoS','SQL Inject','Phishing','XSS','MITM'];
  const data   = [87, 54, 42, 38, 29, 22, 15];

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Incidents',
        data,
        backgroundColor: data.map((v, i) => {
          const colors = ['rgba(198,40,40,0.7)','rgba(230,81,0,0.7)','rgba(198,40,40,0.5)','rgba(230,81,0,0.5)','rgba(21,101,192,0.6)','rgba(2,136,209,0.5)','rgba(21,101,192,0.4)'];
          return colors[i];
        }),
        borderColor: ['#c62828','#e65100','#c62828','#e65100','#1565c0','#0288d1','#1565c0'],
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor: '#ffffff', borderColor: '#d0e4f7', borderWidth: 1, titleColor: '#0d1b2a', bodyColor: '#2c5282' }
      },
      scales: {
        x: { grid: { color: 'rgba(21,101,192,0.06)' }, ticks: { color: '#7a9fc0', font: { size: 10 } } },
        y: { grid: { display: false }, ticks: { color: '#2c5282', font: { size: 11 } } }
      }
    }
  });
}

function buildSeverityChart() {
  const ctx = $('#severityChart').getContext('2d');
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{
        data: [12, 34, 89, 212],
        backgroundColor: ['#c62828','#e65100','#f57f17','#2e7d32'],
        borderColor: '#ffffff',
        borderWidth: 3,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive: true,
      cutout: '60%',
      plugins: {
        legend: { position: 'bottom', labels: { color: '#2c5282', font: { size: 11 }, boxWidth: 10, usePointStyle: true, padding: 10 } },
        tooltip: { backgroundColor: '#ffffff', borderColor: '#d0e4f7', borderWidth: 1, titleColor: '#0d1b2a', bodyColor: '#2c5282' }
      }
    }
  });
}

// ============================================================
// THREAT FEED
// ============================================================
const THREAT_DATA = [
  { icon: 'fa-skull-crossbones', cls: 'red',    sev: 'critical', title: 'APT29 C2 Communication Detected',       sub: '185.220.101.33 → 10.0.0.45 | Port 443', time: '2 min ago' },
  { icon: 'fa-burst',           cls: 'red',    sev: 'critical', title: 'Ransomware Signature Match (LockBit 3.0)', sub: 'Workstation WS-041 | 47 files encrypted', time: '8 min ago' },
  { icon: 'fa-database',        cls: 'orange', sev: 'high',     title: 'SQL Injection Campaign Active',            sub: '203.0.113.5 → web-server-02 | 234 attempts', time: '12 min ago' },
  { icon: 'fa-bomb',            cls: 'orange', sev: 'high',     title: 'DDoS Attack — SYN Flood',                  sub: '14.2 Gbps incoming | CDN mitigation active', time: '19 min ago' },
  { icon: 'fa-user-secret',     cls: 'yellow', sev: 'medium',   title: 'Lateral Movement Attempt',                 sub: 'Internal: 10.0.0.12 → 10.0.0.0/24 sweep', time: '31 min ago' },
  { icon: 'fa-wifi',            cls: 'yellow', sev: 'medium',   title: 'Rogue Access Point Detected',              sub: 'SSID: "Corp-WiFi-Free" | Building C Floor 2', time: '45 min ago' },
  { icon: 'fa-envelope-open',   cls: 'blue',   sev: 'low',      title: 'Phishing Email Quarantined',               sub: '28 emails | Malicious attachment detected', time: '1 hr ago' },
  { icon: 'fa-magnifying-glass', cls: 'blue',  sev: 'low',      title: 'Automated Reconnaissance Scan',            sub: '45.33.32.156 | Nmap signature detected', time: '1.5 hr ago' },
];

function buildThreatFeed() {
  const feed = $('#threatFeed');
  feed.innerHTML = THREAT_DATA.map(t => `
    <div class="threat-item">
      <div class="ti-icon ${t.cls}"><i class="fas ${t.icon}"></i></div>
      <div class="ti-main">
        <div class="ti-title">${t.title}</div>
        <div class="ti-sub">${t.sub}</div>
      </div>
      <span class="pill ${t.sev}">${t.sev.toUpperCase()}</span>
      <span class="ti-time">${t.time}</span>
    </div>
  `).join('');
}

// ============================================================
// ALERTS CENTER
// ============================================================
const ALERTS_DATA = [
  { type: 'critical', icon: 'fa-skull', title: 'Critical: APT Activity Detected', desc: 'Advanced persistent threat indicators found on endpoint EP-0042. Possible data exfiltration in progress.', source: 'EDR Agent', time: '2m ago', unread: true },
  { type: 'critical', icon: 'fa-radiation', title: 'Critical: Ransomware Execution Blocked', desc: 'LockBit 3.0 ransomware execution blocked on WS-041. File encryption attempt detected and quarantined.', source: 'AV Engine', time: '8m ago', unread: true },
  { type: 'critical', icon: 'fa-triangle-exclamation', title: 'Critical: C2 Beacon Detected', desc: 'Outbound C2 communication to known threat actor infrastructure detected on internal host.', source: 'IDS Rule 2048', time: '15m ago', unread: true },
  { type: 'warning',  icon: 'fa-burst',      title: 'Warning: DDoS Attack Ongoing', desc: 'SYN flood attack targeting public IP 203.0.113.100. Mitigation in progress — 14.2 Gbps absorbed.', source: 'DDoS Guard', time: '19m ago', unread: false },
  { type: 'warning',  icon: 'fa-database',   title: 'Warning: SQL Injection Campaign', desc: 'Automated SQL injection attempts detected from 203.0.113.5 targeting login endpoints.', source: 'WAF', time: '31m ago', unread: true },
  { type: 'warning',  icon: 'fa-user-secret','title': 'Warning: Privilege Escalation', desc: 'Unauthorized privilege escalation attempt detected. User jsmith attempting sudo access.', source: 'SIEM Rule 44', time: '44m ago', unread: false },
  { type: 'warning',  icon: 'fa-door-open',  title: 'Warning: After-Hours Access', desc: 'User account accessed at 02:34 AM from unusual geolocation (TOR exit node).', source: 'UEBA Engine', time: '1h ago', unread: false },
  { type: 'info',     icon: 'fa-shield',     title: 'Info: Policy Update Applied', desc: 'Firewall policy v12.4 has been applied to all edge nodes. 847 new rules activated.', source: 'Config Mgmt', time: '2h ago', unread: false },
  { type: 'info',     icon: 'fa-rotate',     title: 'Info: Signature DB Updated', desc: 'Threat signature database updated to version 2024.12.1. 3,429 new signatures added.', source: 'Update Svc', time: '3h ago', unread: false },
  { type: 'info',     icon: 'fa-check',      title: 'Info: Vulnerability Scan Complete', desc: 'Scheduled vulnerability scan completed. 3 critical, 8 high, 22 medium vulnerabilities found.', source: 'Vuln Scanner', time: '4h ago', unread: false },
];

function buildAlerts() {
  const list = $('#alertsList');
  renderAlerts('all');

  $$('.filter-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $$('.filter-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      renderAlerts(tab.dataset.filter);
    });
  });
}

function renderAlerts(filter) {
  const list = $('#alertsList');
  const filtered = filter === 'all' ? ALERTS_DATA : ALERTS_DATA.filter(a => a.type === filter);
  const colorMap = { critical: 'red', warning: 'orange', info: 'blue' };
  const bgMap    = { critical: 'rgba(198,40,40,0.08)', warning: 'rgba(230,81,0,0.08)', info: 'rgba(21,101,192,0.08)' };

  list.innerHTML = filtered.map(a => `
    <div class="alert-card ${a.unread ? 'unread ' : ''}${a.type}">
      <div class="alert-icon" style="background:${bgMap[a.type]};color:var(--${colorMap[a.type]})">
        <i class="fas ${a.icon}"></i>
      </div>
      <div class="alert-body">
        <div class="alert-title">${a.title}</div>
        <div class="alert-desc">${a.desc}</div>
        <div class="alert-meta">
          <span><i class="fas fa-microchip" style="margin-right:4px"></i>${a.source}</span>
        </div>
      </div>
      <div class="alert-time">${a.time}</div>
    </div>
  `).join('');
}

function buildAlertTimeline() {
  const ctx = $('#alertTimeline').getContext('2d');
  const hours = Array.from({ length: 12 }, (_, i) => `${(i * 2).toString().padStart(2,'0')}:00`);
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: hours,
      datasets: [
        { label: 'Critical', data: [3,1,0,2,4,2,1,5,3,2,4,3], backgroundColor: 'rgba(198,40,40,0.7)', borderRadius: 3 },
        { label: 'Warning',  data: [6,4,2,5,8,6,4,9,7,5,8,6], backgroundColor: 'rgba(230,81,0,0.6)',  borderRadius: 3 },
        { label: 'Info',     data: [2,3,1,4,3,2,3,4,2,3,2,4], backgroundColor: 'rgba(21,101,192,0.5)',  borderRadius: 3 },
      ]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { labels: { color: '#2c5282', font: { size: 11 }, boxWidth: 10, usePointStyle: true } },
        tooltip: { backgroundColor: '#ffffff', borderColor: '#d0e4f7', borderWidth: 1, titleColor: '#0d1b2a', bodyColor: '#2c5282' }
      },
      scales: {
        x: { stacked: true, grid: { display: false }, ticks: { color: '#7a9fc0', font: { size: 10 } } },
        y: { stacked: true, grid: { color: 'rgba(21,101,192,0.06)' }, ticks: { color: '#7a9fc0', font: { size: 10 } } }
      }
    }
  });
}

// ============================================================
// REPORTS
// ============================================================
const REPORTS_DATA = [
  { name: 'Q4 2024 Threat Intelligence Report', type: 'Quarterly', date: '2025-01-02', size: '4.2 MB', status: 'ready' },
  { name: 'DDoS Incident Report — Dec 2024',    type: 'Incident',  date: '2024-12-28', size: '1.8 MB', status: 'ready' },
  { name: 'Monthly Security Summary — Nov 2024', type: 'Monthly',  date: '2024-12-01', size: '3.1 MB', status: 'ready' },
  { name: 'APT Campaign Analysis Report',        type: 'Threat Intel', date: '2024-11-20', size: '6.4 MB', status: 'ready' },
  { name: 'Vulnerability Assessment Q3 2024',    type: 'Assessment', date: '2024-10-15', size: '8.9 MB', status: 'ready' },
  { name: 'Compliance Audit — PCI DSS',          type: 'Compliance', date: '2024-09-30', size: '12.1 MB', status: 'ready' },
  { name: 'Insider Threat Investigation #IT-094', type: 'Incident', date: '2024-09-12', size: '2.3 MB', status: 'archived' },
];

function buildReports() {
  const tbody = $('#reportsTable');
  const typeColors = { Quarterly: 'blue', Incident: 'red', Monthly: 'cyan', 'Threat Intel': 'orange', Assessment: 'orange', Compliance: 'green', Incident: 'red' };
  tbody.innerHTML = REPORTS_DATA.map(r => `
    <tr>
      <td style="color:var(--text-primary);font-weight:500">
        <i class="fas fa-file-pdf" style="color:var(--red);margin-right:8px"></i>${r.name}
      </td>
      <td><span class="pill ${typeColors[r.type] || 'medium'}">${r.type.toUpperCase()}</span></td>
      <td style="color:var(--text-secondary)">${r.date}</td>
      <td style="color:var(--text-muted)">${r.size}</td>
      <td><span class="pill ${r.status === 'ready' ? 'allowed' : 'medium'}">${r.status.toUpperCase()}</span></td>
      <td>
        <button class="btn-sm btn-export" onclick="this.innerHTML='<i class=\\'fas fa-spinner fa-spin\\'></i> Loading';setTimeout(()=>this.innerHTML='<i class=\\'fas fa-check\\'></i> Done',1200)">
          <i class="fas fa-download"></i> Download
        </button>
      </td>
    </tr>
  `).join('');
}

function buildReportChart() {
  const ctx = $('#reportChart').getContext('2d');
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const g1 = ctx.createLinearGradient(0, 0, 0, 150);
  g1.addColorStop(0, 'rgba(21,101,192,0.3)'); g1.addColorStop(1, 'rgba(21,101,192,0)');

  new Chart(ctx, {
    type: 'line',
    data: {
      labels: months,
      datasets: [{
        label: 'Total Threats',
        data: [145,189,167,234,198,276,312,289,341,298,367,347],
        borderColor: '#1565c0', borderWidth: 2.5, backgroundColor: g1, fill: true, tension: 0.4, pointRadius: 4,
        pointBackgroundColor: '#1565c0', pointBorderColor: '#ffffff', pointBorderWidth: 2,
      },{
        label: 'Resolved',
        data: [138,175,155,218,182,255,289,265,318,275,342,320],
        borderColor: '#2e7d32', borderWidth: 2, backgroundColor: 'transparent', fill: false, tension: 0.4, pointRadius: 4,
        pointBackgroundColor: '#2e7d32', pointBorderColor: '#ffffff', pointBorderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { labels: { color: '#2c5282', font: { size: 12 }, boxWidth: 10, usePointStyle: true } },
        tooltip: { backgroundColor: '#ffffff', borderColor: '#d0e4f7', borderWidth: 1, titleColor: '#0d1b2a', bodyColor: '#2c5282' }
      },
      scales: {
        x: { grid: { color: 'rgba(21,101,192,0.06)' }, ticks: { color: '#7a9fc0', font: { size: 11 } } },
        y: { grid: { color: 'rgba(21,101,192,0.06)' }, ticks: { color: '#7a9fc0', font: { size: 11 } } }
      }
    }
  });
}

// ============================================================
// SYSTEM HEALTH
// ============================================================
const healthCharts = {};

function drawGauge(canvasId, value, color) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const cx = w / 2, cy = h * 0.9, r = Math.min(w, h * 1.8) * 0.42;
  const startAngle = Math.PI;
  const endAngle   = 2 * Math.PI;
  const valAngle   = startAngle + (value / 100) * Math.PI;

  // BG arc
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, endAngle);
  ctx.strokeStyle = 'rgba(21,101,192,0.1)';
  ctx.lineWidth = 12;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Value arc
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, valAngle);
  const g = ctx.createLinearGradient(cx - r, cy, cx + r, cy);
  g.addColorStop(0, color + 'aa');
  g.addColorStop(1, color);
  ctx.strokeStyle = g;
  ctx.lineWidth = 12;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Glow
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, valAngle);
  ctx.strokeStyle = color + '22';
  ctx.lineWidth = 18;
  ctx.lineCap = 'round';
  ctx.stroke();
}

function buildHealthHistoryChart(canvasId, color, data) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  const g = ctx.createLinearGradient(0, 0, 0, 60);
  g.addColorStop(0, color + '44'); g.addColorStop(1, color + '00');
  healthCharts[canvasId] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map(() => ''),
      datasets: [{ data, borderColor: color, borderWidth: 1.5, backgroundColor: g, fill: true, tension: 0.4, pointRadius: 0 }]
    },
    options: {
      animation: false, responsive: true,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: { x: { display: false }, y: { display: false, min: 0, max: 100 } }
    }
  });
}

function buildSystemHealth() {
  drawGauge('cpuGauge',  67, '#1565c0');
  drawGauge('memGauge',  82, '#e65100');
  drawGauge('netGauge',  45, '#0288d1');
  drawGauge('diskGauge', 38, '#2e7d32');

  buildHealthHistoryChart('cpuHistory', '#1565c0', [55,60,58,65,70,67,72,65,68,67,70,67]);
  buildHealthHistoryChart('memHistory', '#e65100', [75,77,76,79,81,80,83,82,84,82,83,82]);
  buildHealthHistoryChart('netHistory', '#0288d1', [30,35,40,38,42,45,43,46,44,47,45,45]);
  buildHealthHistoryChart('diskHistory','#2e7d32', [35,36,36,37,38,37,38,39,38,38,38,38]);
}

// ============================================================
// SERVICES
// ============================================================
const SERVICES = [
  { icon: 'fa-shield-halved', name: 'IDS/IPS Engine',       meta: 'Snort 3.1.45 | 14,392 rules active', uptime: 99.98, color: '#1565c0' },
  { icon: 'fa-fire-flame-curved', name: 'Firewall Service', meta: 'iptables v1.8 | 847 active rules',   uptime: 100,   color: '#0288d1' },
  { icon: 'fa-eye',           name: 'SIEM Correlation',     meta: 'Splunk 9.2 | 2.4M events/day',      uptime: 99.7,  color: '#2e7d32' },
  { icon: 'fa-robot',         name: 'AI Threat Engine',     meta: 'FALCON ML v4.2 | 98.3% accuracy',   uptime: 99.9,  color: '#6a1b9a' },
  { icon: 'fa-virus-slash',   name: 'Antivirus Scanner',    meta: 'ClamAV 1.3 | DB: 2024-12-21',      uptime: 100,   color: '#2e7d32' },
  { icon: 'fa-database',      name: 'Log Aggregator',       meta: 'Elasticsearch 8.11 | 3.2 TB indexed', uptime: 99.95, color: '#e65100' },
];

function buildServices() {
  const list = $('#servicesList');
  list.innerHTML = SERVICES.map(s => `
    <div class="service-item">
      <div class="svc-icon" style="background:${s.color}1a;color:${s.color}"><i class="fas ${s.icon}"></i></div>
      <div style="flex:1">
        <span class="svc-name">${s.name}</span>
        <span class="svc-meta">${s.meta}</span>
      </div>
      <div class="svc-status-bar"><div class="svc-fill" style="width:${s.uptime}%;background:${s.color}"></div></div>
      <span class="svc-pct">${s.uptime}%</span>
      <span class="health-badge ok" style="margin-left:8px">ACTIVE</span>
    </div>
  `).join('');
}

// ============================================================
// SYSTEM LOGS
// ============================================================
const LOG_MESSAGES = [
  { level: 'info',    msg: 'IDS engine started — 14392 signatures loaded' },
  { level: 'success', msg: 'Threat signature database updated to v2024.12.1' },
  { level: 'warn',    msg: 'Memory usage exceeding 80% threshold — monitor closely' },
  { level: 'error',   msg: 'C2 beacon detected — host 10.0.0.42 quarantined' },
  { level: 'info',    msg: 'Daily vulnerability scan initiated on subnet 10.0.0.0/24' },
  { level: 'success', msg: 'Firewall policy v12.4 applied to all edge nodes' },
  { level: 'warn',    msg: 'Anomalous traffic spike on VLAN 30 — +340% above baseline' },
  { level: 'info',    msg: 'Log rotation completed — archived 4.2 GB to cold storage' },
  { level: 'error',   msg: 'Port scan detected from 45.33.32.156 — blacklisted' },
  { level: 'success', msg: 'Automated response blocked 1,847 malicious packets' },
  { level: 'info',    msg: 'SSL/TLS certificate renewed — expires 2025-12-21' },
  { level: 'warn',    msg: 'Failed login attempts on admin portal — 23 attempts from 198.51.100.42' },
];

function buildSystemLogs() {
  const logEl = $('#systemLogs');
  const now = new Date();
  const lines = LOG_MESSAGES.map((l, i) => {
    const t = new Date(now - i * rand(15000, 120000));
    const ts = t.toLocaleTimeString('en-US', { hour12: false });
    const levelLabel = { info: 'INFO', warn: 'WARN', error: 'ERROR', success: 'OK' }[l.level];
    return `<div class="log-line">
      <span class="log-ts">${ts}</span>
      <span class="log-level ${l.level}">[${levelLabel}]</span>
      <span class="log-msg">${l.msg}</span>
    </div>`;
  });
  logEl.innerHTML = lines.join('');
  logEl.scrollTop = logEl.scrollHeight;
}

// ============================================================
// LAZY-INIT SECTION CHARTS (called when switching tabs)
// ============================================================
const sectionInited = new Set(['overview']);

async function initSectionCharts(section) {
  if (sectionInited.has(section)) return;
  sectionInited.add(section);

  if (section === 'monitoring') {
    if (!liveChart) buildLiveTrafficChart();
    if (backendOnline) {
      await loadRealConnections();
      await loadRealMiniStats();
      await loadRealLiveChart();
    } else {
      buildTrafficTable();
    }
  }

  if (section === 'threats') {
    buildRiskGauge();
    buildAttackChart();
    buildSeverityChart();
    if (backendOnline) {
      await loadRealThreatFeed();
      await loadRealThreatSummary();
    } else {
      buildThreatFeed();
    }
  }

  if (section === 'alerts') {
    buildAlertTimeline();
    if (backendOnline) {
      await loadRealAlerts();
    } else {
      buildAlerts();
    }
  }

  if (section === 'reports') {
    buildReports();
    buildReportChart();
  }

  if (section === 'health') {
    buildSystemHealth();
    buildServices();
    if (backendOnline) {
      await loadRealHealth();
      await loadRealProcessLogs();
    } else {
      buildSystemLogs();
    }
  }
}

// ============================================================
// LIVE UPDATES
// ============================================================
function startLiveUpdates() {
  // Update live traffic chart every 2s
  setInterval(() => {
    if (!liveChart) return;
    liveChart.data.datasets[0].data.shift();
    liveChart.data.datasets[0].data.push(rand(30, 140));
    liveChart.data.datasets[1].data.shift();
    liveChart.data.datasets[1].data.push(rand(20, 90));
    liveChart.update('none');
  }, 2000);

  // Update mini stats every 3s
  setInterval(() => {
    const inVals  = ['0.98 GB/s','1.24 GB/s','1.56 GB/s','2.01 GB/s','1.37 GB/s'];
    const outVals = ['642 MB/s','842 MB/s','1.1 GB/s','754 MB/s','923 MB/s'];
    const el1 = $('#inboundStat');
    const el2 = $('#outboundStat');
    if (el1) el1.textContent = inVals[rand(0, inVals.length - 1)];
    if (el2) el2.textContent = outVals[rand(0, outVals.length - 1)];
    const blocked = $('#blockedStat');
    if (blocked) {
      const cur = parseInt(blocked.textContent.replace(/,/g,''));
      blocked.textContent = (cur + rand(0,3)).toLocaleString();
    }
  }, 3000);

  // Refresh traffic table rows every 5s (add new row at top)
  setInterval(() => {
    const tbody = $('#trafficTableBody');
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr');
    if (rows.length >= 20) rows[rows.length - 1].remove();
    const newRow = document.createElement('tbody');
    newRow.innerHTML = generateRow(rand(1, 9999));
    const tr = newRow.querySelector('tr');
    tr.style.animation = 'fadeSlide 0.3s ease';
    tr.style.background = 'rgba(21,101,192,0.06)';
    setTimeout(() => tr.style.background = '', 600);
    tbody.prepend(tr);
  }, 5000);

  // Pulse CPU gauge
  let cpuTick = 67;
  setInterval(() => {
    cpuTick = Math.min(100, Math.max(10, cpuTick + rand(-4, 6)));
    const el = $('#cpuVal');
    if (el) { el.textContent = cpuTick + '%'; drawGauge('cpuGauge', cpuTick, '#1565c0'); }
    const hc = healthCharts['cpuHistory'];
    if (hc) { hc.data.datasets[0].data.shift(); hc.data.datasets[0].data.push(cpuTick); hc.update('none'); }
  }, 2500);

  let memTick = 82;
  setInterval(() => {
    memTick = Math.min(98, Math.max(60, memTick + rand(-2, 3)));
    const el = $('#memVal');
    if (el) { el.textContent = memTick + '%'; drawGauge('memGauge', memTick, '#e65100'); }
    const hc = healthCharts['memHistory'];
    if (hc) { hc.data.datasets[0].data.shift(); hc.data.datasets[0].data.push(memTick); hc.update('none'); }
  }, 3000);

  // Bump traffic chart occasionally
  setInterval(() => {
    if (!window._trafficChart) return;
    const ds = window._trafficChart.data.datasets;
    ds[0].data = ds[0].data.map(v => Math.max(50, v + rand(-10, 15)));
    ds[1].data = ds[1].data.map(v => Math.max(5, v + rand(-3, 5)));
    window._trafficChart.update('none');
  }, 4000);
}

// ============================================================
// REAL DATA — OVERVIEW
// ============================================================
let prevNetSent = 0, prevNetRecv = 0;

async function loadRealOverview() {
  const data = await apiFetch('/overview');
  if (!data) return;

  // Animate stat counters with real values
  animateValue($('.stat-card:nth-child(1) .stat-value'), data.bytes_recv);
  animateValue($('.stat-card:nth-child(2) .stat-value'), data.active_connections);
  animateValue($('.stat-card:nth-child(3) .stat-value'), data.threats_total);
  animateValue($('.stat-card:nth-child(4) .stat-value'), data.threats_critical);

  prevNetSent = data.bytes_sent;
  prevNetRecv = data.bytes_recv;
}

function animateValue(el, target) {
  if (!el) return;
  const duration = 1200;
  const start = performance.now();
  const raf = (ts) => {
    const p = Math.min((ts - start) / duration, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(ease * target).toLocaleString();
    if (p < 1) requestAnimationFrame(raf);
  };
  requestAnimationFrame(raf);
}

// ============================================================
// REAL DATA — RECENT THREATS TABLE
// ============================================================
async function loadRealRecentThreats() {
  const data = await apiFetch('/threats');
  const tbody = $('#recentEventsTable');
  if (!tbody) return;

  if (!data || data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px">
      <i class="fas fa-shield-check" style="color:var(--green);margin-right:8px"></i>No threats detected yet — monitoring active</td></tr>`;
    return;
  }

  tbody.innerHTML = data.slice(0, 10).map(t => `
    <tr>
      <td>${t.time}</td>
      <td style="color:var(--text-primary);font-weight:500">${t.type}</td>
      <td><span class="ip-tag">${t.source_ip}</span></td>
      <td><span class="pill ${t.severity}">${t.severity.toUpperCase()}</span></td>
      <td><span class="pill flagged">DETECTED</span></td>
    </tr>
  `).join('');
}

// ============================================================
// REAL DATA — LIVE MONITORING SECTION
// ============================================================
async function loadRealConnections() {
  const data = await apiFetch('/connections');
  const tbody = $('#trafficTableBody');
  if (!tbody || !data) return;

  if (data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:20px">No active connections</td></tr>`;
    return;
  }

  tbody.innerHTML = data.slice(0, 20).map((c, i) => {
    const statusClass = c.status === 'ESTABLISHED' ? 'allowed' : 'scanning';
    return `<tr>
      <td style="color:var(--text-muted);font-size:0.72rem">${i + 1}</td>
      <td style="font-size:0.75rem;color:var(--text-muted)">${new Date().toLocaleTimeString('en-US',{hour12:false})}</td>
      <td><span class="ip-tag">${c.local_ip}</span></td>
      <td><span class="ip-tag">${c.remote_ip}</span></td>
      <td><span class="protocol-tag">${c.protocol}</span></td>
      <td style="color:var(--text-secondary)">${c.remote_port}</td>
      <td style="color:var(--text-secondary);font-size:0.75rem">${c.process || '—'}</td>
      <td><span class="pill ${statusClass}">${c.status}</span></td>
      <td>
        <button class="action-btn" title="Inspect"><i class="fas fa-magnifying-glass"></i></button>
      </td>
    </tr>`;
  }).join('');
}

async function loadRealMiniStats() {
  const data = await apiFetch('/stats');
  if (!data) return;

  const el1 = $('#inboundStat');
  const el2 = $('#outboundStat');
  const el3 = $('#blockedStat');

  // Calculate per-second rate from history
  const hist = await apiFetch('/stats/history');
  if (hist && hist.length >= 2) {
    const last = hist[hist.length - 1];
    const prev = hist[hist.length - 2];
    const recvRate = last.bytes_recv - prev.bytes_recv;
    const sentRate = last.bytes_sent - prev.bytes_sent;
    if (el1) el1.textContent = fmtBytes(Math.max(0, recvRate));
    if (el2) el2.textContent = fmtBytes(Math.max(0, sentRate));
  }

  const threats = await apiFetch('/threats/summary');
  if (threats && el3) {
    el3.textContent = (threats.total || 0).toLocaleString();
  }
}

async function loadRealLiveChart() {
  const hist = await apiFetch('/stats/history');
  if (!hist || !liveChart) return;

  const recv = hist.map(h => Math.round(h.bytes_recv / 1024)); // KB/s
  const sent = hist.map(h => Math.round(h.bytes_sent / 1024));

  // Pad to 30 points
  while (recv.length < 30) recv.unshift(0);
  while (sent.length < 30) sent.unshift(0);

  liveChart.data.datasets[0].data = recv.slice(-30);
  liveChart.data.datasets[1].data = sent.slice(-30);
  liveChart.update('none');
}

// ============================================================
// REAL DATA — SYSTEM HEALTH SECTION
// ============================================================
async function loadRealHealth() {
  const data = await apiFetch('/stats');
  if (!data) return;

  // CPU
  const cpuPct = Math.round(data.cpu.percent);
  const cpuEl = $('#cpuVal');
  if (cpuEl) { cpuEl.textContent = cpuPct + '%'; drawGauge('cpuGauge', cpuPct, '#1565c0'); }
  const cpuLbl = cpuEl?.closest('.card-body')?.querySelector('.hg-lbl');
  if (cpuLbl) cpuLbl.textContent = `${data.cpu.cores} cores · ${Math.round(data.cpu.freq_mhz)} MHz`;

  // Memory
  const memPct = Math.round(data.memory.percent);
  const memEl = $('#memVal');
  if (memEl) { memEl.textContent = memPct + '%'; drawGauge('memGauge', memPct, '#e65100'); }
  const memLbl = memEl?.closest('.card-body')?.querySelector('.hg-lbl');
  if (memLbl) memLbl.textContent = `${data.memory.used_gb} / ${data.memory.total_gb} GB`;

  // Disk
  const diskPct = Math.round(data.disk.percent);
  const diskEl = $('#diskVal');
  if (diskEl) { diskEl.textContent = diskPct + '%'; drawGauge('diskGauge', diskPct, '#2e7d32'); }
  const diskLbl = diskEl?.closest('.card-body')?.querySelector('.hg-lbl');
  if (diskLbl) diskLbl.textContent = `${data.disk.used_gb} / ${data.disk.total_gb} GB`;

  // Network load (estimate based on bytes/s)
  const hist = await apiFetch('/stats/history');
  if (hist && hist.length >= 2) {
    const last = hist[hist.length - 1];
    const prev = hist[hist.length - 2];
    const totalRate = (last.bytes_recv - prev.bytes_recv + last.bytes_sent - prev.bytes_sent);
    const netPct = Math.min(100, Math.round(totalRate / 1250000 * 100)); // estimate vs 100Mbps
    const netEl = $('#netVal');
    if (netEl) { netEl.textContent = netPct + '%'; drawGauge('netGauge', netPct, '#0288d1'); }
    const netLbl = netEl?.closest('.card-body')?.querySelector('.hg-lbl');
    if (netLbl) netLbl.textContent = fmtBytes(totalRate) + ' total';

    // Update history charts
    const hc = healthCharts['cpuHistory'];
    if (hc) { hc.data.datasets[0].data.shift(); hc.data.datasets[0].data.push(cpuPct); hc.update('none'); }
    const hm = healthCharts['memHistory'];
    if (hm) { hm.data.datasets[0].data.shift(); hm.data.datasets[0].data.push(memPct); hm.update('none'); }
    const hn = healthCharts['netHistory'];
    if (hn) { hn.data.datasets[0].data.shift(); hn.data.datasets[0].data.push(netPct); hn.update('none'); }
    const hd = healthCharts['diskHistory'];
    if (hd) { hd.data.datasets[0].data.shift(); hd.data.datasets[0].data.push(diskPct); hd.update('none'); }
  }
}

// ============================================================
// REAL DATA — THREATS SECTION
// ============================================================
async function loadRealThreatFeed() {
  const data = await apiFetch('/threats');
  const feed = $('#threatFeed');
  if (!feed) return;

  if (!data || data.length === 0) {
    feed.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text-muted)">
      <i class="fas fa-shield-check" style="font-size:2rem;color:var(--green);display:block;margin-bottom:12px"></i>
      No threats detected — system is clean
    </div>`;
    return;
  }

  const iconMap = { critical: 'fa-skull-crossbones', high: 'fa-burst', medium: 'fa-triangle-exclamation', low: 'fa-magnifying-glass' };
  const clsMap  = { critical: 'red', high: 'orange', medium: 'yellow', low: 'blue' };

  feed.innerHTML = data.slice(0, 20).map(t => `
    <div class="threat-item">
      <div class="ti-icon ${clsMap[t.severity] || 'blue'}">
        <i class="fas ${iconMap[t.severity] || 'fa-circle-info'}"></i>
      </div>
      <div class="ti-main">
        <div class="ti-title">${t.type}</div>
        <div class="ti-sub">${t.description} ${t.source_ip ? '· src: ' + t.source_ip : ''}</div>
      </div>
      <span class="pill ${t.severity}">${t.severity.toUpperCase()}</span>
      <span class="ti-time">${t.time}</span>
    </div>
  `).join('');
}

async function loadRealThreatSummary() {
  const data = await apiFetch('/threats/summary');
  if (!data) return;

  // Update severity chart if it exists
  if (window._severityChart) {
    window._severityChart.data.datasets[0].data = [
      data.critical || 0,
      data.high     || 0,
      data.medium   || 0,
      data.low      || 0,
    ];
    window._severityChart.update();
  }

  // Update risk gauge score
  const total = data.total || 0;
  const score = Math.min(100, data.critical * 15 + data.high * 8 + data.medium * 3 + data.low);
  const gaugeEl = $('#gaugeScore');
  if (gaugeEl) {
    gaugeEl.textContent = score;
    const label = gaugeEl.nextElementSibling;
    if (label) {
      if (score >= 70) { label.textContent = 'HIGH RISK'; gaugeEl.style.color = 'var(--red)'; }
      else if (score >= 40) { label.textContent = 'MEDIUM RISK'; gaugeEl.style.color = 'var(--orange)'; }
      else { label.textContent = 'LOW RISK'; gaugeEl.style.color = 'var(--green)'; }
    }
  }
}

// ============================================================
// REAL DATA — ALERTS SECTION
// ============================================================
async function loadRealAlerts() {
  const data = await apiFetch('/threats');
  if (!data || data.length === 0) {
    renderAlerts('all'); // fall back to demo
    return;
  }

  const list = $('#alertsList');
  if (!list) return;

  const sevToType = { critical: 'critical', high: 'warning', medium: 'warning', low: 'info' };
  const iconMap   = { critical: 'fa-skull', high: 'fa-burst', medium: 'fa-triangle-exclamation', low: 'fa-circle-info' };
  const colorMap  = { critical: 'red', warning: 'orange', info: 'blue' };
  const bgMap     = { critical: 'rgba(198,40,40,0.08)', warning: 'rgba(230,81,0,0.08)', info: 'rgba(21,101,192,0.08)' };

  list.innerHTML = data.slice(0, 20).map(t => {
    const type = sevToType[t.severity] || 'info';
    return `<div class="alert-card unread ${type}">
      <div class="alert-icon" style="background:${bgMap[type]};color:var(--${colorMap[type]})">
        <i class="fas ${iconMap[t.severity] || 'fa-circle-info'}"></i>
      </div>
      <div class="alert-body">
        <div class="alert-title">${t.type}</div>
        <div class="alert-desc">${t.description}</div>
        <div class="alert-meta">
          <span><i class="fas fa-crosshairs" style="margin-right:4px"></i>src: ${t.source_ip}</span>
          ${t.port ? `<span>port: ${t.port}</span>` : ''}
        </div>
      </div>
      <div class="alert-time">${t.time}</div>
    </div>`;
  }).join('');
}

// ============================================================
// REAL DATA — POLLING ENGINE
// ============================================================
function startRealDataPolling() {
  // Poll overview every 4s
  setInterval(async () => {
    const data = await apiFetch('/overview');
    if (!data) { updateBackendStatus(false); return; }
    backendOnline = true;
    updateBackendStatus(true);

    animateValue($('.stat-card:nth-child(1) .stat-value'), data.bytes_recv);
    animateValue($('.stat-card:nth-child(2) .stat-value'), data.active_connections);
    animateValue($('.stat-card:nth-child(3) .stat-value'), data.threats_total);
    animateValue($('.stat-card:nth-child(4) .stat-value'), data.threats_critical);
  }, 4000);

  // Poll live monitoring every 3s
  setInterval(async () => {
    const active = $('#section-monitoring.active');
    if (active) {
      await loadRealConnections();
      await loadRealMiniStats();
      await loadRealLiveChart();
    }
  }, 3000);

  // Poll system health every 3s
  setInterval(async () => {
    const active = $('#section-health.active');
    if (active) await loadRealHealth();
  }, 3000);

  // Poll threats every 5s
  setInterval(async () => {
    const active = $('#section-threats.active');
    if (active) {
      await loadRealThreatFeed();
      await loadRealThreatSummary();
    }
    // Always update recent events on overview
    await loadRealRecentThreats();
  }, 5000);

  // Poll alerts every 5s
  setInterval(async () => {
    const active = $('#section-alerts.active');
    if (active) await loadRealAlerts();
  }, 5000);

  // Keep live chart ticking even without section focus
  setInterval(async () => {
    await loadRealLiveChart();
  }, 2000);
}

// end of file

// ============================================================
// REAL DATA — OVERVIEW STAT CARDS
// ============================================================
async function refreshOverviewStats() {
  const data = await apiFetch('/overview');
  if (!data) return;

  // Card 1: Total bytes received (real network traffic)
  const c1 = $('.stat-card:nth-child(1) .stat-value');
  const c1lbl = $('.stat-card:nth-child(1) .stat-label');
  if (c1) { animateValue(c1, data.bytes_recv); }
  if (c1lbl) c1lbl.textContent = 'Bytes Received';

  // Card 2: Active connections
  const c2 = $('.stat-card:nth-child(2) .stat-value');
  const c2lbl = $('.stat-card:nth-child(2) .stat-label');
  if (c2) animateValue(c2, data.active_connections);
  if (c2lbl) c2lbl.textContent = 'Active Connections';

  // Card 3: Threats detected
  const c3 = $('.stat-card:nth-child(3) .stat-value');
  const c3lbl = $('.stat-card:nth-child(3) .stat-label');
  if (c3) animateValue(c3, data.threats_total);
  if (c3lbl) c3lbl.textContent = 'Threats Detected';

  // Card 4: Critical threats
  const c4 = $('.stat-card:nth-child(4) .stat-value');
  const c4lbl = $('.stat-card:nth-child(4) .stat-label');
  if (c4) animateValue(c4, data.threats_critical);
  if (c4lbl) c4lbl.textContent = 'Critical Alerts';
}

// ============================================================
// REAL DATA — GEO / CONNECTIONS from real IP data
// ============================================================
async function loadRealGeoConnections() {
  const conns = await apiFetch('/connections');
  const el = $('#geoList');
  if (!el) return;

  if (!conns || conns.length === 0) {
    buildGeoList(); // fallback
    return;
  }

  // Count unique remote IPs and group by first octet (rough geo)
  const ipCount = {};
  conns.forEach(c => {
    if (c.remote_ip) ipCount[c.remote_ip] = (ipCount[c.remote_ip] || 0) + 1;
  });

  // Get top 7 IPs
  const top = Object.entries(ipCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7);

  if (top.length === 0) { buildGeoList(); return; }

  const maxCount = top[0][1];
  el.innerHTML = top.map(([ip, count]) => {
    const pct = Math.round((count / maxCount) * 100);
    const process = conns.find(c => c.remote_ip === ip)?.process || '';
    return `
      <div class="geo-item">
        <div class="geo-flag" style="font-family:monospace;font-size:0.75rem;color:var(--blue);width:auto;min-width:28px">${ip.split('.')[0]}.*</div>
        <div class="geo-bar-wrap">
          <div class="geo-label">
            <span class="geo-country">${ip} ${process ? '('+process+')' : ''}</span>
            <span class="geo-count">${count} conn${count>1?'s':''}</span>
          </div>
          <div class="geo-bar"><div class="geo-fill" style="width:0%" data-w="${pct}"></div></div>
        </div>
      </div>`;
  }).join('');

  setTimeout(() => {
    $$('.geo-fill').forEach(e => e.style.width = e.dataset.w + '%');
  }, 200);
}

// ============================================================
// REAL DATA — TRAFFIC CHART (from real history)
// ============================================================
async function loadRealTrafficChart() {
  const hist = await apiFetch('/stats/history');
  if (!hist || hist.length < 2 || !window._trafficChart) return;

  // Build per-second KB values from cumulative bytes
  const labels = hist.map((_, i) => {
    const d = new Date(Date.now() - (hist.length - i) * 2000);
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  });

  const recv = hist.map((h, i) => {
    if (i === 0) return 0;
    return Math.max(0, Math.round((h.bytes_recv - hist[i-1].bytes_recv) / 1024));
  });
  const sent = hist.map((h, i) => {
    if (i === 0) return 0;
    return Math.max(0, Math.round((h.bytes_sent - hist[i-1].bytes_sent) / 1024));
  });

  window._trafficChart.data.labels = labels;
  window._trafficChart.data.datasets[0].data = recv;
  window._trafficChart.data.datasets[0].label = 'Inbound (KB/s)';
  window._trafficChart.data.datasets[1].data = sent;
  window._trafficChart.data.datasets[1].label = 'Outbound (KB/s)';
  window._trafficChart.update();
}

// ============================================================
// REAL DATA — PROCESS LOGS (System Health logs)
// ============================================================
async function loadRealProcessLogs() {
  const procs = await apiFetch('/processes');
  const logEl = $('#systemLogs');
  if (!logEl || !procs) { buildSystemLogs(); return; }

  const now = new Date().toLocaleTimeString('en-US', { hour12: false });
  const lines = procs.slice(0, 15).map(p => {
    const cpu = (p.cpu_percent || 0).toFixed(1);
    const mem = (p.memory_percent || 0).toFixed(1);
    const level = cpu > 50 ? 'warn' : cpu > 80 ? 'error' : 'info';
    const label = { info: 'INFO', warn: 'WARN', error: 'ERROR' }[level];
    return `<div class="log-line">
      <span class="log-ts">${now}</span>
      <span class="log-level ${level}">[${label}]</span>
      <span class="log-msg">PID ${p.pid || '?'} · <b style="color:#e2e8f0">${p.name || 'unknown'}</b> · CPU: ${cpu}% · MEM: ${mem}%</span>
    </div>`;
  });
  logEl.innerHTML = lines.join('');
  logEl.scrollTop = logEl.scrollHeight;
}

// ============================================================
// POLLING — refreshes real data every few seconds
// ============================================================
function startRealDataPolling() {
  // Overview stats every 4s
  setInterval(async () => {
    const ok = await checkBackend();
    if (ok) await refreshOverviewStats();
  }, 4000);

  // Live chart every 2s
  setInterval(async () => {
    if (backendOnline) await loadRealLiveChart();
  }, 2000);

  // Monitoring section every 3s
  setInterval(async () => {
    if (!backendOnline) return;
    if ($('#section-monitoring.active')) {
      await loadRealConnections();
      await loadRealMiniStats();
      await loadRealLiveChart();
    }
  }, 3000);

  // Health section every 3s
  setInterval(async () => {
    if (!backendOnline) return;
    if ($('#section-health.active')) {
      await loadRealHealth();
      await loadRealProcessLogs();
    }
  }, 3000);

  // Threats + alerts every 5s
  setInterval(async () => {
    if (!backendOnline) return;
    await loadRealRecentThreats();
    if ($('#section-threats.active')) {
      await loadRealThreatFeed();
      await loadRealThreatSummary();
    }
    if ($('#section-alerts.active')) await loadRealAlerts();
  }, 5000);

  // Traffic chart + geo every 6s
  setInterval(async () => {
    if (!backendOnline) return;
    await loadRealTrafficChart();
    await loadRealGeoConnections();
  }, 6000);
}
