#!/usr/bin/env python3
"""
SIEM Web Dashboard - Flask backend
Run: python3 app.py  then open http://localhost:5000
"""

from flask import Flask, jsonify, request
from siem_monitor import generate_mock_logs, run_detection
from datetime import datetime

app = Flask(__name__)

# Generate data once on startup
logs = generate_mock_logs(n=500)
alerts = run_detection(logs)

# Investigation state store (in-memory)
investigation_state = {}  # alert_id -> {status, notes, analyst}

def alert_to_dict(a):
    return {
        "id": a.alert_id,
        "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "category": a.category,
        "severity": a.severity,
        "source_ip": a.source_ip,
        "username": a.username,
        "description": a.description,
        "evidence": a.evidence,
        "mitre_tactic": a.mitre_tactic,
        "recommended_action": a.recommended_action,
        "inv_status": investigation_state.get(a.alert_id, {}).get("status", "NEW"),
        "inv_notes": investigation_state.get(a.alert_id, {}).get("notes", ""),
        "inv_analyst": investigation_state.get(a.alert_id, {}).get("analyst", ""),
    }

@app.route("/")
def index():
    return HTML_DASHBOARD

@app.route("/api/alerts")
def get_alerts():
    severity_filter = request.args.get("severity", "ALL")
    category_filter = request.args.get("category", "ALL")
    status_filter = request.args.get("inv_status", "ALL")

    result = []
    for a in alerts:
        d = alert_to_dict(a)
        if severity_filter != "ALL" and d["severity"] != severity_filter:
            continue
        if category_filter != "ALL" and d["category"] != category_filter:
            continue
        if status_filter != "ALL" and d["inv_status"] != status_filter:
            continue
        result.append(d)
    return jsonify(result)

@app.route("/api/alerts/<alert_id>", methods=["GET"])
def get_alert(alert_id):
    for a in alerts:
        if a.alert_id == alert_id:
            return jsonify(alert_to_dict(a))
    return jsonify({"error": "Not found"}), 404

@app.route("/api/alerts/<alert_id>/investigate", methods=["POST"])
def update_investigation(alert_id):
    data = request.json
    investigation_state[alert_id] = {
        "status": data.get("status", "NEW"),
        "notes": data.get("notes", ""),
        "analyst": data.get("analyst", ""),
        "updated_at": datetime.now().isoformat(),
    }
    return jsonify({"ok": True})

@app.route("/api/stats")
def get_stats():
    from collections import defaultdict
    sev_counts = defaultdict(int)
    cat_counts = defaultdict(int)
    inv_counts = defaultdict(int)
    for a in alerts:
        sev_counts[a.severity] += 1
        cat_counts[a.category] += 1
        inv_counts[investigation_state.get(a.alert_id, {}).get("status", "NEW")] += 1
    return jsonify({
        "total_alerts": len(alerts),
        "total_logs": len(logs),
        "by_severity": dict(sev_counts),
        "by_category": dict(cat_counts),
        "by_inv_status": dict(inv_counts),
    })

@app.route("/api/rescan", methods=["POST"])
def rescan():
    global logs, alerts, investigation_state
    logs = generate_mock_logs(n=500)
    alerts = run_detection(logs)
    investigation_state = {}
    return jsonify({"ok": True, "alert_count": len(alerts)})

# ─────────────────────────────────────────────
# EMBEDDED HTML DASHBOARD
# ─────────────────────────────────────────────

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SIEM — Threat Monitor</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #080b10;
    --surface:   #0d1117;
    --border:    #1c2333;
    --border2:   #21262d;
    --text:      #c9d1d9;
    --muted:     #484f58;
    --accent:    #00ff9d;
    --accent2:   #00bfff;
    --crit:      #ff4757;
    --high:      #ff6b35;
    --med:       #ffd700;
    --low:       #4fc3f7;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Syne', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,255,157,0.015) 2px,
      rgba(0,255,157,0.015) 4px
    );
    pointer-events: none;
    z-index: 1000;
  }

  /* ── HEADER ── */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 32px;
    border-bottom: 1px solid var(--border);
    background: rgba(13,17,23,0.95);
    position: sticky; top: 0; z-index: 100;
    backdrop-filter: blur(8px);
  }

  .logo {
    font-family: var(--sans);
    font-weight: 800;
    font-size: 20px;
    color: var(--accent);
    letter-spacing: -0.5px;
    display: flex; align-items: center; gap: 10px;
  }

  .logo-dot {
    width: 8px; height: 8px;
    background: var(--accent);
    border-radius: 50%;
    box-shadow: 0 0 12px var(--accent);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.8); }
  }

  .header-meta {
    display: flex; align-items: center; gap: 24px;
    font-size: 11px; color: var(--muted);
  }

  .live-badge {
    background: rgba(0,255,157,0.1);
    border: 1px solid rgba(0,255,157,0.3);
    color: var(--accent);
    padding: 3px 10px;
    border-radius: 3px;
    font-size: 10px;
    letter-spacing: 1px;
  }

  .rescan-btn {
    background: transparent;
    border: 1px solid var(--border2);
    color: var(--text);
    padding: 6px 14px;
    border-radius: 4px;
    cursor: pointer;
    font-family: var(--mono);
    font-size: 11px;
    transition: all 0.2s;
  }
  .rescan-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }

  /* ── LAYOUT ── */
  .container { padding: 24px 32px; }

  /* ── STAT CARDS ── */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 24px;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
    position: relative;
    overflow: hidden;
    animation: fadeUp 0.4s ease both;
  }

  .stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }
  .stat-card.crit::before { background: var(--crit); }
  .stat-card.high::before { background: var(--high); }
  .stat-card.med::before  { background: var(--med); }
  .stat-card.low::before  { background: var(--accent2); }
  .stat-card.total::before { background: var(--accent); }

  .stat-label { font-size: 10px; color: var(--muted); letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 8px; }
  .stat-value { font-family: var(--sans); font-size: 32px; font-weight: 800; line-height: 1; }
  .stat-card.crit .stat-value { color: var(--crit); }
  .stat-card.high .stat-value { color: var(--high); }
  .stat-card.med  .stat-value { color: var(--med); }
  .stat-card.low  .stat-value { color: var(--accent2); }
  .stat-card.total .stat-value { color: var(--accent); }
  .stat-sub { font-size: 10px; color: var(--muted); margin-top: 4px; }

  /* ── FILTERS ── */
  .filters {
    display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;
    align-items: center;
  }

  .filter-label { color: var(--muted); font-size: 11px; margin-right: 4px; }

  select {
    background: var(--surface);
    border: 1px solid var(--border2);
    color: var(--text);
    padding: 6px 10px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 11px;
    cursor: pointer;
    outline: none;
  }
  select:focus { border-color: var(--accent); }

  .filter-sep { width: 1px; height: 20px; background: var(--border); margin: 0 4px; }

  /* ── ALERT TABLE ── */
  .table-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }

  table { width: 100%; border-collapse: collapse; }

  thead th {
    padding: 10px 14px;
    text-align: left;
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    background: rgba(255,255,255,0.02);
    white-space: nowrap;
  }

  tbody tr {
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.15s;
    animation: fadeUp 0.3s ease both;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: rgba(0,255,157,0.04); }
  tbody tr.selected { background: rgba(0,255,157,0.08); border-left: 2px solid var(--accent); }

  td { padding: 10px 14px; vertical-align: middle; }

  .sev-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.5px;
  }
  .sev-CRITICAL { background: rgba(255,71,87,0.15);  color: var(--crit); border: 1px solid rgba(255,71,87,0.3); }
  .sev-HIGH     { background: rgba(255,107,53,0.15); color: var(--high); border: 1px solid rgba(255,107,53,0.3); }
  .sev-MEDIUM   { background: rgba(255,215,0,0.12);  color: var(--med);  border: 1px solid rgba(255,215,0,0.3); }
  .sev-LOW      { background: rgba(79,195,247,0.12); color: var(--low);  border: 1px solid rgba(79,195,247,0.3); }

  .inv-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
  }
  .inv-NEW        { color: #777; border: 1px solid #333; }
  .inv-CONFIRMED  { color: var(--crit); border: 1px solid rgba(255,71,87,0.4); }
  .inv-FALSE_POS  { color: var(--muted); border: 1px solid var(--border2); text-decoration: line-through; }
  .inv-ESCALATED  { color: var(--high); border: 1px solid rgba(255,107,53,0.4); }
  .inv-RESOLVED   { color: var(--accent); border: 1px solid rgba(0,255,157,0.3); }

  .cat-tag {
    font-size: 10px; color: var(--accent2);
    background: rgba(0,191,255,0.08);
    border: 1px solid rgba(0,191,255,0.2);
    padding: 2px 6px; border-radius: 2px;
  }

  .ip { color: var(--accent); font-size: 12px; }
  .ts { color: var(--muted); font-size: 11px; }
  .desc-cell { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #8b949e; font-size: 12px; }

  /* ── DETAIL PANEL ── */
  .detail-panel {
    position: fixed;
    top: 0; right: -520px;
    width: 500px; height: 100vh;
    background: var(--surface);
    border-left: 1px solid var(--border);
    z-index: 200;
    transition: right 0.3s cubic-bezier(0.4,0,0.2,1);
    display: flex; flex-direction: column;
    overflow: hidden;
  }
  .detail-panel.open { right: 0; }

  .detail-header {
    padding: 20px 24px 16px;
    border-bottom: 1px solid var(--border);
    display: flex; justify-content: space-between; align-items: flex-start;
  }

  .detail-title {
    font-family: var(--sans);
    font-size: 15px;
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 6px;
  }

  .close-btn {
    background: none; border: none;
    color: var(--muted); cursor: pointer;
    font-size: 20px; line-height: 1;
    padding: 0 4px;
    transition: color 0.2s;
  }
  .close-btn:hover { color: var(--text); }

  .detail-body {
    flex: 1; overflow-y: auto;
    padding: 20px 24px;
    scrollbar-width: thin;
    scrollbar-color: var(--border2) transparent;
  }

  .detail-section { margin-bottom: 20px; }
  .detail-section-title {
    font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
    color: var(--muted); margin-bottom: 10px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 6px;
  }

  .detail-grid {
    display: grid;
    grid-template-columns: 110px 1fr;
    gap: 8px 12px;
  }
  .detail-key { color: var(--muted); font-size: 11px; }
  .detail-val { color: var(--text); font-size: 12px; word-break: break-all; }

  .evidence-item {
    background: rgba(0,0,0,0.3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 12px;
    margin-bottom: 6px;
    font-size: 11px;
    color: #8b949e;
    border-left: 2px solid var(--border2);
  }

  .mitre-pill {
    display: inline-block;
    background: rgba(0,191,255,0.08);
    border: 1px solid rgba(0,191,255,0.25);
    color: var(--accent2);
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
  }

  .action-box {
    background: rgba(0,255,157,0.05);
    border: 1px solid rgba(0,255,157,0.2);
    border-radius: 4px;
    padding: 10px 12px;
    font-size: 12px;
    color: var(--accent);
    line-height: 1.5;
  }

  /* Investigation form */
  .inv-form { display: flex; flex-direction: column; gap: 10px; }

  .inv-form label { font-size: 10px; color: var(--muted); letter-spacing: 1px; text-transform: uppercase; }

  .inv-form select, .inv-form input, .inv-form textarea {
    width: 100%;
    background: rgba(0,0,0,0.3);
    border: 1px solid var(--border2);
    color: var(--text);
    padding: 8px 10px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 12px;
    outline: none;
    resize: vertical;
    transition: border-color 0.2s;
  }
  .inv-form select:focus,
  .inv-form input:focus,
  .inv-form textarea:focus { border-color: var(--accent); }

  .save-btn {
    background: rgba(0,255,157,0.1);
    border: 1px solid rgba(0,255,157,0.4);
    color: var(--accent);
    padding: 9px 18px;
    border-radius: 4px;
    cursor: pointer;
    font-family: var(--mono);
    font-size: 12px;
    transition: all 0.2s;
    align-self: flex-end;
  }
  .save-btn:hover { background: rgba(0,255,157,0.2); }
  .save-btn:active { transform: scale(0.97); }

  .saved-flash {
    color: var(--accent);
    font-size: 11px;
    opacity: 0;
    transition: opacity 0.3s;
    align-self: center;
  }
  .saved-flash.show { opacity: 1; }

  /* ── EMPTY STATE ── */
  .empty {
    text-align: center;
    padding: 60px 20px;
    color: var(--muted);
    font-size: 13px;
  }
  .empty-icon { font-size: 36px; margin-bottom: 12px; opacity: 0.4; }

  /* ── ANIMATIONS ── */
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  /* ── SCROLLBAR ── */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

  /* Loading overlay */
  .loading {
    position: fixed; inset: 0;
    background: var(--bg);
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    z-index: 9999;
    transition: opacity 0.4s;
  }
  .loading.hidden { opacity: 0; pointer-events: none; }
  .loading-text {
    font-family: var(--sans);
    font-size: 28px;
    font-weight: 800;
    color: var(--accent);
    margin-bottom: 12px;
  }
  .loading-sub { font-size: 12px; color: var(--muted); }
  .loading-bar {
    width: 200px; height: 2px;
    background: var(--border);
    margin-top: 20px;
    border-radius: 1px;
    overflow: hidden;
  }
  .loading-bar-fill {
    height: 100%; width: 0;
    background: var(--accent);
    animation: load 1s ease forwards;
  }
  @keyframes load { to { width: 100%; } }
</style>
</head>
<body>

<!-- Loading screen -->
<div class="loading" id="loading">
  <div class="loading-text">SIEM</div>
  <div class="loading-sub">Initialising threat monitor...</div>
  <div class="loading-bar"><div class="loading-bar-fill"></div></div>
</div>

<!-- Header -->
<header>
  <div class="logo">
    <div class="logo-dot"></div>
    THREAT MONITOR
  </div>
  <div class="header-meta">
    <span class="live-badge">● LIVE</span>
    <span id="header-time"></span>
    <span id="header-logcount" style="color:var(--muted)"></span>
    <button class="rescan-btn" onclick="rescan()">⟳ RESCAN</button>
  </div>
</header>

<!-- Main -->
<div class="container">

  <!-- Stat cards -->
  <div class="stats-row" id="stats-row">
    <div class="stat-card total"><div class="stat-label">Total Alerts</div><div class="stat-value" id="s-total">—</div><div class="stat-sub">Last 24h</div></div>
    <div class="stat-card crit"><div class="stat-label">Critical</div><div class="stat-value" id="s-crit">—</div><div class="stat-sub">Immediate action</div></div>
    <div class="stat-card high"><div class="stat-label">High</div><div class="stat-value" id="s-high">—</div><div class="stat-sub">Investigate today</div></div>
    <div class="stat-card med"><div class="stat-label">Medium</div><div class="stat-value" id="s-med">—</div><div class="stat-sub">Review this week</div></div>
    <div class="stat-card low"><div class="stat-label">New / Unreviewed</div><div class="stat-value" id="s-new">—</div><div class="stat-sub">Awaiting triage</div></div>
  </div>

  <!-- Filters -->
  <div class="filters">
    <span class="filter-label">FILTER:</span>
    <select id="f-severity" onchange="loadAlerts()">
      <option value="ALL">All Severities</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
    <select id="f-category" onchange="loadAlerts()">
      <option value="ALL">All Categories</option>
      <option value="BRUTE_FORCE">Brute Force</option>
      <option value="PORT_SCAN">Port Scan</option>
      <option value="OFF_HOURS_ACCESS">Off-Hours Access</option>
      <option value="SENSITIVE_FILE_ACCESS">Sensitive File Access</option>
    </select>
    <div class="filter-sep"></div>
    <select id="f-status" onchange="loadAlerts()">
      <option value="ALL">All Statuses</option>
      <option value="NEW">New</option>
      <option value="CONFIRMED">Confirmed</option>
      <option value="ESCALATED">Escalated</option>
      <option value="FALSE_POS">False Positive</option>
      <option value="RESOLVED">Resolved</option>
    </select>
    <span id="result-count" style="color:var(--muted);font-size:11px;margin-left:8px;"></span>
  </div>

  <!-- Table -->
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Category</th>
          <th>Source IP</th>
          <th>User</th>
          <th>Description</th>
          <th>Timestamp</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="alert-tbody"></tbody>
    </table>
    <div class="empty" id="empty-state" style="display:none">
      <div class="empty-icon">🛡</div>
      No alerts match your filters.
    </div>
  </div>
</div>

<!-- Detail panel -->
<div class="detail-panel" id="detail-panel">
  <div class="detail-header">
    <div>
      <div class="detail-title" id="dp-title">Alert Detail</div>
      <div id="dp-badges" style="display:flex;gap:6px;flex-wrap:wrap;"></div>
    </div>
    <button class="close-btn" onclick="closeDetail()">✕</button>
  </div>
  <div class="detail-body">
    <div class="detail-section">
      <div class="detail-section-title">Alert Info</div>
      <div class="detail-grid" id="dp-grid"></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">MITRE ATT&CK</div>
      <div id="dp-mitre"></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Evidence</div>
      <div id="dp-evidence"></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Recommended Action</div>
      <div class="action-box" id="dp-action"></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Investigation</div>
      <div class="inv-form">
        <div>
          <label>Analyst</label>
          <input type="text" id="inv-analyst" placeholder="your name" />
        </div>
        <div>
          <label>Status</label>
          <select id="inv-status">
            <option value="NEW">New — not yet reviewed</option>
            <option value="CONFIRMED">Confirmed — real threat</option>
            <option value="ESCALATED">Escalated — needs senior review</option>
            <option value="FALSE_POS">False Positive — benign</option>
            <option value="RESOLVED">Resolved — action taken</option>
          </select>
        </div>
        <div>
          <label>Notes</label>
          <textarea id="inv-notes" rows="4" placeholder="Document your findings, actions taken, IOCs observed..."></textarea>
        </div>
        <div style="display:flex;gap:10px;align-items:center;">
          <button class="save-btn" onclick="saveInvestigation()">SAVE</button>
          <span class="saved-flash" id="saved-flash">✓ Saved</span>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let allAlerts = [];
let currentAlertId = null;

// ── Clock ──
function updateClock() {
  document.getElementById('header-time').textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// ── Load Stats ──
async function loadStats() {
  const res = await fetch('/api/stats');
  const s = await res.json();
  document.getElementById('s-total').textContent = s.total_alerts;
  document.getElementById('s-crit').textContent  = s.by_severity.CRITICAL || 0;
  document.getElementById('s-high').textContent  = s.by_severity.HIGH || 0;
  document.getElementById('s-med').textContent   = s.by_severity.MEDIUM || 0;
  document.getElementById('s-new').textContent   = s.by_inv_status.NEW || s.total_alerts;
  document.getElementById('header-logcount').textContent = `${s.total_logs.toLocaleString()} logs analysed`;
}

// ── Load Alerts ──
async function loadAlerts() {
  const sev = document.getElementById('f-severity').value;
  const cat = document.getElementById('f-category').value;
  const sta = document.getElementById('f-status').value;
  const params = new URLSearchParams({ severity: sev, category: cat, inv_status: sta });
  const res = await fetch('/api/alerts?' + params);
  allAlerts = await res.json();

  const tbody = document.getElementById('alert-tbody');
  const empty = document.getElementById('empty-state');
  tbody.innerHTML = '';

  document.getElementById('result-count').textContent =
    allAlerts.length > 0 ? `${allAlerts.length} alert${allAlerts.length !== 1 ? 's' : ''}` : '';

  if (allAlerts.length === 0) {
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  allAlerts.forEach((a, i) => {
    const tr = document.createElement('tr');
    tr.style.animationDelay = (i * 0.03) + 's';
    if (a.id === currentAlertId) tr.classList.add('selected');
    tr.innerHTML = `
      <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
      <td><span class="cat-tag">${a.category.replace(/_/g,' ')}</span></td>
      <td class="ip">${a.source_ip}</td>
      <td style="color:#8b949e">${a.username || '—'}</td>
      <td class="desc-cell" title="${a.description}">${a.description}</td>
      <td class="ts">${a.timestamp}</td>
      <td><span class="inv-badge inv-${a.inv_status}">${a.inv_status.replace('_',' ')}</span></td>
    `;
    tr.onclick = () => openDetail(a.id);
    tbody.appendChild(tr);
  });
}

// ── Detail panel ──
async function openDetail(id) {
  currentAlertId = id;
  // highlight row
  document.querySelectorAll('tbody tr').forEach(r => r.classList.remove('selected'));
  event && event.currentTarget && event.currentTarget.classList.add('selected');

  const res = await fetch('/api/alerts/' + id);
  const a = await res.json();

  document.getElementById('dp-title').textContent = a.category.replace(/_/g,' ');
  document.getElementById('dp-badges').innerHTML = `
    <span class="sev-badge sev-${a.severity}">${a.severity}</span>
    <span class="inv-badge inv-${a.inv_status}">${a.inv_status.replace('_',' ')}</span>
  `;

  document.getElementById('dp-grid').innerHTML = `
    <span class="detail-key">Alert ID</span><span class="detail-val" style="color:var(--accent)">${a.id}</span>
    <span class="detail-key">Timestamp</span><span class="detail-val">${a.timestamp}</span>
    <span class="detail-key">Source IP</span><span class="detail-val" style="color:var(--accent)">${a.source_ip}</span>
    <span class="detail-key">Username</span><span class="detail-val">${a.username || '—'}</span>
    <span class="detail-key">Description</span><span class="detail-val">${a.description}</span>
  `;

  document.getElementById('dp-mitre').innerHTML = `<span class="mitre-pill">${a.mitre_tactic}</span>`;
  document.getElementById('dp-action').textContent = a.recommended_action;

  const evDiv = document.getElementById('dp-evidence');
  evDiv.innerHTML = '';
  if (a.evidence && a.evidence.length) {
    a.evidence.forEach(e => {
      const d = document.createElement('div');
      d.className = 'evidence-item';
      d.textContent = e;
      evDiv.appendChild(d);
    });
  } else {
    evDiv.innerHTML = '<span style="color:var(--muted)">No evidence samples.</span>';
  }

  // Pre-fill investigation form
  document.getElementById('inv-analyst').value = a.inv_analyst || '';
  document.getElementById('inv-status').value  = a.inv_status  || 'NEW';
  document.getElementById('inv-notes').value   = a.inv_notes   || '';
  document.getElementById('saved-flash').classList.remove('show');

  document.getElementById('detail-panel').classList.add('open');
}

function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
  currentAlertId = null;
  document.querySelectorAll('tbody tr').forEach(r => r.classList.remove('selected'));
}

// ── Save investigation ──
async function saveInvestigation() {
  if (!currentAlertId) return;
  await fetch('/api/alerts/' + currentAlertId + '/investigate', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      status:   document.getElementById('inv-status').value,
      notes:    document.getElementById('inv-notes').value,
      analyst:  document.getElementById('inv-analyst').value,
    })
  });
  const flash = document.getElementById('saved-flash');
  flash.classList.add('show');
  setTimeout(() => flash.classList.remove('show'), 2000);
  await loadAlerts();
  await loadStats();
}

// ── Rescan ──
async function rescan() {
  closeDetail();
  document.getElementById('loading').classList.remove('hidden');
  await fetch('/api/rescan', { method: 'POST' });
  await loadStats();
  await loadAlerts();
  setTimeout(() => document.getElementById('loading').classList.add('hidden'), 600);
}

// ── Close panel on outside click ──
document.addEventListener('click', (e) => {
  const panel = document.getElementById('detail-panel');
  if (panel.classList.contains('open') &&
      !panel.contains(e.target) &&
      !e.target.closest('tbody tr')) {
    closeDetail();
  }
});

// ── Init ──
window.addEventListener('load', async () => {
  await loadStats();
  await loadAlerts();
  setTimeout(() => document.getElementById('loading').classList.add('hidden'), 800);
});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n🛡  SIEM Dashboard starting...")
    print("   Open your browser → http://localhost:5000\n")
    app.run(debug=False, port=5000)
