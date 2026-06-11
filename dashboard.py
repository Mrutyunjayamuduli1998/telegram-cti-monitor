"""
dashboard.py — Web dashboard for Telegram CTI Monitor
Run: python dashboard.py
Then open: http://localhost:5000
"""

import sqlite3
import yaml
from flask import Flask, jsonify, render_template_string
from datetime import datetime, timedelta

app = Flask(__name__)

def load_db_path():
    try:
        with open("config.yaml") as f:
            cfg = yaml.safe_load(f)
        return cfg["monitor"]["db_path"]
    except:
        return "cti_monitor.db"

def query(sql, params=()):
    db = load_db_path()
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── API endpoints ────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    total_messages = query("SELECT COUNT(*) as c FROM messages")[0]["c"]
    total_alerts   = query("SELECT COUNT(*) as c FROM alerts")[0]["c"]
    misp_pushed    = query("SELECT COUNT(*) as c FROM alerts WHERE misp_event_id IS NOT NULL")[0]["c"]
    live_alerts    = query("SELECT COUNT(*) as c FROM alerts WHERE message_id NOT IN (SELECT message_id FROM messages WHERE has_alert=1 AND ingested_at < (SELECT MIN(ingested_at) FROM messages WHERE ingested_at > datetime('now','-1 hour')))")[0]["c"]

    by_category = query("""
        SELECT category, COUNT(*) as count
        FROM alerts GROUP BY category ORDER BY count DESC
    """)
    by_channel = query("""
        SELECT channel, COUNT(*) as count
        FROM alerts GROUP BY channel ORDER BY count DESC
    """)
    top_keywords = query("""
        SELECT matched_keyword, COUNT(*) as count
        FROM alerts GROUP BY matched_keyword ORDER BY count DESC LIMIT 10
    """)

    return jsonify({
        "total_messages": total_messages,
        "total_alerts":   total_alerts,
        "misp_pushed":    misp_pushed,
        "by_category":    by_category,
        "by_channel":     by_channel,
        "top_keywords":   top_keywords,
    })

@app.route("/api/alerts")
def api_alerts():
    rows = query("""
        SELECT id, channel, category, matched_keyword,
               message_text, date, misp_event_id, created_at
        FROM alerts
        ORDER BY created_at DESC
        LIMIT 200
    """)
    return jsonify(rows)

@app.route("/api/timeline")
def api_timeline():
    rows = query("""
        SELECT date(created_at) as day, COUNT(*) as count
        FROM alerts
        GROUP BY day
        ORDER BY day DESC
        LIMIT 30
    """)
    return jsonify(rows)

@app.route("/api/live")
def api_live():
    rows = query("""
        SELECT channel, category, matched_keyword, message_text, created_at
        FROM alerts
        ORDER BY created_at DESC
        LIMIT 10
    """)
    return jsonify(rows)

# ── Main page ────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CTI Monitor Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }

  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 32px;
           display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 18px; font-weight: 600; color: #f0f6fc; letter-spacing: 0.5px; }
  header h1 span { color: #58a6ff; }
  .live-dot { width: 8px; height: 8px; background: #3fb950; border-radius: 50%;
              display: inline-block; margin-right: 6px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .status { font-size: 13px; color: #3fb950; display: flex; align-items: center; }

  .container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }

  .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
               padding: 20px 24px; }
  .stat-card .label { font-size: 12px; color: #8b949e; text-transform: uppercase;
                      letter-spacing: 0.8px; margin-bottom: 8px; }
  .stat-card .value { font-size: 32px; font-weight: 700; color: #f0f6fc; }
  .stat-card .value.blue  { color: #58a6ff; }
  .stat-card .value.green { color: #3fb950; }
  .stat-card .value.amber { color: #d29922; }
  .stat-card .value.red   { color: #f85149; }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px 24px; }
  .card h2 { font-size: 13px; font-weight: 600; color: #8b949e; text-transform: uppercase;
             letter-spacing: 0.8px; margin-bottom: 16px; }

  .bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .bar-row .name { font-size: 13px; color: #c9d1d9; width: 160px; white-space: nowrap;
                   overflow: hidden; text-overflow: ellipsis; }
  .bar-row .bar-wrap { flex: 1; background: #21262d; border-radius: 4px; height: 8px; }
  .bar-row .bar-fill { height: 8px; border-radius: 4px; background: #58a6ff; transition: width 0.6s; }
  .bar-row .count { font-size: 12px; color: #8b949e; width: 30px; text-align: right; }

  .cat-pill { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px;
              font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
  .cat-threat_actors   { background: #3d1f63; color: #c084fc; }
  .cat-malware         { background: #3d1a1a; color: #f85149; }
  .cat-ransomware      { background: #3d2a0a; color: #d29922; }
  .cat-vulnerabilities { background: #0d2f4a; color: #58a6ff; }
  .cat-data_leaks      { background: #0d3d1f; color: #3fb950; }
  .cat-ioc_patterns    { background: #2d2d2d; color: #8b949e; }

  .alert-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .alert-table th { text-align: left; padding: 8px 12px; color: #8b949e; font-weight: 500;
                    border-bottom: 1px solid #30363d; font-size: 12px; text-transform: uppercase; }
  .alert-table td { padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }
  .alert-table tr:hover td { background: #1c2128; }
  .alert-table .msg-preview { color: #8b949e; max-width: 400px; white-space: nowrap;
                               overflow: hidden; text-overflow: ellipsis; }
  .alert-table .keyword { color: #f0f6fc; font-weight: 500; }
  .alert-table .channel { color: #58a6ff; }
  .alert-table .time { color: #8b949e; white-space: nowrap; }
  .misp-badge { background: #1a3a5c; color: #58a6ff; padding: 2px 6px; border-radius: 3px;
                font-size: 10px; font-weight: 600; }

  .search-bar { width: 100%; background: #21262d; border: 1px solid #30363d; border-radius: 6px;
                padding: 8px 14px; color: #c9d1d9; font-size: 13px; margin-bottom: 16px;
                outline: none; }
  .search-bar:focus { border-color: #58a6ff; }

  .chart-wrap { position: relative; height: 200px; }

  .keyword-chip { display: inline-block; background: #21262d; border: 1px solid #30363d;
                  border-radius: 4px; padding: 3px 8px; margin: 3px; font-size: 12px; color: #c9d1d9; }
  .keyword-chip .kcount { color: #58a6ff; font-weight: 600; margin-left: 4px; }

  @media (max-width: 900px) {
    .stat-grid { grid-template-columns: repeat(2,1fr); }
    .grid-2, .grid-3 { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<header>
  <h1>🛡️ <span>CTI</span> Monitor Dashboard</h1>
  <div class="status"><span class="live-dot"></span> Live</div>
</header>

<div class="container">

  <!-- Stat cards -->
  <div class="stat-grid" id="stat-grid">
    <div class="stat-card"><div class="label">Messages Ingested</div><div class="value blue" id="s-messages">—</div></div>
    <div class="stat-card"><div class="label">Total Alerts</div><div class="value red" id="s-alerts">—</div></div>
    <div class="stat-card"><div class="label">MISP Events Created</div><div class="value green" id="s-misp">—</div></div>
    <div class="stat-card"><div class="label">Channels Monitored</div><div class="value amber" id="s-channels">—</div></div>
  </div>

  <!-- Charts row -->
  <div class="grid-2">
    <div class="card">
      <h2>Alerts by Category</h2>
      <div class="chart-wrap"><canvas id="cat-chart"></canvas></div>
    </div>
    <div class="card">
      <h2>Alert Timeline (last 30 days)</h2>
      <div class="chart-wrap"><canvas id="timeline-chart"></canvas></div>
    </div>
  </div>

  <!-- Bars row -->
  <div class="grid-2">
    <div class="card">
      <h2>Top Channels</h2>
      <div id="channel-bars"></div>
    </div>
    <div class="card">
      <h2>Top Keywords</h2>
      <div id="keyword-chips"></div>
    </div>
  </div>

  <!-- Alert feed -->
  <div class="card">
    <h2>Alert Feed</h2>
    <input class="search-bar" id="search" placeholder="Search alerts by keyword, channel, or message text..." oninput="filterTable()">
    <div style="overflow-x:auto">
      <table class="alert-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Channel</th>
            <th>Category</th>
            <th>Keyword</th>
            <th>Message Preview</th>
            <th>MISP</th>
          </tr>
        </thead>
        <tbody id="alert-tbody"></tbody>
      </table>
    </div>
  </div>

</div>

<script>
let allAlerts = [];
let catChart, timelineChart;

const CAT_COLORS = {
  threat_actors:   '#c084fc',
  malware:         '#f85149',
  ransomware:      '#d29922',
  vulnerabilities: '#58a6ff',
  data_leaks:      '#3fb950',
  ioc_patterns:    '#8b949e',
};

function fmtTime(s) {
  if (!s) return '—';
  const d = new Date(s.replace(' ','T')+'Z');
  return d.toLocaleString('en-IN', {timeZone:'Asia/Kolkata',
    day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit'});
}

async function loadStats() {
  const r = await fetch('/api/stats');
  const d = await r.json();

  document.getElementById('s-messages').textContent  = d.total_messages.toLocaleString();
  document.getElementById('s-alerts').textContent    = d.total_alerts.toLocaleString();
  document.getElementById('s-misp').textContent      = d.misp_pushed.toLocaleString();
  document.getElementById('s-channels').textContent  = d.by_channel.length;

  // Category chart
  const cats   = d.by_category.map(x => x.category.replace('_',' '));
  const counts = d.by_category.map(x => x.count);
  const colors = d.by_category.map(x => CAT_COLORS[x.category] || '#8b949e');

  if (catChart) catChart.destroy();
  catChart = new Chart(document.getElementById('cat-chart'), {
    type: 'doughnut',
    data: { labels: cats, datasets: [{ data: counts, backgroundColor: colors, borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'right', labels: { color: '#8b949e', font: { size: 12 } } } } }
  });

  // Channel bars
  const maxC = d.by_channel[0]?.count || 1;
  document.getElementById('channel-bars').innerHTML = d.by_channel.map(x => `
    <div class="bar-row">
      <div class="name">${x.channel}</div>
      <div class="bar-wrap"><div class="bar-fill" style="width:${(x.count/maxC*100).toFixed(1)}%"></div></div>
      <div class="count">${x.count}</div>
    </div>`).join('');

  // Keyword chips
  document.getElementById('keyword-chips').innerHTML = d.top_keywords.map(x => `
    <span class="keyword-chip">${x.matched_keyword}<span class="kcount">${x.count}</span></span>
  `).join('');
}

async function loadTimeline() {
  const r = await fetch('/api/timeline');
  const d = await r.json();
  const reversed = [...d].reverse();

  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(document.getElementById('timeline-chart'), {
    type: 'bar',
    data: {
      labels: reversed.map(x => x.day),
      datasets: [{ data: reversed.map(x => x.count), backgroundColor: '#1f6feb',
                   borderRadius: 4, borderSkipped: false }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b949e', font: { size: 10 }, maxRotation: 45 },
             grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
      }
    }
  });
}

async function loadAlerts() {
  const r = await fetch('/api/alerts');
  allAlerts = await r.json();
  renderTable(allAlerts);
}

function renderTable(data) {
  document.getElementById('alert-tbody').innerHTML = data.map(a => `
    <tr>
      <td class="time">${fmtTime(a.created_at)}</td>
      <td class="channel">${a.channel}</td>
      <td><span class="cat-pill cat-${a.category}">${a.category.replace('_',' ')}</span></td>
      <td class="keyword">${a.matched_keyword}</td>
      <td class="msg-preview" title="${(a.message_text||'').replace(/"/g,'&quot;')}">${(a.message_text||'').substring(0,120)}</td>
      <td>${a.misp_event_id ? '<span class="misp-badge">MISP</span>' : ''}</td>
    </tr>`).join('');
}

function filterTable() {
  const q = document.getElementById('search').value.toLowerCase();
  if (!q) { renderTable(allAlerts); return; }
  renderTable(allAlerts.filter(a =>
    (a.matched_keyword||'').toLowerCase().includes(q) ||
    (a.channel||'').toLowerCase().includes(q) ||
    (a.message_text||'').toLowerCase().includes(q) ||
    (a.category||'').toLowerCase().includes(q)
  ));
}

async function refresh() {
  await Promise.all([loadStats(), loadTimeline(), loadAlerts()]);
}

refresh();
setInterval(refresh, 30000); // auto-refresh every 30s
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

if __name__ == "__main__":
    print("\n  CTI Monitor Dashboard")
    print("  Open in browser: http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
