const REFRESH_MS = 4000;
const CATEGORY_COLORS = {
  port_scan: "#38bdf8",
  syn_flood: "#ef4444",
  repeated_port_probe: "#eab308",
  exfiltration: "#a855f7",
  arp_spoofing: "#f97316",
  dns_tunneling: "#22d3ee",
  stealth_scan: "#ec4899",
  icmp_flood: "#84cc16",
  brute_force: "#f43f5e",
  ml_anomaly: "#64748b",
};
const CATEGORY_LABELS = {
  port_scan: "Port scan",
  syn_flood: "SYN flood",
  repeated_port_probe: "Port probe",
  exfiltration: "Exfiltration",
  arp_spoofing: "ARP spoofing",
  dns_tunneling: "DNS tunneling",
  stealth_scan: "Stealth scan",
  icmp_flood: "ICMP flood",
  brute_force: "Brute force",
  ml_anomaly: "ML anomaly",
};

let searchDebounceTimer = null;
let lastAlertsData = [];

async function fetchJSON(url, options) {
  const res = await fetch(url, options);
  return res.json();
}

function formatTime(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

function formatDuration(seconds) {
  if (seconds == null) return "-";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i++;
  }
  return `${bytes.toFixed(1)} ${units[i]}`;
}

function truncate(str, n) {
  if (!str) return "";
  return str.length > n ? str.slice(0, n) + "…" : str;
}

function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.classList.add("toast-visible"), 10);
  setTimeout(() => {
    toast.classList.remove("toast-visible");
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

async function refreshSummary() {
  const s = await fetchJSON("/api/summary");
  document.getElementById("statTraffic").textContent = s.traffic_count.toLocaleString();
  document.getElementById("statAlerts").textContent = s.alert_count.toLocaleString();
  document.getElementById("statRate").textContent = s.alert_rate.toFixed(4) + "%";
  document.getElementById("statBlocked").textContent = s.blocked_count;

  const modeEl = document.getElementById("modeIndicator");
  if (s.dry_run) {
    modeEl.textContent = "Dry Run";
    modeEl.className = "mode-indicator dry-run";
  } else {
    modeEl.textContent = "Live Enforcement";
    modeEl.className = "mode-indicator live";
  }
}

async function refreshHealth() {
  const h = await fetchJSON("/api/health");
  const grid = document.getElementById("healthGrid");

  const detectOk = h.detect_service_status === "active";
  const dashOk = h.dashboard_service_status === "active";

  const dot = document.getElementById("healthDot");
  dot.className = "health-dot " + (detectOk ? "health-ok" : "health-bad");

  const captureAge = h.last_capture_ts ? (h.server_time - h.last_capture_ts) : null;
  const captureStale = captureAge !== null && captureAge > 60;

  grid.innerHTML = `
    <div class="health-item">
      <div class="health-item-label">Detection Service</div>
      <div class="health-item-value ${detectOk ? 'health-good' : 'health-warn'}">${h.detect_service_status}</div>
    </div>
    <div class="health-item">
      <div class="health-item-label">Dashboard Service</div>
      <div class="health-item-value ${dashOk ? 'health-good' : 'health-warn'}">${h.dashboard_service_status}</div>
    </div>
    <div class="health-item">
      <div class="health-item-label">Last Capture</div>
      <div class="health-item-value ${captureStale ? 'health-warn' : ''}">${captureAge !== null ? formatDuration(captureAge) + ' ago' : '-'}</div>
    </div>
    <div class="health-item">
      <div class="health-item-label">Model Last Trained</div>
      <div class="health-item-value">${h.model_last_trained ? formatTime(h.model_last_trained) : 'never'}</div>
    </div>
    <div class="health-item">
      <div class="health-item-label">Database Size</div>
      <div class="health-item-value">${formatBytes(h.db_size_bytes)}</div>
    </div>
    <div class="health-item">
      <div class="health-item-label">Dashboard Uptime</div>
      <div class="health-item-value">${formatDuration(h.dashboard_uptime_seconds)}</div>
    </div>
  `;
}

function currentFilters() {
  return {
    q: document.getElementById("searchInput").value.trim(),
    reason: document.getElementById("reasonFilter").value,
    feedback: document.getElementById("feedbackFilter").value,
  };
}

async function markFeedback(alertId, label) {
  try {
    const res = await fetch(`/api/alerts/${alertId}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label }),
    });
    if (!res.ok) {
      const err = await res.json();
      showToast(`Failed: ${err.error || res.statusText}`, "error");
      return;
    }
    showToast(`Marked as ${label.replace('_', ' ')}`, "success");
    await refreshAlerts();
  } catch (e) {
    showToast("Network error marking feedback", "error");
    console.error("markFeedback failed:", e);
  }
}

async function unblockIp(ip) {
  try {
    const res = await fetch(`/api/blocklist/${ip}/unblock`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json();
      showToast(`Failed: ${err.error || res.statusText}`, "error");
      return;
    }
    showToast(`Unblocked ${ip}`, "success");
    await refreshBlocklist();
    await refreshSummary();
  } catch (e) {
    showToast("Network error unblocking IP", "error");
    console.error("unblockIp failed:", e);
  }
}

function exportAlertsToCsv() {
  if (lastAlertsData.length === 0) {
    showToast("No alerts to export", "error");
    return;
  }
  const headers = ["id", "time", "src_ip", "dst_ip", "score", "reason", "feedback"];
  const rows = lastAlertsData.map(a => [
    a.id, formatTime(a.timestamp), a.src_ip, a.dst_ip, a.score,
    `"${(a.rule_reason || a.top_reasons || "").replace(/"/g, '""')}"`,
    a.feedback || "none",
  ]);
  const csv = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `acf_alerts_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported ${lastAlertsData.length} alerts`, "success");
}

async function refreshAlerts() {
  const f = currentFilters();
  const params = new URLSearchParams();
  if (f.q) params.set("q", f.q);
  if (f.reason) params.set("reason", f.reason);
  if (f.feedback) params.set("feedback", f.feedback);

  const alerts = await fetchJSON("/api/alerts?" + params.toString());
  lastAlertsData = alerts;
  const body = document.getElementById("alertsBody");
  if (alerts.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No alerts match these filters</td></tr>';
    return;
  }
  body.innerHTML = alerts.map(a => {
    const scoreClass = a.score < 0 ? "score-neg" : "score-pos";
    const reason = a.rule_reason || a.top_reasons || "";
    const feedback = a.feedback || "none";

    const fpActive = a.feedback === "false_positive" ? "action-btn-active" : "";
    const ctActive = a.feedback === "confirmed_threat" ? "action-btn-active" : "";

    return `<tr>
      <td>${formatTime(a.timestamp)}</td>
      <td>${a.src_ip}</td>
      <td>${a.dst_ip}</td>
      <td class="${scoreClass}"><span class="score-pill ${scoreClass}">${a.score.toFixed(3)}</span></td>
      <td>${truncate(reason, 60)}</td>
      <td><span class="feedback-tag feedback-${feedback}">${feedback}</span></td>
      <td class="actions-cell">
        <button class="action-btn action-btn-fp ${fpActive}" onclick="markFeedback(${a.id}, 'false_positive')">FP</button>
        <button class="action-btn action-btn-ct ${ctActive}" onclick="markFeedback(${a.id}, 'confirmed_threat')">Threat</button>
      </td>
    </tr>`;
  }).join("");
}

async function refreshBreakdown() {
  const data = await fetchJSON("/api/alert-breakdown");
  const container = document.getElementById("breakdownChart");

  if (data.length === 0) {
    container.innerHTML = '<div class="empty">No alerts yet</div>';
    return;
  }

  const max = Math.max(...data.map(d => d.count));
  container.innerHTML = data.map(d => {
    const color = CATEGORY_COLORS[d.category] || "#64748b";
    const label = CATEGORY_LABELS[d.category] || d.category;
    const pct = (d.count / max) * 100;
    return `<div class="breakdown-row">
      <div class="breakdown-label">${label}</div>
      <div class="breakdown-bar-track">
        <div class="breakdown-bar-fill" style="width:${pct}%;background:${color};"></div>
      </div>
      <div class="breakdown-count">${d.count}</div>
    </div>`;
  }).join("");
}

async function refreshBlocklist() {
  const blocked = await fetchJSON("/api/blocklist");
  const body = document.getElementById("blocklistBody");
  if (blocked.length === 0) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No IPs currently blocked</td></tr>';
    return;
  }
  body.innerHTML = blocked.map(b => {
    const mode = b.dry_run ? "dry-run" : "LIVE";
    return `<tr>
      <td>${b.ip}</td>
      <td>${formatTime(b.blocked_at)}</td>
      <td>${mode}</td>
      <td>${truncate(b.reason || "", 60)}</td>
      <td><button class="action-btn action-btn-unblock" onclick="unblockIp('${b.ip}')">Unblock</button></td>
    </tr>`;
  }).join("");
}

function drawSparkline(data) {
  const canvas = document.getElementById("sparkline");
  const ctx = canvas.getContext("2d");
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * devicePixelRatio;
  canvas.height = rect.height * devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio);

  const w = rect.width, h = rect.height;
  ctx.clearRect(0, 0, w, h);

  if (data.length < 2) {
    ctx.fillStyle = "#64748b";
    ctx.font = "12px Inter";
    ctx.fillText("Collecting data...", 10, h / 2);
    return;
  }

  const max = Math.max(...data.map(d => d.count), 1);
  const stepX = w / (data.length - 1);

  ctx.beginPath();
  ctx.strokeStyle = "#38bdf8";
  ctx.lineWidth = 2;
  data.forEach((d, i) => {
    const x = i * stepX;
    const y = h - (d.count / max) * (h - 10) - 5;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  ctx.closePath();
  ctx.fillStyle = "rgba(56, 189, 248, 0.1)";
  ctx.fill();
}

async function refreshTimeline() {
  const data = await fetchJSON("/api/traffic-timeline");
  drawSparkline(data);
}

async function refreshAll() {
  try {
    await Promise.all([refreshSummary(), refreshHealth(), refreshAlerts(), refreshBreakdown(), refreshBlocklist(), refreshTimeline()]);
  } catch (e) {
    console.error("Refresh failed:", e);
  }
}

document.getElementById("searchInput").addEventListener("input", () => {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(refreshAlerts, 300);
});
document.getElementById("reasonFilter").addEventListener("change", refreshAlerts);
document.getElementById("feedbackFilter").addEventListener("change", refreshAlerts);
document.getElementById("exportBtn").addEventListener("click", exportAlertsToCsv);

refreshAll();
setInterval(refreshAll, REFRESH_MS);
