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
  invalid_flags: "#fb923c",
  ttl_anomaly: "#a3e635",
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
  invalid_flags: "Invalid flags",
  ttl_anomaly: "TTL anomaly",
  ml_anomaly: "ML anomaly",
};
const CATEGORY_DESCRIPTIONS = {
  port_scan: "One source contacting many distinct ports quickly -- reconnaissance to find open services.",
  syn_flood: "Many connection attempts (SYNs) from one source without completing the handshake -- a denial-of-service technique.",
  repeated_port_probe: "Many repeated attempts at the same single port -- distinct from a scan, which spreads across ports.",
  exfiltration: "A single connection moving an unusually large amount of data over a sustained period.",
  arp_spoofing: "An IP address suddenly claimed by a different MAC address -- the classic man-in-the-middle technique on a local network.",
  dns_tunneling: "Data smuggled through DNS by encoding it into many unique or high-entropy subdomains.",
  stealth_scan: "TCP packets with unusual flag combinations (NULL, FIN-only, or XMAS) designed to slip past simpler firewalls.",
  icmp_flood: "A high rate of ICMP echo requests (pings) from one source -- a denial-of-service technique.",
  brute_force: "Rapid repeated connection attempts to a known authentication port (SSH, RDP, etc.) -- likely a password-guessing attempt.",
  invalid_flags: "TCP packets with logically contradictory flags (e.g. SYN+FIN) that only crafted/evasive tools produce.",
  ttl_anomaly: "The same source IP suddenly showing a very different TTL -- a strong signal of IP spoofing.",
  ml_anomaly: "Flagged by the general anomaly model as statistically unusual, without matching a specific known attack pattern.",
};

let searchDebounceTimer = null;
let lastAlertsData = [];
let seenAlertIds = new Set();
let firstAlertsLoad = true;
let soundEnabled = true;
let audioCtx = null;
let currentRange = "30m";
const RANGE_LABELS = { "30m": "last 30 min", "1h": "last hour", "6h": "last 6 hours", "24h": "last 24 hours" };

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

function playAlertSound() {
  if (!soundEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.frequency.value = 880;
    osc.type = "sine";
    gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.25);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.25);
  } catch (e) {
    console.error("Sound playback failed:", e);
  }
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
    closeModal();
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

function categoryOf(ruleReason) {
  if (!ruleReason) return "ml_anomaly";
  for (const key of Object.keys(CATEGORY_LABELS)) {
    if (ruleReason.startsWith(key)) return key;
  }
  return "ml_anomaly";
}

function openModal(alert) {
  const cat = categoryOf(alert.rule_reason);
  const label = CATEGORY_LABELS[cat] || cat;
  const color = CATEGORY_COLORS[cat] || "#64748b";
  const feedback = alert.feedback || "none";

  document.getElementById("modalBody").innerHTML = `
    <div class="modal-field"><span class="modal-field-label">Time</span><span>${formatTime(alert.timestamp)}</span></div>
    <div class="modal-field"><span class="modal-field-label">Source</span><span>${alert.src_ip}</span></div>
    <div class="modal-field"><span class="modal-field-label">Destination</span><span>${alert.dst_ip}</span></div>
    <div class="modal-field"><span class="modal-field-label">Score</span><span>${alert.score.toFixed(4)}</span></div>
    <div class="modal-field"><span class="modal-field-label">Type</span><span><span class="type-dot" style="background:${color}"></span>${label}</span></div>
    <div class="modal-field-full"><span class="modal-field-label">Rule Reason</span><div class="modal-longtext">${alert.rule_reason || '(none -- flagged by ML model)'}</div></div>
    <div class="modal-field-full"><span class="modal-field-label">Feature Explanation</span><div class="modal-longtext">${alert.top_reasons || '(not recorded)'}</div></div>
    <div class="modal-field"><span class="modal-field-label">Feedback</span><span class="feedback-tag feedback-${feedback}">${feedback}</span></div>
    <div class="modal-actions">
      <button class="action-btn action-btn-fp" onclick="markFeedback(${alert.id}, 'false_positive')">Mark False Positive</button>
      <button class="action-btn action-btn-ct" onclick="markFeedback(${alert.id}, 'confirmed_threat')">Mark Confirmed Threat</button>
    </div>
  `;
  document.getElementById("alertModalOverlay").classList.remove("modal-hidden");
}

function closeModal() {
  document.getElementById("alertModalOverlay").classList.add("modal-hidden");
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

  const newIds = alerts.filter(a => !seenAlertIds.has(a.id)).map(a => a.id);
  if (!firstAlertsLoad && newIds.length > 0) {
    playAlertSound();
  }
  alerts.forEach(a => seenAlertIds.add(a.id));
  firstAlertsLoad = false;

  body.innerHTML = alerts.map(a => {
    const scoreClass = a.score < 0 ? "score-neg" : "score-pos";
    const reason = a.rule_reason || a.top_reasons || "";
    const feedback = a.feedback || "none";
    const isNew = newIds.includes(a.id) ? "row-flash" : "";

    const fpActive = a.feedback === "false_positive" ? "action-btn-active" : "";
    const ctActive = a.feedback === "confirmed_threat" ? "action-btn-active" : "";
    const alertJson = JSON.stringify(a).replace(/"/g, "&quot;");

    return `<tr class="${isNew}" onclick="openModal(${alertJson})">
      <td>${formatTime(a.timestamp)}</td>
      <td>${a.src_ip}</td>
      <td>${a.dst_ip}</td>
      <td class="${scoreClass}"><span class="score-pill ${scoreClass}">${a.score.toFixed(3)}</span></td>
      <td>${truncate(reason, 60)}</td>
      <td><span class="feedback-tag feedback-${feedback}">${feedback}</span></td>
      <td class="actions-cell" onclick="event.stopPropagation()">
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

function renderGlossary() {
  const panel = document.getElementById("glossaryPanel");
  panel.innerHTML = Object.keys(CATEGORY_LABELS).map(key => `
    <div class="glossary-item">
      <div class="glossary-item-title">
        <span class="type-dot" style="background:${CATEGORY_COLORS[key]}"></span>
        ${CATEGORY_LABELS[key]}
      </div>
      <div class="glossary-item-desc">${CATEGORY_DESCRIPTIONS[key]}</div>
    </div>
  `).join("");
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

async function refreshTopOffenders() {
  const data = await fetchJSON("/api/top-offenders?limit=10");
  const body = document.getElementById("offendersBody");
  if (data.length === 0) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No alerts yet</td></tr>';
    return;
  }
  body.innerHTML = data.map(o => {
    const cat = categoryOf(o.last_reason);
    const label = CATEGORY_LABELS[cat] || cat;
    const statusBadge = o.is_blocked
      ? '<span class="feedback-tag feedback-confirmed_threat">blocked</span>'
      : '<span class="feedback-tag feedback-none">not blocked</span>';
    return `<tr>
      <td>${o.src_ip}</td>
      <td>${o.alert_count}</td>
      <td>${formatTime(o.last_seen)}</td>
      <td>${truncate(label + (o.last_reason ? ': ' + o.last_reason : ''), 50)}</td>
      <td>${statusBadge}</td>
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
  const data = await fetchJSON("/api/traffic-timeline?range=" + currentRange);
  drawSparkline(data);
}

async function refreshAll() {
  try {
    await Promise.all([refreshSummary(), refreshHealth(), refreshAlerts(), refreshBreakdown(), refreshBlocklist(), refreshTimeline(), refreshTopOffenders()]);
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
document.getElementById("modalClose").addEventListener("click", closeModal);
document.getElementById("alertModalOverlay").addEventListener("click", (e) => {
  if (e.target.id === "alertModalOverlay") closeModal();
});
document.getElementById("glossaryToggle").addEventListener("click", () => {
  const panel = document.getElementById("glossaryPanel");
  panel.classList.toggle("glossary-hidden");
  if (!panel.classList.contains("glossary-hidden")) renderGlossary();
});
document.querySelectorAll(".range-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".range-btn").forEach(b => b.classList.remove("range-btn-active"));
    btn.classList.add("range-btn-active");
    currentRange = btn.dataset.range;
    document.getElementById("sparklineTitle").textContent = "Traffic — " + RANGE_LABELS[currentRange];
    refreshTimeline();
  });
});
document.getElementById("soundToggle").addEventListener("click", () => {
  soundEnabled = !soundEnabled;
  document.getElementById("soundToggle").textContent = soundEnabled ? "🔔" : "🔕";
  showToast(soundEnabled ? "Alert sound on" : "Alert sound off", "info");
});

refreshAll();
setInterval(refreshAll, REFRESH_MS);
