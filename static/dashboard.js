const REFRESH_MS = 4000;
let trafficHistory = [];

async function fetchJSON(url) {
  const res = await fetch(url);
  return res.json();
}

function formatTime(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

function truncate(str, n) {
  if (!str) return "";
  return str.length > n ? str.slice(0, n) + "…" : str;
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

async function markFeedback(alertId, label) {
  try {
    const res = await fetch(`/api/alerts/${alertId}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label }),
    });
    if (!res.ok) {
      const err = await res.json();
      alert(`Failed to mark feedback: ${err.error || res.statusText}`);
      return;
    }
    await refreshAlerts();
  } catch (e) {
    console.error("markFeedback failed:", e);
  }
}

async function refreshAlerts() {
  const alerts = await fetchJSON("/api/alerts");
  const body = document.getElementById("alertsBody");
  if (alerts.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No alerts yet</td></tr>';
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
      <td class="${scoreClass}">${a.score.toFixed(3)}</td>
      <td>${truncate(reason, 60)}</td>
      <td><span class="feedback-tag feedback-${feedback}">${feedback}</span></td>
      <td class="actions-cell">
        <button class="action-btn action-btn-fp ${fpActive}" onclick="markFeedback(${a.id}, 'false_positive')">FP</button>
        <button class="action-btn action-btn-ct ${ctActive}" onclick="markFeedback(${a.id}, 'confirmed_threat')">Threat</button>
      </td>
    </tr>`;
  }).join("");
}

async function refreshBlocklist() {
  const blocked = await fetchJSON("/api/blocklist");
  const body = document.getElementById("blocklistBody");
  if (blocked.length === 0) {
    body.innerHTML = '<tr><td colspan="4" class="empty">No IPs currently blocked</td></tr>';
    return;
  }
  body.innerHTML = blocked.map(b => {
    const mode = b.dry_run ? "dry-run" : "LIVE";
    return `<tr>
      <td>${b.ip}</td>
      <td>${formatTime(b.blocked_at)}</td>
      <td>${mode}</td>
      <td>${truncate(b.reason || "", 60)}</td>
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
    await Promise.all([refreshSummary(), refreshAlerts(), refreshBlocklist(), refreshTimeline()]);
  } catch (e) {
    console.error("Refresh failed:", e);
  }
}

refreshAll();
setInterval(refreshAll, REFRESH_MS);
