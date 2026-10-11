// Agent Observability Client Logic

let timerInterval = null;
let timerSeconds = 0;

function formatBadge(status) {
  if (!status) return `<span class="badge badge-muted">Unknown</span>`;
  const s = status.toLowerCase();
  if (s.includes("verified") || s === "working and verified" || s === "success") {
    return `<span class="badge badge-ok">${status}</span>`;
  }
  if (s.includes("authentication") || s.includes("pending") || s.includes("partially")) {
    return `<span class="badge badge-warn">${status}</span>`;
  }
  if (s.includes("failed") || s.includes("not installed")) {
    return `<span class="badge badge-err">${status}</span>`;
  }
  return `<span class="badge badge-muted">${status}</span>`;
}

function formatDuration(ms) {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatDate(isoStr) {
  if (!isoStr) return "-";
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + 
           " (" + d.toLocaleDateString() + ")";
  } catch (e) {
    return isoStr;
  }
}

async function fetchJSON(url, options = {}) {
  const defaultHeaders = {
    "X-Requested-With": "Fetch",
    "Content-Type": "application/json"
  };
  options.headers = { ...defaultHeaders, ...(options.headers || {}) };
  const res = await fetch(url, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Request failed" }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

async function loadHealth() {
  try {
    const data = await fetchJSON("/api/health");
    const tbody = document.getElementById("tools-body");
    tbody.innerHTML = "";

    const tools = data.tools || {};
    for (const [toolId, info] of Object.entries(tools)) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${toolId}</strong></td>
        <td>${formatBadge(info.result_status)}</td>
        <td>${formatBadge(info.runtime_status)}</td>
        <td>${info.version || "-"}</td>
        <td>${formatDate(info.timestamp)}</td>
        <td><code>${info.telemetry_source || "none"}</code></td>
        <td class="subtext">${info.diagnostic_message || "-"}</td>
      `;
      tbody.appendChild(tr);
    }

    const lastUpdated = document.getElementById("last-updated");
    lastUpdated.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;

    const badge = document.getElementById("staleness-badge");
    if (data.is_stale) {
      badge.className = "badge badge-warn";
      badge.textContent = "Checks Stale (>1h ago)";
    } else {
      badge.className = "badge badge-ok";
      badge.textContent = "Recent Evidence Available";
    }
  } catch (err) {
    document.getElementById("tools-body").innerHTML = `<tr><td colspan="7" class="badge-err">${err.message}</td></tr>`;
  }
}

async function loadTelemetry() {
  const filterTool = document.getElementById("filter-tool").value;
  try {
    const url = filterTool === "all" ? "/api/events" : `/api/events?tool_id=${filterTool}`;
    const data = await fetchJSON(url);

    // 1. Render Usage Summary Table
    const usageBody = document.getElementById("usage-body");
    usageBody.innerHTML = "";
    const summary = data.usage_summary || {};

    const toolsToShow = filterTool === "all" ? Object.keys(summary) : [filterTool];

    for (const toolId of toolsToShow) {
      const s = summary[toolId] || {};
      const total = s.total_recorded_invocations || 0;
      const rate = s.success_rate !== null && s.success_rate !== undefined ? `${s.success_rate}%` : "-";
      const sources = s.evidence_sources && s.evidence_sources.length > 0 ? s.evidence_sources.join(", ") : "not instrumented";

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${toolId}</strong></td>
        <td>${total}</td>
        <td>${s.successful_invocations || 0}</td>
        <td>${s.failed_invocations || 0}</td>
        <td>${rate}</td>
        <td>${formatDate(s.last_recorded_use)}</td>
        <td>${formatDuration(s.average_duration_ms)}</td>
        <td><code>${sources}</code></td>
      `;
      usageBody.appendChild(tr);
    }

    // 2. Render Recent Events Table
    const eventsBody = document.getElementById("events-body");
    eventsBody.innerHTML = "";
    const events = data.events || [];

    if (events.length === 0) {
      eventsBody.innerHTML = `<tr><td colspan="7" class="empty">No events recorded yet.</td></tr>`;
    } else {
      for (const ev of events) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${formatDate(ev.timestamp)}</td>
          <td><strong>${ev.tool_id}</strong></td>
          <td>${ev.event_type}</td>
          <td>${formatBadge(ev.status)}</td>
          <td>${formatDuration(ev.duration_ms)}</td>
          <td><code>${ev.evidence_source}</code></td>
          <td class="subtext">${ev.details || "-"}</td>
        `;
        eventsBody.appendChild(tr);
      }
    }
  } catch (err) {
    document.getElementById("usage-body").innerHTML = `<tr><td colspan="8" class="badge-err">${err.message}</td></tr>`;
  }
}

async function loadMetrics() {
  try {
    const data = await fetchJSON("/api/metrics");

    document.getElementById("val-tasks-count").textContent = data.total_tasks_completed;
    document.getElementById("val-assisted-hours").textContent = `${data.total_assisted_hours} h`;
    document.getElementById("val-baseline-hours").textContent = `${data.total_baseline_hours} h`;

    const diffEl = document.getElementById("val-diff-hours");
    const diffHours = data.estimated_time_difference_hours;
    diffEl.textContent = `${diffHours > 0 ? "+" : ""}${diffHours} h`;
    diffEl.style.color = diffHours >= 0 ? "var(--status-ok)" : "var(--status-err)";

    const labourEl = document.getElementById("val-labour-inr");
    if (data.estimated_labour_value_inr !== null) {
      labourEl.textContent = `₹${data.estimated_labour_value_inr.toLocaleString()}`;
    } else {
      labourEl.textContent = data.financial_status_message || "-";
      labourEl.style.fontSize = "0.75rem";
    }

    const netEl = document.getElementById("val-net-inr");
    if (data.estimated_net_value_inr !== null) {
      netEl.textContent = `₹${data.estimated_net_value_inr.toLocaleString()}`;
    } else {
      netEl.textContent = data.net_value_status_message || "-";
      netEl.style.fontSize = "0.75rem";
    }

    // Workflow breakdown table
    const wfBody = document.getElementById("workflow-body");
    wfBody.innerHTML = "";
    const workflows = data.workflow_breakdown || {};
    const keys = Object.keys(workflows);

    if (keys.length === 0) {
      wfBody.innerHTML = `<tr><td colspan="5" class="empty">No recorded sessions yet.</td></tr>`;
    } else {
      for (const k of keys) {
        const wf = workflows[k];
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${k}</strong></td>
          <td>${wf.tasks_count}</td>
          <td>${wf.assisted_hours} h</td>
          <td>${wf.baseline_hours} h</td>
          <td>${wf.diff_hours > 0 ? "+" : ""}${wf.diff_hours} h</td>
        `;
        wfBody.appendChild(tr);
      }
    }
  } catch (err) {
    console.error("Failed to load metrics:", err);
  }
}

async function loadConfig() {
  try {
    const cfg = await fetchJSON("/api/config");
    if (cfg.hourly_rate_inr) document.getElementById("cfg-rate").value = cfg.hourly_rate_inr;
    if (cfg.attributable_costs_inr) document.getElementById("cfg-costs").value = cfg.attributable_costs_inr;
  } catch (err) {
    console.error("Failed to load config:", err);
  }
}

// Timer Logic
function startTimer() {
  if (timerInterval) return;
  document.getElementById("btn-timer-start").disabled = true;
  document.getElementById("btn-timer-stop").disabled = false;
  timerInterval = setInterval(() => {
    timerSeconds++;
    const h = String(Math.floor(timerSeconds / 3600)).padStart(2, '0');
    const m = String(Math.floor((timerSeconds % 3600) / 60)).padStart(2, '0');
    const s = String(timerSeconds % 60).padStart(2, '0');
    document.getElementById("timer-display").textContent = `${h}:${m}:${s}`;
  }, 1000);
}

function stopTimer() {
  if (!timerInterval) return;
  clearInterval(timerInterval);
  timerInterval = null;
  document.getElementById("btn-timer-start").disabled = false;
  document.getElementById("btn-timer-stop").disabled = true;
  // Populate actual duration input in minutes
  const mins = (timerSeconds / 60).toFixed(1);
  document.getElementById("actual-duration").value = mins;
}

function resetTimer() {
  clearInterval(timerInterval);
  timerInterval = null;
  timerSeconds = 0;
  document.getElementById("timer-display").textContent = "00:00:00";
  document.getElementById("btn-timer-start").disabled = false;
  document.getElementById("btn-timer-stop").disabled = true;
}

let autoRefreshTimer = null;
let isRefreshing = false;

async function autoRefresh() {
  if (isRefreshing) return;
  isRefreshing = true;
  try {
    await loadTelemetry();
    await loadMetrics();
    const lastUpdated = document.getElementById("last-updated");
    if (lastUpdated) {
      lastUpdated.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }
  } catch (e) {
    // Suppress transient network errors during auto-refresh
  } finally {
    isRefreshing = false;
  }
}

function startAutoRefresh(intervalMs = 3000) {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = setInterval(autoRefresh, intervalMs);
}

// Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  loadHealth();
  loadTelemetry();
  loadMetrics();
  loadConfig();
  startAutoRefresh(3000);

  document.getElementById("btn-refresh").addEventListener("click", () => {
    loadHealth();
    loadTelemetry();
    loadMetrics();
  });

  document.getElementById("filter-tool").addEventListener("change", loadTelemetry);


  document.getElementById("btn-run-checks").addEventListener("click", async () => {
    const btn = document.getElementById("btn-run-checks");
    btn.disabled = true;
    btn.textContent = "Running...";
    try {
      await fetchJSON("/api/health/run", { method: "POST", body: "{}" });
      await loadHealth();
    } catch (e) {
      alert("Health check failed: " + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Run Health Checks";
    }
  });

  document.getElementById("btn-timer-start").addEventListener("click", startTimer);
  document.getElementById("btn-timer-stop").addEventListener("click", stopTimer);
  document.getElementById("btn-timer-reset").addEventListener("click", resetTimer);

  document.getElementById("btn-save-config").addEventListener("click", async () => {
    const rate = document.getElementById("cfg-rate").value;
    const costs = document.getElementById("cfg-costs").value;
    try {
      await fetchJSON("/api/config", {
        method: "POST",
        body: JSON.stringify({ hourly_rate_inr: rate, attributable_costs_inr: costs })
      });
      alert("Configuration saved.");
      loadMetrics();
    } catch (e) {
      alert("Failed to save config: " + e.message);
    }
  });

  document.getElementById("session-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const taskName = document.getElementById("task-name").value;
    const actualMins = parseFloat(document.getElementById("actual-duration").value);
    const baselineMins = parseFloat(document.getElementById("baseline-duration").value);
    const status = document.getElementById("task-status").value;
    const notes = document.getElementById("task-notes").value;

    const selectedTools = Array.from(document.querySelectorAll("input[name='tools']:checked")).map(cb => cb.value);

    try {
      await fetchJSON("/api/sessions", {
        method: "POST",
        body: JSON.stringify({
          task_name: taskName,
          actual_duration_seconds: actualMins * 60,
          baseline_duration_seconds: baselineMins * 60,
          tools_used: selectedTools,
          completion_status: status,
          measurement_method: timerSeconds > 0 ? "timer" : "manual",
          notes: notes
        })
      });

      // Clear form and reload
      document.getElementById("session-form").reset();
      resetTimer();
      alert("Work session recorded.");
      loadMetrics();
    } catch (err) {
      alert("Error recording session: " + err.message);
    }
  });

  document.getElementById("btn-export").addEventListener("click", async () => {
    try {
      const data = await fetchJSON("/api/export");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `agent-observability-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Export failed: " + e.message);
    }
  });

  document.getElementById("btn-clear-db").addEventListener("click", async () => {
    if (!confirm("Are you sure you want to clear all monitoring records? This cannot be undone.")) return;
    try {
      await fetchJSON("/api/clear", {
        method: "POST",
        body: JSON.stringify({ confirm: true })
      });
      alert("Database cleared.");
      loadHealth();
      loadTelemetry();
      loadMetrics();
    } catch (e) {
      alert("Clear failed: " + e.message);
    }
  });
});
