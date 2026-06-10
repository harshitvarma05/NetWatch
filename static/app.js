const applyDefenseButton = document.querySelector("#applyDefense");
let selectedFlow = null;
let selectedPrediction = null;
let currentFlows = [];
let monitorActive = false;
let liveTimer = null;
let pollInFlight = false;
let pollGeneration = 0;
let demoCases = [];

const severityRank = { Critical: 3, High: 2, Low: 0 };

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Request failed" }));
    if (response.status === 401) showLogin(error.error || "Authentication required");
    throw new Error(error.error || "Request failed");
  }
  return response.json();
}

function showNotice(message, type = "info") {
  const notice = document.querySelector("#notice");
  notice.textContent = message;
  notice.className = `notice ${type === "error" ? "error" : ""}`;
  clearTimeout(showNotice.timer);
  showNotice.timer = setTimeout(() => notice.classList.add("hidden"), 4200);
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatUptime(seconds) {
  if (!seconds) return "uptime 0s";
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return minutes ? `uptime ${minutes}m ${rest}s` : `uptime ${rest}s`;
}

function riskScore(item) {
  const { prediction, record } = item;
  const severity = severityRank[prediction.recommended_action.severity] || 0;
  const attackBase = prediction.label === "normal" ? 0 : 42;
  const volume = Math.min(12, Math.round((record.packet_count || 0) / 20));
  return Math.min(100, Math.round(attackBase + prediction.confidence * 0.42 + severity * 12 + volume));
}

function renderDashboard(data) {
  document.querySelector("#totalFlows").textContent = formatNumber(data.total_flows);
  document.querySelector("#liveFlowCount").textContent = formatNumber(data.live_flows);
  document.querySelector("#packetRowsCount").textContent = formatNumber(data.packet_rows || 0);
  document.querySelector("#highSeverity").textContent = formatNumber(data.high);
  document.querySelector("#criticalSeverity").textContent = formatNumber(data.critical);
  document.querySelector("#actionsTaken").textContent = formatNumber(
    (data.blocked_ips || []).length + (data.rate_limited_ips || []).length + (data.suspicious_ips || []).length + (data.alerts || []).length
  );
  document.querySelector("#normalTraffic").textContent = `${formatNumber(data.normal)} normal`;
  document.querySelector("#queueHealth").textContent = data.attack ? `${formatNumber(data.attack)} suspicious` : "No active alerts";
  renderCollector(data.collector);
  renderModel(data.model);
  renderBreakdown(data.attack_breakdown || {});
  renderTopSources(data.top_sources || []);
  renderList("#blockedIps", data.blocked_ips || []);
  renderList("#rateLimitedIps", data.rate_limited_ips || []);
  renderList("#suspiciousIps", data.suspicious_ips || []);
  if (data.settings) renderSettings(data.settings);
}

function showLogin(message = "") {
  document.querySelector("#authOverlay").classList.remove("hidden");
  if (message) document.querySelector("#loginStatus").textContent = message;
}

function hideLogin() {
  document.querySelector("#authOverlay").classList.add("hidden");
}

async function checkSession() {
  const session = await request("/api/session");
  if (session.authenticated) {
    hideLogin();
    return true;
  }
  showLogin(session.default_passcode_hint ? `Default passcode is ${session.default_passcode_hint}.` : "Enter local passcode.");
  return false;
}

function renderModel(model) {
  if (!model) return;
  document.querySelector("#modelEngine").textContent = model.active || "Model unavailable";
  const primary = model.primary || {};
  document.querySelector("#modelDetail").textContent = primary.status || primary.error || "No model status";
  document.querySelector("#modelMode").textContent = model.mode || "single-model";
  document.querySelector("#trainingRows").textContent = formatNumber(primary.training_rows || 0);
  document.querySelector("#modelAccuracy").textContent = primary.accuracy ? `${(primary.accuracy * 100).toFixed(2)}%` : "--";
  document.querySelector("#modelClasses").textContent = (primary.classes || []).join(", ") || "--";
  const counts = primary.label_counts || {};
  document.querySelector("#labelCounts").innerHTML = Object.keys(counts).length
    ? Object.entries(counts)
        .map(([label, count]) => `<div><span>${label}</span><strong>${formatNumber(count)}</strong></div>`)
        .join("")
    : `<div><span>Status</span><strong>${primary.status || "No training metadata"}</strong></div>`;
}

function renderSettings(settings) {
  document.querySelector("#captureSeconds").value = settings.capture_seconds ?? 1;
  document.querySelector("#captureDevice").value = settings.capture_device || "";
  document.querySelector("#csvRowLimit").value = settings.csv_row_limit ?? 250;
  document.querySelector("#highRiskConfidence").value = settings.high_risk_confidence ?? 78;
  document.querySelector("#r2lSpecialist").checked = Boolean(settings.r2l_specialist_enabled);
}

function renderSystemInfo(info) {
  document.querySelector("#systemVersion").textContent = `v${info.version || "--"}`;
  const fields = [
    ["Project", info.project],
    ["Platform", info.platform],
    ["Dataset", info.dataset?.exists ? `${info.dataset.name} (${info.dataset.size_mb} MB)` : "Missing"],
    ["Active model", info.model?.active],
    ["Collector", info.collector?.mode],
    ["Auth", info.auth_enabled ? "Enabled" : "Disabled"],
    ["Database", info.database_exists ? "Ready" : "Not created"],
    ["Predictions", formatNumber(info.runtime?.predictions_loaded || 0)],
    ["Defense actions", formatNumber(info.runtime?.defense_actions || 0)],
  ];
  document.querySelector("#systemInfo").innerHTML = fields
    .map(([label, value]) => `<div><span>${label}</span><strong>${value || "--"}</strong></div>`)
    .join("");
}

function renderCollector(collector) {
  if (!collector) return;
  const labels = {
    pcap: "Packet stream",
    "pcap-context": "Packet stream context",
    "pcap-idle": "Packet stream idle",
    "pcap-idle-fallback": "Stream context",
    "netstat-fallback": "Connection fallback",
    "os-fallback": "Connection fallback",
    initializing: "Collector starting",
  };
  document.querySelector("#collectorMode").textContent = labels[collector.mode] || "Collector";
  document.querySelector("#collectorDetail").textContent = collector.status || "No status reported";
  document.querySelector("#collectorUptime").textContent = formatUptime(collector.uptime_seconds);
}

function renderTopSources(sources) {
  const element = document.querySelector("#topSources");
  if (!sources.length) {
    element.innerHTML = `<div class="empty-state">No source activity yet.</div>`;
    return;
  }
  const max = Math.max(...sources.map((source) => source.count), 1);
  element.innerHTML = sources
    .map(
      (source) => `
        <div class="source-row">
          <span>${source.ip}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${Math.round((source.count / max) * 100)}%"></div></div>
          <strong>${source.count}</strong>
        </div>
      `
    )
    .join("");
}

function renderRiskQueue(flows) {
  const queue = document.querySelector("#riskQueue");
  if (!flows.length) {
    queue.innerHTML = `<div class="empty-state">No flows in the current stream window.</div>`;
    return;
  }
  const sorted = [...flows].sort((a, b) => riskScore(b) - riskScore(a)).slice(0, 12);
  queue.innerHTML = sorted
    .map((item) => {
      const { record, prediction } = item;
      const selected = selectedFlow === record ? " selected" : "";
      return `
        <button class="queue-item${selected}" data-index="${currentFlows.indexOf(item)}">
          <span class="risk-score">${riskScore(item)}</span>
          <span class="queue-main">
            <strong>${record.source_ip}</strong>
            <small>${record.protocol.toUpperCase()} ${record.service} -> ${record.destination_ip}</small>
          </span>
          <span class="class-pill ${prediction.label}">${prediction.label_name}</span>
        </button>
      `;
    })
    .join("");
}

function renderLiveRows(flows) {
  const rows = document.querySelector("#liveRows");
  if (!flows.length) {
    rows.innerHTML = `<tr><td colspan="4">No packets were visible in this stream window.</td></tr>`;
    return;
  }
  rows.innerHTML = flows
    .slice(0, 10)
    .map(({ record, prediction }) => {
      return `
        <tr>
          <td>${record.source_ip} -> ${record.destination_ip}</td>
          <td>${prediction.label_name}</td>
          <td>${prediction.confidence}%</td>
          <td>${prediction.recommended_action.action}</td>
        </tr>
      `;
    })
    .join("");
}

function formatPacketTime(timestamp) {
  if (!timestamp) return "--";
  return new Date(Number(timestamp) * 1000).toLocaleTimeString();
}

function renderPacketFeed(packets) {
  const rows = document.querySelector("#packetTableRows");
  const status = document.querySelector("#packetFeedStatus");
  if (!rows || !status) return;
  status.textContent = packets.length ? `${formatNumber(packets.length)} buffered` : "Waiting";
  if (!packets.length) {
    rows.innerHTML = `<tr><td colspan="7">No packet rows captured yet.</td></tr>`;
    return;
  }
  rows.innerHTML = packets
    .slice(-40)
    .reverse()
    .map((packet) => {
      const source = `${packet.source_ip || "--"}:${packet.source_port || 0}`;
      const destination = `${packet.destination_ip || "--"}:${packet.destination_port || 0}`;
      return `
        <tr>
          <td>${formatPacketTime(packet.timestamp)}</td>
          <td>${source}</td>
          <td>${destination}</td>
          <td>${String(packet.protocol || "--").toUpperCase()}</td>
          <td>${packet.service || "--"}</td>
          <td>${formatNumber(packet.length || 0)}</td>
          <td>${packet.flag || "--"}</td>
        </tr>
      `;
    })
    .join("");
}

function renderDemoButtons(cases) {
  const container = document.querySelector("#demoButtons");
  demoCases = cases;
  container.innerHTML = cases
    .map(
      (item) => `
        <button data-demo-key="${item.key}">
          ${item.name}
        </button>
      `
    )
    .join("");
}

function renderBreakdown(breakdown) {
  const total = Object.values(breakdown).reduce((sum, value) => sum + value, 0) || 1;
  document.querySelector("#breakdown").innerHTML = Object.entries(breakdown)
    .map(([label, count]) => {
      const percent = Math.round((count / total) * 100);
      return `
        <div class="bar-row">
          <span>${label}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${percent}%"></div></div>
          <strong>${count}</strong>
        </div>
      `;
    })
    .join("");
}

function renderList(selector, values) {
  const element = document.querySelector(selector);
  if (!values.length) {
    element.innerHTML = `<li class="empty">No entries</li>`;
    return;
  }
  element.innerHTML = values.map((ip) => `<li class="ip">${ip}</li>`).join("");
}

function renderSelected(item) {
  selectedFlow = item.record;
  selectedPrediction = item.prediction;
  const { record, prediction } = item;
  document.querySelector("#predictionLabel").textContent = prediction.label_name;
  document.querySelector("#confidenceValue").textContent = `${prediction.confidence}%`;
  document.querySelector("#selectedSource").textContent = record.source_ip;
  document.querySelector("#selectedDestination").textContent = record.destination_ip;
  document.querySelector("#selectedProtocol").textContent = `${record.protocol.toUpperCase()} protocol`;
  document.querySelector("#selectedService").textContent = `${record.service} service`;
  document.querySelector("#selectedPackets").textContent = `${record.packet_count} packets`;
  document.querySelector("#selectedDuration").textContent = `${record.duration}s duration`;
  document.querySelector("#severityBadge").textContent = prediction.recommended_action.severity;
  document.querySelector("#severityBadge").className = `severity ${prediction.recommended_action.severity.toLowerCase()}`;
  document.querySelector("#recommendedAction").textContent = prediction.recommended_action.action;
  applyDefenseButton.disabled = prediction.label === "normal";
  document.querySelector("#explanationList").innerHTML = prediction.explanation
    .map((entry) => `<li><strong>${entry.reason}</strong><span>+${entry.contribution}% influence</span></li>`)
    .join("");
  document.querySelector("#probabilities").innerHTML = Object.entries(prediction.probabilities)
    .map(
      ([label, percent]) => `
        <div class="bar-row">
          <span>${label}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${percent}%"></div></div>
          <strong>${percent}%</strong>
        </div>
      `
    )
    .join("");
  renderRiskQueue(currentFlows);
}

async function pollLive({ autoSelect = false } = {}) {
  if (pollInFlight) return;
  pollInFlight = true;
  const generation = pollGeneration;
  try {
    const payload = await request("/api/live");
    if (generation !== pollGeneration) return;
    currentFlows = payload.flows;
    renderDashboard(payload.dashboard);
    renderRiskQueue(currentFlows);
    renderLiveRows(currentFlows);
    renderPacketFeed(payload.packets || []);
    if (monitorActive) document.querySelector("#liveStatus").textContent = "Live";
    if (currentFlows.length && (!selectedFlow || autoSelect)) {
      renderSelected([...currentFlows].sort((a, b) => riskScore(b) - riskScore(a))[0]);
    }
  } finally {
    pollInFlight = false;
  }
}

async function loadDemoCases() {
  const payload = await request("/api/demo-cases");
  renderDemoButtons(payload.cases || []);
}

async function loadSettings() {
  const payload = await request("/api/settings");
  renderSettings(payload.settings || {});
}

async function loadSystemInfo() {
  const payload = await request("/api/about");
  renderSystemInfo(payload);
}

async function runDemoCase(key) {
  const status = document.querySelector("#demoStatus");
  status.textContent = "Running";
  const payload = await request("/api/demo-case", {
    method: "POST",
    body: JSON.stringify({ key }),
  });
  currentFlows = [payload.flow];
  renderDashboard(payload.dashboard);
  renderRiskQueue(currentFlows);
  renderLiveRows(currentFlows);
  renderPacketFeed([]);
  renderSelected(payload.flow);
  status.textContent = payload.flow.prediction.label_name;
}

async function analyzeCsvFile() {
  const input = document.querySelector("#csvFile");
  const status = document.querySelector("#csvStatus");
  const summary = document.querySelector("#csvSummary");
  if (!input.files.length) {
    status.textContent = "Choose file";
    return;
  }
  status.textContent = "Analyzing";
  const csvText = await input.files[0].text();
  const payload = await request("/api/csv", {
    method: "POST",
    body: JSON.stringify({ csv: csvText, limit: Number(document.querySelector("#csvRowLimit").value || 250) }),
  });
  currentFlows = payload.flows || [];
  renderDashboard(payload.dashboard);
  renderRiskQueue(currentFlows);
  renderLiveRows(currentFlows);
  renderPacketFeed([]);
  if (currentFlows.length) renderSelected([...currentFlows].sort((a, b) => riskScore(b) - riskScore(a))[0]);
  const breakdown = payload.summary.breakdown || {};
  summary.innerHTML = `
    <div><span>Rows analyzed</span><strong>${formatNumber(payload.rows)}</strong></div>
    <div><span>Attack traffic</span><strong>${formatNumber(payload.summary.attack)}</strong></div>
    <div><span>Most common</span><strong>${payload.summary.most_common}</strong></div>
    ${Object.entries(breakdown)
      .map(([label, count]) => `<div><span>${label}</span><strong>${formatNumber(count)}</strong></div>`)
      .join("")}
  `;
  status.textContent = `${payload.rows} rows`;
}

async function exportReport() {
  const payload = await request("/api/export");
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `netwatch-report-${Date.now()}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showNotice("JSON report exported.");
}

function downloadUrl(path) {
  const link = document.createElement("a");
  link.href = path;
  document.body.appendChild(link);
  link.click();
  link.remove();
}

async function saveSettings() {
  const payload = {
    capture_seconds: Number(document.querySelector("#captureSeconds").value || 1),
    capture_device: document.querySelector("#captureDevice").value,
    csv_row_limit: Number(document.querySelector("#csvRowLimit").value || 250),
    high_risk_confidence: Number(document.querySelector("#highRiskConfidence").value || 78),
    r2l_specialist_enabled: document.querySelector("#r2lSpecialist").checked,
  };
  const response = await request("/api/settings", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  renderSettings(response.settings || {});
  document.querySelector("#settingsStatus").textContent = "Saved";
  setTimeout(() => {
    document.querySelector("#settingsStatus").textContent = "Saved locally";
  }, 1200);
  showNotice("Settings saved.");
}

async function resetRuntime() {
  const payload = await request("/api/reset", { method: "POST", body: JSON.stringify({}) });
  currentFlows = [];
  selectedFlow = null;
  selectedPrediction = null;
  renderDashboard(payload.dashboard);
  renderRiskQueue([]);
  renderLiveRows([]);
  renderPacketFeed([]);
  document.querySelector("#predictionLabel").textContent = "No flow selected";
  document.querySelector("#confidenceValue").textContent = "0%";
  document.querySelector("#recommendedAction").textContent = "Awaiting analysis";
  document.querySelector("#explanationList").innerHTML = "";
  document.querySelector("#probabilities").innerHTML = "";
  applyDefenseButton.disabled = true;
  await loadSystemInfo();
  showNotice("Runtime history and defense state cleared.");
}

function scheduleLivePoll() {
  if (!monitorActive) return;
  pollLive({ autoSelect: true })
    .catch((error) => {
      document.querySelector("#liveStatus").textContent = error.message;
    })
    .finally(() => {
      if (monitorActive) liveTimer = setTimeout(scheduleLivePoll, 1200);
    });
}

document.querySelector("#riskQueue").addEventListener("click", (event) => {
  const button = event.target.closest(".queue-item");
  if (!button) return;
  const item = currentFlows[Number(button.dataset.index)];
  if (item) renderSelected(item);
});

document.querySelector("#demoButtons").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-demo-key]");
  if (!button) return;
  runDemoCase(button.dataset.demoKey).catch((error) => {
    document.querySelector("#demoStatus").textContent = error.message;
    showNotice(error.message, "error");
  });
});

document.querySelector("#runCsv").addEventListener("click", () => {
  analyzeCsvFile().catch((error) => {
    document.querySelector("#csvStatus").textContent = error.message;
    showNotice(error.message, "error");
  });
});

document.querySelector("#exportReport").addEventListener("click", () => {
  exportReport().catch((error) => {
    document.querySelector("#liveStatus").textContent = error.message;
    showNotice(error.message, "error");
  });
});

document.querySelector("#exportPredictions").addEventListener("click", () => {
  downloadUrl("/api/export-predictions.csv");
  showNotice("Prediction CSV export started.");
});

document.querySelector("#exportDefense").addEventListener("click", () => {
  downloadUrl("/api/export-defense.csv");
  showNotice("Defense CSV export started.");
});

document.querySelector("#saveSettings").addEventListener("click", () => {
  saveSettings().catch((error) => {
    document.querySelector("#settingsStatus").textContent = error.message;
    showNotice(error.message, "error");
  });
});

document.querySelector("#refreshSystem").addEventListener("click", () => {
  loadSystemInfo()
    .then(() => showNotice("System info refreshed."))
    .catch((error) => showNotice(error.message, "error"));
});

document.querySelector("#resetRuntime").addEventListener("click", () => {
  resetRuntime().catch((error) => showNotice(error.message, "error"));
});

document.querySelector("#loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await request("/api/login", {
      method: "POST",
      body: JSON.stringify({ passcode: document.querySelector("#passcodeInput").value }),
    });
    hideLogin();
    await initializeDashboard();
  } catch (error) {
    document.querySelector("#loginStatus").textContent = error.message;
  }
});

document.querySelector("#toggleLive").addEventListener("click", () => {
  const button = document.querySelector("#toggleLive");
  const status = document.querySelector("#liveStatus");
  pollGeneration += 1;
  if (monitorActive) {
    monitorActive = false;
    clearTimeout(liveTimer);
    button.textContent = "Start monitor";
    status.textContent = "Paused";
    status.classList.remove("on");
    return;
  }
  monitorActive = true;
  button.textContent = "Pause monitor";
  status.textContent = "Starting";
  status.classList.add("on");
  scheduleLivePoll();
});

applyDefenseButton.addEventListener("click", async () => {
  if (!selectedFlow || !selectedPrediction) return;
  const payload = await request("/api/defense", {
    method: "POST",
    body: JSON.stringify({ source_ip: selectedFlow.source_ip, label: selectedPrediction.label }),
  });
  renderDashboard(payload.dashboard);
  applyDefenseButton.textContent = "Applied";
  setTimeout(() => {
    applyDefenseButton.textContent = "Apply response";
  }, 1200);
});

async function initializeDashboard() {
  await Promise.allSettled([loadSettings(), loadDemoCases(), loadSystemInfo()]);
  await pollLive().catch((error) => {
    document.querySelector("#predictionLabel").textContent = "Collector unavailable";
    document.querySelector("#recommendedAction").textContent = error.message;
    showNotice(error.message, "error");
  });
  await loadSystemInfo().catch(() => {});
}

checkSession()
  .then((authenticated) => {
    if (authenticated) return initializeDashboard();
  })
  .catch(() => showLogin("Enter local passcode."));
