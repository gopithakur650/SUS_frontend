const API = "";
const NFs = ["AMF", "SMF", "UPF", "NRF", "AUSF", "UDM"];
const CATEGORIES = ["Auth", "Encrypt", "Transport", "Access", "Exposure", "Harden"];
const state = {
  health: null,
  history: [],
  historyDetails: [],
  rules: [],
  currentScan: null,
  selectedFile: null,
  selectedNode: null,
  mode: "network",
  zoom: 1,
  labels: true
  , severityView: "bars"
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, options);
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch (_) {}
    throw new Error(detail);
  }
  return response.json();
}

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove("show"), 2600);
}

function formatTime(value) {
  if (!value) return "No scan data";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[char]);
}

function animateCount(element, target) {
  if (!element) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    element.textContent = target;
    return;
  }
  const start = Number(element.textContent) || 0;
  const duration = 420;
  const started = performance.now();
  function update(now) {
    const progress = Math.min(1, (now - started) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    element.textContent = String(Math.round(start + (target - start) * eased));
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

async function checkBackend() {
  const status = $("#connectionStatus");
  try {
    await api("/api/health");
    status.className = "connection online";
    status.querySelector("span:last-child").textContent = "Backend Online";
  } catch (_) {
    status.className = "connection offline";
    status.querySelector("span:last-child").textContent = "Backend Disconnected";
  }
}

async function loadRules() {
  try {
    const data = await api("/api/scan/rules");
    state.rules = data.rules || [];
    renderRuleTable();
  } catch (error) {
    state.rules = [];
    $("#ruleTable").innerHTML = `<div class="inspector-body">${escapeHtml(error.message)}</div>`;
  }
}

async function loadHistory() {
  try {
    const data = await api("/api/scan/history");
    state.history = data.scans || [];
    const scanFilter = $("#scanFilter");
    if (scanFilter) {
      scanFilter.innerHTML = `<option value="">LATEST SCAN</option>${state.history.map((entry) => `<option value="${escapeHtml(entry.scan_id)}">${escapeHtml(entry.filename)}</option>`).join("")}`;
    }
    state.historyDetails = [];
    await Promise.all(state.history.map(async (entry) => {
      try {
        state.historyDetails.push(await api(`/api/scan/${encodeURIComponent(entry.scan_id)}`));
      } catch (_) {}
    }));
    state.historyDetails.sort((a, b) => new Date(a.scanned_at || 0) - new Date(b.scanned_at || 0));
    renderHistory();
    renderTopRisks();
    renderCategoryChart();
    renderRuleCoverage();
    renderFrequencyChart();
    renderActivityTimeline();
    renderRemediation();
    renderTrend();
  } catch (error) {
    state.history = [];
    $("#historyList").innerHTML = `<div class="last-scan">${escapeHtml(error.message)}</div>`;
    $("#historyTable").innerHTML = `<div class="inspector-body">${escapeHtml(error.message)}</div>`;
  }
}

function renderHealth(summary) {
  if (!summary) {
    $("#securityScore").textContent = "—";
    $("#healthStatus").textContent = "NO DATA";
    $("#healthStatus").className = "status-label";
    ["totalFindings", "criticalFindings", "highFindings", "rulesChecked"].forEach((id) => $("#" + id).textContent = "—");
    if ($("#criticalCardCount")) $("#criticalCardCount").textContent = "—";
    $("#scoreProgress").style.width = "0";
    renderSeverity({});
    renderTopRisks();
    renderCategoryChart();
    renderRuleCoverage();
    renderRemediation();
    return;
  }
  const score = Number(summary.security_score);
  animateCount($("#securityScore"), Number.isFinite(score) ? score : 0);
  $("#healthStatus").textContent = summary.status === "CLEAN" ? "CLEAN" : "VULNERABILITIES FOUND";
  $("#healthStatus").className = `status-label ${summary.status === "CLEAN" ? "clean" : "risk"}`;
  $("#totalFindings").textContent = summary.total_findings ?? 0;
  $("#criticalFindings").textContent = summary.critical ?? 0;
  if ($("#criticalCardCount")) $("#criticalCardCount").textContent = summary.critical ?? 0;
  if ($("#criticalFindings")) $("#criticalFindings").textContent = `${summary.critical ?? 0} CRITICAL`;
  if ($("#highFindings")) $("#highFindings").textContent = `${summary.high ?? 0} HIGH`;
  if ($("#highFindings")) $("#highFindings").textContent = `${summary.high ?? 0} HIGH`;
  $("#rulesChecked").textContent = summary.total_rules_checked ?? "—";
  $("#lastScan").textContent = formatTime(state.currentScan?.scanned_at);
  $("#scoreProgress").style.width = `${Number.isFinite(score) ? score : 0}%`;
  renderSeverity(summary);
  renderMatrix(summary);
  renderTrend();
  renderTopRisks();
  renderCategoryChart();
  renderRuleCoverage();
  renderRemediation();
  updateTopology(summary);
}

function renderSeverity(summary) {
  const values = { CRITICAL: summary.critical ?? 0, HIGH: summary.high ?? 0, MEDIUM: summary.medium ?? 0, LOW: summary.low ?? 0 };
  const total = Object.values(values).reduce((sum, value) => sum + Number(value || 0), 0);
  if (!total) {
    $("#severityChart").innerHTML = `<div class="analytics-empty"><strong>Clean distribution</strong><span>No findings in the selected scan.</span></div>`;
    return;
  }
  if (state.severityView === "donut") {
    const radius = 38;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const colors = { CRITICAL: "var(--red)", HIGH: "var(--amber)", MEDIUM: "#a9a9a4", LOW: "var(--green)" };
    const segments = Object.entries(values).map(([severity, count]) => {
      const fraction = total ? count / total : 0;
      const segment = `<circle cx="54" cy="54" r="${radius}" fill="none" stroke="${colors[severity]}" stroke-width="8"
        stroke-dasharray="${fraction * circumference} ${circumference}"
        stroke-dashoffset="${-offset}" transform="rotate(-90 54 54)" title="${count} ${severity} · ${(fraction * 100).toFixed(1)}%"></circle>`;
      offset += fraction * circumference;
      return segment;
    }).join("");
    $("#severityChart").innerHTML = `<div class="donut-layout"><svg viewBox="0 0 108 108"><circle cx="54" cy="54" r="${radius}" fill="none" stroke="var(--border)" stroke-width="8"></circle>${segments}</svg>
      <div class="donut-legend">${Object.entries(values).map(([severity, count]) => `<div><span>${severity.charAt(0) + severity.slice(1).toLowerCase()}</span><strong>${count} · ${total ? ((count / total) * 100).toFixed(1) : "0"}%</strong></div>`).join("")}</div></div>`;
    return;
  }
  const max = Math.max(...Object.values(values), 1);
  $("#severityChart").innerHTML = Object.entries(values).map(([severity, count]) => `
    <div class="severity-row" data-severity="${severity}" title="${count} ${severity.toLowerCase()} findings · ${total ? ((count / total) * 100).toFixed(1) : "0"}%">
      <label>${severity.charAt(0) + severity.slice(1).toLowerCase()}</label>
      <div class="severity-track"><div class="severity-fill" style="width:${count ? Math.max((count / max) * 100, 8) : 0}%"></div></div>
      <b>${count}</b>
    </div>
  `).join("");
}

function renderMatrix(summary) {
  const categories = [...new Set(state.rules.map((rule) => rule.category).filter(Boolean))].slice(0, 6);
  if (!categories.length) categories.push(...CATEGORIES);
  let header = `<div class="matrix-grid header"><span>NF</span>${categories.map((category) => `<span>${escapeHtml(category)}</span>`).join("")}</div>`;
  const activeNF = summary?.network_function;
  const currentFindings = state.currentScan?.findings || [];
  const applicableRules = activeNF ? state.rules.filter((rule) => rule.target_nf === "ALL" || rule.target_nf === activeNF) : [];
  const rows = NFs.map((nf) => {
    const cells = categories.map((category) => {
      let className = "";
      if (nf === activeNF) {
        const categoryFindings = currentFindings.filter((finding) => finding.category === category);
        const categoryRules = applicableRules.filter((rule) => rule.category === category);
        if (categoryFindings.some((finding) => finding.severity === "CRITICAL")) className = "red";
        else if (categoryFindings.some((finding) => ["HIGH", "MEDIUM"].includes(finding.severity))) className = "amber";
        else if (categoryRules.length) className = "green";
      }
      const categoryFindings = nf === activeNF ? currentFindings.filter((finding) => finding.category === category) : [];
      const weights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
      const highest = [...categoryFindings].sort((a, b) => (weights[b.severity] || 0) - (weights[a.severity] || 0))[0]?.severity || "None";
      const ruleIds = categoryFindings.map((finding) => finding.rule_id).join(", ") || "None";
      return `<i class="matrix-cell ${className}" data-nf="${nf}" data-category="${escapeHtml(category)}" title="${nf} · ${escapeHtml(category)} · ${categoryFindings.length} findings · Highest: ${highest} · Rules: ${escapeHtml(ruleIds)}"></i>`;
    }).join("");
    return `<div class="matrix-grid matrix-row" data-nf="${nf}"><strong>${nf}</strong>${cells}</div>`;
  }).join("");
  $("#nfMatrix").innerHTML = header + rows;
  $$(".matrix-row").forEach((row) => row.addEventListener("click", () => selectNode(row.dataset.nf)));
  $$(".matrix-cell").forEach((cell) => cell.addEventListener("click", (event) => {
    event.stopPropagation();
    const finding = (state.currentScan?.findings || []).find((item) =>
      item.target_nf === cell.dataset.nf && item.category === cell.dataset.category
    );
    if (finding) openFinding(finding);
    else selectNode(cell.dataset.nf);
  }));
}

function renderTrend() {
  const nf = state.currentScan?.summary?.network_function;
  const comparable = nf
    ? state.historyDetails.filter((entry) => entry.summary?.network_function === nf)
    : [];

  if (!comparable.length) {
    $("#trendChart").innerHTML = `<div class="analytics-empty"><strong>No comparable trend</strong><span>Load a scanned network function to begin a comparison.</span></div>`;
    return;
  }
  if (comparable.length < 2) {
    $("#trendChart").innerHTML = `<div class="analytics-empty"><strong>More scans required to display a trend.</strong><span>Comparable ${escapeHtml(nf)} scan history has 1 record.</span></div>`;
    return;
  }
  const values = comparable.map((entry) => Number(entry.summary.security_score));
  const width = 420, height = 105, pad = 8;
  const points = values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : pad + (index / (values.length - 1)) * (width - pad * 2);
    const y = height - pad - (value / 100) * (height - pad * 2);
    return [x, y];
  });
  const line = points.map((point) => point.join(",")).join(" ");
  const area = `${pad},${height} ${line} ${width - pad},${height}`;
  $("#trendChart").innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
    <polygon class="area" points="${area}"></polygon>
    <polyline points="${line}"></polyline>
  </svg>`;
}

function renderTopRisks() {
  const findings = state.currentScan?.findings || [];
  const weights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
  const ranked = [...findings].sort((a, b) =>
    (weights[b.severity] || 0) - (weights[a.severity] || 0) ||
    String(a.rule_id).localeCompare(String(b.rule_id))
  ).slice(0, 5);
  if (!ranked.length) {
    $("#riskList").innerHTML = `<div class="analytics-empty"><strong>No ranked risks</strong><span>The selected scan contains no findings.</span></div>`;
    return;
  }
  $("#riskList").innerHTML = ranked.map((finding, index) => `
    <button class="risk-row" data-rule-id="${escapeHtml(finding.rule_id)}">
      <span class="risk-index">${String(index + 1).padStart(2, "0")}</span>
      <span class="risk-copy"><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.target_nf)} · ${escapeHtml(finding.category)}</small></span>
      <span class="severity-pill ${finding.severity.toLowerCase()}">${escapeHtml(finding.severity)}</span>
    </button>
  `).join("");
  $$(".risk-row").forEach((row) => row.addEventListener("click", () =>
    openFinding(findings.find((finding) => finding.rule_id === row.dataset.ruleId))
  ));
}

function renderCategoryChart() {
  const findings = state.currentScan?.findings || [];
  if (!findings.length) {
    $("#categoryChart").innerHTML = `<div class="analytics-empty"><strong>No categories flagged</strong><span>No findings in the selected scan.</span></div>`;
    return;
  }
  const weights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
  const groups = {};
  findings.forEach((finding) => {
    const category = finding.category || "Uncategorized";
    if (!groups[category]) groups[category] = [];
    groups[category].push(finding);
  });
  const categories = Object.entries(groups).sort((a, b) =>
    b[1].length - a[1].length ||
    a[0].localeCompare(b[0])
  );
  const max = Math.max(...categories.map(([, items]) => items.length));
  $("#categoryChart").innerHTML = categories.map(([category, items]) => {
    const highest = [...items].sort((a, b) => (weights[b.severity] || 0) - (weights[a.severity] || 0))[0].severity;
    const percentage = (items.length / findings.length) * 100;
    return `<button class="category-row" data-category="${escapeHtml(category)}" title="${escapeHtml(category)}: ${items.length} findings · ${percentage.toFixed(1)}% · Highest ${highest}">
      <span class="category-name">${escapeHtml(category)}</span>
      <span class="category-track"><i style="width:${(items.length / max) * 100}%"></i></span>
      <strong>${items.length} · ${percentage.toFixed(0)}%</strong>
      <small>${highest}</small>
    </button>`;
  }).join("");
  $$(".category-row").forEach((row) => row.addEventListener("click", () => {
    const first = findings.find((finding) => finding.category === row.dataset.category);
    if (first) openFinding(first);
  }));
}

function renderRuleCoverage() {
  const nf = state.currentScan?.summary?.network_function;
  const catalog = state.rules || [];
  const applicable = nf ? catalog.filter((rule) => rule.target_nf === "ALL" || rule.target_nf === nf) : [];
  const evaluated = Number(state.currentScan?.summary?.total_rules_checked || 0);
  const triggered = state.currentScan?.findings?.length || 0;
  const nonApplicable = catalog.length - applicable.length;
  const notEvaluated = Math.max(applicable.length - evaluated, 0);
  const noFinding = Math.max(evaluated - triggered, 0);
  $("#coverageMeta").textContent = `${catalog.length} RULES`;
  if ($("#coverageCount")) $("#coverageCount").textContent = `${catalog.length} AVAILABLE`;
  if (!catalog.length) {
    $("#coverageChart").innerHTML = `<div class="analytics-empty"><strong>Coverage unavailable</strong><span>The rule catalog is unavailable.</span></div>`;
    return;
  }
  const segments = [
    ["Evaluated", noFinding, "var(--secondary-text)"],
    ["Triggered", triggered, "var(--red)"],
    ["Not evaluated", notEvaluated, "var(--border)"],
    ["Not applicable", nonApplicable, "var(--muted)"]
  ];
  const total = segments.reduce((sum, [, count]) => sum + count, 0) || 1;
  $("#coverageChart").innerHTML = `
    <div class="coverage-summary"><span><strong>${catalog.length}</strong>Total</span><span><strong>${applicable.length}</strong>Applicable</span><span><strong>${evaluated}</strong>Evaluated</span><span><strong>${triggered}</strong>Triggered</span></div>
    <div class="coverage-bar" title="Evaluated, triggered, not evaluated, and not applicable rule counts">
      ${segments.map(([, count, color]) => `<i style="width:${(count / total) * 100}%;background:${color}" title="${count}"></i>`).join("")}
    </div>
    <div class="coverage-legend">${segments.map(([label, count]) => `<span><i style="background:${label === "Triggered" ? "var(--red)" : label === "Evaluated" ? "var(--secondary-text)" : "var(--border)"}"></i>${label} ${count}</span>`).join("")}</div>
  `;
}

function renderFrequencyChart() {
  const counts = {};
  state.historyDetails.forEach((scan) => {
    const unique = new Map();
    (scan.findings || []).forEach((finding) => unique.set(finding.rule_id, finding));
    unique.forEach((finding, ruleId) => {
      if (!counts[ruleId]) counts[ruleId] = { count: 0, title: finding.title, nfs: new Set() };
      counts[ruleId].count += 1;
      counts[ruleId].nfs.add(finding.target_nf);
    });
  });
  const ranked = Object.entries(counts).sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0])).slice(0, 5);
  if (!ranked.length) {
    $("#frequencyChart").innerHTML = `<div class="analytics-empty"><strong>No rule frequency</strong><span>Occurrences across available scan history.</span></div>`;
    return;
  }
  const max = ranked[0][1].count;
  $("#frequencyChart").innerHTML = ranked.map(([ruleId, item]) => `
    <div class="frequency-row" title="Occurrences across available scan history">
      <span><strong>${escapeHtml(ruleId)}</strong><small>${escapeHtml([...item.nfs].join(", "))}</small></span>
      <i><b style="width:${(item.count / max) * 100}%"></b></i>
      <strong>${item.count}</strong>
    </div>
  `).join("");
}

function renderActivityTimeline() {
  if (!state.history.length) {
    $("#activityTimeline").innerHTML = `<div class="analytics-empty"><strong>No activity</strong><span>Scan completions appear here.</span></div>`;
    return;
  }
  $("#activityTimeline").innerHTML = state.history.slice(0, 8).map((entry) => {
    const detail = state.historyDetails.find((scan) => scan.scan_id === entry.scan_id);
    const nf = detail?.summary?.network_function || "Unknown";
    return `<button class="activity-row" data-scan-id="${escapeHtml(entry.scan_id)}">
      <i></i><span><strong>${escapeHtml(nf)}</strong><small>${escapeHtml(entry.filename)}</small></span>
      <span class="activity-metrics"><strong>${entry.total_findings ?? 0}</strong><small>${detail ? `${detail.summary.security_score}/100` : "Score unavailable"}</small></span>
      <time>${formatTime(entry.scanned_at)}</time>
    </button>`;
  }).join("");
  $$(".activity-row").forEach((row) => row.addEventListener("click", () => loadScan(row.dataset.scanId)));
}

function renderRemediation() {
  const findings = state.currentScan?.findings || [];
  if (!findings.length) {
    $("#remediationList").innerHTML = `<div class="analytics-empty"><strong>No recommendations</strong><span>The selected scan contains no backend remediation records.</span></div>`;
    return;
  }
  const priorities = [
    ["Immediate", "CRITICAL"], ["High Priority", "HIGH"], ["Planned", "MEDIUM"], ["Hardening", "LOW"]
  ];
  $("#remediationList").innerHTML = priorities.map(([label, severity]) => {
    const items = findings.filter((finding) => finding.severity === severity);
    if (!items.length) return "";
    return `<div class="remediation-group"><label>${label} · ${items.length}</label>${items.map((finding) => `
      <button class="remediation-row" data-rule-id="${escapeHtml(finding.rule_id)}">
        <span><strong>${escapeHtml(finding.rule_id)}</strong><small>${escapeHtml(finding.title)}</small></span>
        <i>${escapeHtml(finding.target_nf)}</i>
      </button>
    `).join("")}</div>`;
  }).join("");
  $$(".remediation-row").forEach((row) => row.addEventListener("click", () =>
    openFinding(findings.find((finding) => finding.rule_id === row.dataset.ruleId))
  ));
}

function renderHistory() {
  if (!state.history.length) {
    $("#historyList").innerHTML = `<div class="last-scan">No completed scans</div>`;
  } else {
    $("#historyList").innerHTML = state.history.slice(0, 5).map((entry) => `
      <div class="history-entry" data-scan-id="${escapeHtml(entry.scan_id)}" title="Load scan ${escapeHtml(entry.scan_id)}">
        <div><strong>${escapeHtml(entry.filename)}</strong><span>${escapeHtml(entry.file_type)} · ${formatTime(entry.scanned_at)}</span></div>
        <div class="history-score"><b>${entry.total_findings ?? 0}</b><small>findings</small></div>
      </div>
    `).join("");
  }
  $$(".history-entry").forEach((entry) => entry.addEventListener("click", () => loadScan(entry.dataset.scanId)));

  if (!state.history.length) {
    $("#historyTable").innerHTML = `<div class="inspector-body">No scan records are available.</div>`;
    return;
  }
  $("#historyTable").innerHTML = `
    <div class="history-table-row header"><strong>Filename</strong><span>Type</span><span>Scanned</span><span>Findings</span><span></span></div>
    ${state.history.map((entry) => `
      <div class="history-table-row" data-scan-id="${escapeHtml(entry.scan_id)}">
        <strong>${escapeHtml(entry.filename)}</strong>
        <span>${escapeHtml(entry.file_type)}</span>
        <span>${formatTime(entry.scanned_at)}</span>
        <span>C ${entry.critical_count || 0} · H ${entry.high_count || 0}</span>
        <button class="delete-button" data-delete="${escapeHtml(entry.scan_id)}" title="Delete scan">×</button>
      </div>
    `).join("")}
  `;
  $$(".history-table-row[data-scan-id]").forEach((row) => row.addEventListener("click", (event) => {
    if (!event.target.closest("[data-delete]")) loadScan(row.dataset.scanId);
  }));
  $$("[data-delete]").forEach((button) => button.addEventListener("click", async (event) => {
    event.stopPropagation();
    if (!confirm("Delete this scan record?")) return;
    try {
      await api(`/api/scan/${encodeURIComponent(button.dataset.delete)}`, { method: "DELETE" });
      await loadHistory();
      toast("Scan record deleted");
    } catch (error) {
      toast(error.message);
    }
  }));
}

async function loadScan(scanId) {
  try {
    const scan = await api(`/api/scan/${encodeURIComponent(scanId)}`);
    state.currentScan = scan;
    renderHealth(scan.summary);
    $("#lastScan").textContent = formatTime(scan.scanned_at);
    closeModal();
    toast(`Loaded ${scan.filename}`);
  } catch (error) {
    toast(error.message);
  }
}

const topologyPositions = {
  AMF: [450, 160], SMF: [280, 330], UPF: [620, 330],
  NRF: [450, 350], AUSF: [280, 530], UDM: [620, 530]
};

function createTopology() {
  const nodeGroup = $("#nodes");
  const connectionGroup = $("#connections");
  const connections = [
    ["AMF", "NRF"], ["AMF", "SMF"], ["SMF", "UPF"], ["SMF", "NRF"],
    ["NRF", "AUSF"], ["NRF", "UDM"], ["AUSF", "AMF"], ["UDM", "SMF"],
    ["UPF", "UDM"], ["AUSF", "UDM"]
  ];
  connectionGroup.innerHTML = connections.map(([a, b]) => {
    const pa = topologyPositions[a], pb = topologyPositions[b];
    const d = `M${pa[0]} ${pa[1]} C${(pa[0] + pb[0]) / 2} ${pa[1]}, ${(pa[0] + pb[0]) / 2} ${pb[1]}, ${pb[0]} ${pb[1]}`;
    return `<path class="connection-line" data-a="${a}" data-b="${b}" d="${d}"></path>`;
  }).join("");

  nodeGroup.innerHTML = NFs.map((nf) => {
    const [x, y] = topologyPositions[nf];
    const points = Array.from({ length: 24 }, (_, i) => {
      const angle = (i / 24) * Math.PI * 2;
      const radius = i % 3 === 0 ? 39 : 31 + (i % 4) * 2;
      return `<circle cx="${(Math.cos(angle) * radius).toFixed(1)}" cy="${(Math.sin(angle) * radius).toFixed(1)}" r="${i % 4 === 0 ? 1.3 : 0.8}"></circle>`;
    }).join("");
    return `<g class="node-group" data-nf="${nf}" transform="translate(${x} ${y})">
      <circle class="node-selected-ring" r="58"></circle>
      <circle class="node-halo" r="48"></circle>
      <circle class="node-halo" r="43" stroke-dasharray="1 6"></circle>
      <circle class="node-core" r="34"></circle>
      <g class="node-points" transform="translate(0 0)">${points}</g>
      <text class="node-label" y="-3">${nf}</text>
      <text class="node-status" y="11">UNKNOWN</text>
      <circle class="node-indicator" cx="26" cy="-24" r="3"></circle>
      <text class="node-count" y="51">NO DATA</text>
    </g>`;
  }).join("");

  $$(".node-group").forEach((node) => {
    node.addEventListener("mouseenter", () => highlightNode(node.dataset.nf));
    node.addEventListener("mouseleave", () => clearHighlights());
    node.addEventListener("click", () => selectNode(node.dataset.nf));
  });
}

function highlightNode(nf) {
  $$(".connection-line").forEach((line) => line.classList.toggle("hot", line.dataset.a === nf || line.dataset.b === nf));
  showNodeTooltip(nf);
}

function clearHighlights() {
  $$(".connection-line").forEach((line) => line.classList.remove("hot"));
  hideNodeTooltip();
}

function showNodeTooltip(nf) {
  let tooltip = $(".node-tooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "node-tooltip";
    document.body.appendChild(tooltip);
  }
  const findings = state.currentScan?.findings?.filter((finding) => finding.target_nf === nf) || [];
  tooltip.innerHTML = `<strong>${nf}</strong><br>${findings.length ? `${findings.length} finding${findings.length === 1 ? "" : "s"}` : "No findings in current scan"}`;
  tooltip.classList.add("visible");
  document.addEventListener("mousemove", positionTooltip);
  positionTooltip();
}

function positionTooltip(event) {
  const tooltip = $(".node-tooltip");
  if (!tooltip) return;
  const x = event?.clientX ?? innerWidth / 2;
  const y = event?.clientY ?? innerHeight / 2;
  tooltip.style.left = `${x + 12}px`;
  tooltip.style.top = `${y + 12}px`;
}

function hideNodeTooltip() {
  const tooltip = $(".node-tooltip");
  if (tooltip) tooltip.classList.remove("visible");
  document.removeEventListener("mousemove", positionTooltip);
}

function updateTopology(summary) {
  const nf = summary?.network_function;
  const findings = state.currentScan?.findings || [];
  $$(".node-group").forEach((node) => {
    const name = node.dataset.nf;
    const nodeFindings = findings.filter((finding) => finding.target_nf === name || (finding.target_nf === "ALL" && name === nf));
    const status = node.querySelector(".node-status");
    const count = node.querySelector(".node-count");
    const indicator = node.querySelector(".node-indicator");
    indicator.className = "node-indicator";
    indicator.style.fill = "var(--muted)";
    if (name === nf) {
      status.textContent = summary.status === "CLEAN" ? "SECURE" : "FINDINGS";
      count.textContent = `${summary.total_findings ?? 0} FINDINGS`;
      const hasCritical = nodeFindings.some((finding) => finding.severity === "CRITICAL");
      indicator.style.fill = hasCritical ? "var(--red)" : (nodeFindings.length ? "var(--amber)" : "var(--green)");
      const core = node.querySelector(".node-core");
      if (state.mode === "risk") {
        if (hasCritical) core.style.stroke = "var(--red)";
        else if (nodeFindings.length) core.style.stroke = "var(--amber)";
        else core.style.stroke = "var(--green)";
      } else {
        core.style.stroke = "";
      }
    } else {
      status.textContent = "UNKNOWN";
      count.textContent = "NO DATA";
    }
  });
}

function selectNode(nf) {
  state.selectedNode = nf;
  $$(".node-group").forEach((node) => {
    node.classList.toggle("selected", node.dataset.nf === nf);
    node.classList.toggle("dimmed", node.dataset.nf !== nf);
  });
  openNodeInspector(nf);
}

function openNodeInspector(nf) {
  const findings = (state.currentScan?.findings || []).filter((finding) => finding.target_nf === nf || (finding.target_nf === "ALL" && state.currentScan?.summary?.network_function === nf));
  const isCurrent = state.currentScan?.summary?.network_function === nf;
  const severity = (name) => findings.filter((finding) => finding.severity === name).length;
  const applicableCount = isCurrent ? (state.currentScan.summary.total_rules_checked ?? "—") : "—";
  const topFinding = [...findings].sort((a, b) => ({CRITICAL:10,HIGH:7,MEDIUM:4,LOW:1}[b.severity] || 0) - ({CRITICAL:10,HIGH:7,MEDIUM:4,LOW:1}[a.severity] || 0))[0];
  $("#inspectorEyebrow").textContent = "NETWORK FUNCTION";
  $("#inspectorTitle").textContent = nf;
  $("#inspectorContent").innerHTML = `
    <div class="inspector-body">
      <div class="finding-meta">
        <div><span>Security score</span><strong>${isCurrent ? (state.currentScan.summary.security_score ?? "—") + " / 100" : "NOT AVAILABLE"}</strong></div>
        <div><span>Detected findings</span><strong>${findings.length}</strong></div>
        <div><span>Applicable rules evaluated</span><strong>${applicableCount}</strong></div>
        <div><span>Status</span><strong>${isCurrent ? state.currentScan.summary.status : "NOT EVALUATED"}</strong></div>
        <div><span>Critical / High</span><strong>${severity("CRITICAL")} / ${severity("HIGH")}</strong></div>
        <div><span>Medium / Low</span><strong>${severity("MEDIUM")} / ${severity("LOW")}</strong></div>
      </div>
      ${topFinding ? `<div class="inspector-block"><label>Top vulnerability</label><p><strong>${escapeHtml(topFinding.title)}</strong><br>${escapeHtml(topFinding.description)}</p></div><div class="inspector-block"><label>Recommended action</label><p>${escapeHtml(topFinding.remediation)}</p></div>` : `<div class="inspector-block"><label>Top vulnerability</label><p>${isCurrent ? "No vulnerability flagged in the current scan." : "Not scanned."}</p></div>`}
      <div class="inspector-block">
        <label>Detected vulnerabilities</label>
        ${findings.length ? findings.map((finding) => `
          <button class="export-option finding-link" data-rule-id="${escapeHtml(finding.rule_id)}" style="width:100%;margin:0 0 8px;">
            <span>${escapeHtml(finding.rule_id)} · ${escapeHtml(finding.severity)}</span>
            <small>${escapeHtml(finding.title)}</small>
          </button>
        `).join("") : `<p>No per-component findings are available from the current scan.</p>`}
      </div>
    </div>
  `;
  $("#inspector").classList.add("open");
  $$(".finding-link").forEach((button) => button.addEventListener("click", () => openFinding(findings.find((finding) => finding.rule_id === button.dataset.ruleId))));
}

function openFinding(finding) {
  if (!finding) return;
  const nf = finding.target_nf === "ALL" ? state.currentScan?.summary?.network_function : finding.target_nf;
  const comparable = state.historyDetails
    .filter((scan) => scan.scan_id !== state.currentScan?.scan_id && scan.summary?.network_function === nf)
    .sort((a, b) => new Date(b.scanned_at || 0) - new Date(a.scanned_at || 0));
  const previous = comparable[0];
  let comparison = "";
  if (previous) {
    const previousIds = new Set((previous.findings || []).map((item) => item.rule_id));
    const currentIds = new Set((state.currentScan?.findings || []).map((item) => item.rule_id));
    const resolved = [...previousIds].filter((id) => !currentIds.has(id));
    const newlyDetected = [...currentIds].filter((id) => !previousIds.has(id));
    const unchanged = [...currentIds].filter((id) => previousIds.has(id));
    comparison = `<div class="inspector-block"><label>Comparable scan differences</label><div class="comparison-grid">
      <div><span>Resolved rule IDs</span><strong>${resolved.length ? escapeHtml(resolved.join(", ")) : "None"}</strong></div>
      <div><span>Newly detected</span><strong>${newlyDetected.length ? escapeHtml(newlyDetected.join(", ")) : "None"}</strong></div>
      <div><span>Unchanged findings</span><strong>${unchanged.length ? escapeHtml(unchanged.join(", ")) : "None"}</strong></div>
    </div><p>Differences between comparable ${escapeHtml(nf)} scans; this does not verify that a configuration change was applied.</p></div>`;
  } else {
    comparison = `<div class="inspector-block"><label>Comparable scan differences</label><p>No earlier ${escapeHtml(nf)} scan is available in history.</p></div>`;
  }
  $("#inspectorEyebrow").textContent = escapeHtml(finding.rule_id);
  $("#inspectorTitle").textContent = escapeHtml(finding.title);
  $("#inspectorContent").innerHTML = `
    <div class="inspector-body">
      <div class="finding-meta">
        <div><span>Severity</span><strong>${escapeHtml(finding.severity)}</strong></div>
        <div><span>Network function</span><strong>${escapeHtml(finding.target_nf)}</strong></div>
        <div><span>Category</span><strong>${escapeHtml(finding.category)}</strong></div>
        <div><span>Rule ID</span><strong>${escapeHtml(finding.rule_id)}</strong></div>
      </div>
      <div class="inspector-block"><label>Technical description</label><p>${escapeHtml(finding.description)}</p></div>
      <div class="inspector-block"><label>Security implications</label><p>${escapeHtml(finding.description)}</p></div>
      <div class="inspector-block"><label>Suggested fix</label><div class="fix-code">${escapeHtml(finding.remediation)}</div><button class="copy-button" id="copyFix">Copy Fix</button></div>
      ${comparison}
    </div>
  `;
  $("#inspector").classList.add("open");
  $("#copyFix").addEventListener("click", async () => {
    await navigator.clipboard?.writeText(finding.remediation);
    toast("Remediation copied");
  });
}

function renderRuleTable() {
  const nf = $("#ruleNF")?.value || "";
  const severity = $("#ruleSeverity")?.value || "";
  const search = ($("#ruleSearch")?.value || "").toLowerCase();
  const filtered = state.rules.filter((rule) =>
    (!nf || rule.target_nf === nf || rule.target_nf === "ALL") &&
    (!severity || rule.severity === severity) &&
    (!search || `${rule.rule_id} ${rule.title} ${rule.category} ${rule.description}`.toLowerCase().includes(search))
  );
  if (!filtered.length) {
    $("#ruleTable").innerHTML = `<div class="inspector-body">No rules match the selected filters.</div>`;
    return;
  }
  $("#ruleTable").innerHTML = `
    <div class="rule-row header"><strong>Rule ID</strong><strong>Title</strong><strong>Severity</strong><strong>Target NF</strong><strong class="header-category">Description</strong></div>
    ${filtered.map((rule) => `
      <div class="rule-row">
        <strong>${escapeHtml(rule.rule_id)}</strong>
        <p><strong>${escapeHtml(rule.title)}</strong></p>
        <span class="severity-pill">${escapeHtml(rule.severity)}</span>
        <strong>${escapeHtml(rule.target_nf)}</strong>
        <p>${escapeHtml(rule.description)}</p>
      </div>
    `).join("")}
  `;
  const nfSelect = $("#ruleNF");
  if (nfSelect && nfSelect.options.length === 1) {
    NFs.forEach((name) => nfSelect.add(new Option(name, name)));
  }
}

function openModal(id) {
  $$(".modal.open").forEach((modal) => modal.classList.remove("open"));
  $("#" + id)?.classList.add("open");
}

function closeModal() {
  $$(".modal.open").forEach((modal) => modal.classList.remove("open"));
}

function setTheme(theme) {
  document.documentElement.classList.toggle("light", theme !== "dark");
  document.documentElement.classList.toggle("dark", theme === "dark");
  localStorage.setItem("susignal-theme", theme);
}

function setCamera() {
  $("#camera").style.transform = `scale(${state.zoom})`;
}

let selectedUpload = null;

function selectUpload(file) {
  if (!file) return;
  const ext = file.name.toLowerCase();
  if (!/\.(yaml|yml|json)$/.test(ext)) {
    toast("Unsupported format. Use YAML or JSON.");
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    toast("File exceeds the 5 MB limit.");
    return;
  }
  selectedUpload = file;
  $("#selectedFilename").textContent = file.name;
  if ($("#fileMeta")) $("#fileMeta").textContent = `${ext.split(".").pop().toUpperCase()} · ${(file.size / 1024).toFixed(1)} KB`;
  $("#startScan").disabled = false;
  $("#scanState").textContent = "Ready to analyze";
}

async function startScan() {
  if (!selectedUpload) return;
  const button = $("#startScan");
  button.disabled = true;
  button.textContent = "Scanning...";
  $("#progressTrack").classList.add("active");
  $("#canvasScanline").classList.add("scanning");
  $("#scanState").textContent = "Uploading configuration";
  const form = new FormData();
  form.append("file", selectedUpload);
  try {
    const scan = await api("/api/scan/upload", { method: "POST", body: form });
    state.currentScan = scan;
    $("#scanState").textContent = `Complete · ${scan.summary.total_findings} findings`;
    renderHealth(scan.summary);
    $("#lastScan").textContent = "Just now";
    await loadHistory();
    toast(`Scan complete · ${scan.summary.security_score}/100`);
  } catch (error) {
    $("#scanState").textContent = error.message;
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Start Scan";
    $("#progressTrack").classList.remove("active");
    $("#canvasScanline").classList.remove("scanning");
  }
}

async function selectSample(filename) {
  if (!filename) {
    selectedUpload = null;
    $("#startScan").disabled = true;
    return;
  }
  try {
    const response = await fetch(`/sample_configs/${encodeURIComponent(filename)}`);
    if (!response.ok) throw new Error("Sample configuration could not be loaded.");
    const blob = await response.blob();
    const file = new File([blob], filename, { type: filename.endsWith(".json") ? "application/json" : "application/yaml" });
    selectUpload(file);
  } catch (error) {
    toast(error.message);
  }
}

function printReport() {
  if (!state.currentScan) {
    toast("Run or load a scan before exporting.");
    return;
  }
  const scan = state.currentScan;
  const findings = scan.findings || [];
  const html = `<!doctype html><html><head><title>SUSignal Report</title><style>
    body{font-family:Arial,sans-serif;color:#171717;margin:48px}h1{font-size:28px}h2{font-size:15px;margin-top:32px}
    table{width:100%;border-collapse:collapse}th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:12px}
    .meta{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.meta div{border:1px solid #ddd;padding:12px}
  </style></head><body><h1>SUSignal Security Report</h1><p>Detect weaknesses. Secure connections.</p>
  <div class="meta"><div><strong>File</strong><br>${escapeHtml(scan.filename)}</div><div><strong>Security score</strong><br>${scan.summary.security_score}/100</div><div><strong>Scan ID</strong><br>${escapeHtml(scan.scan_id)}</div></div>
  <h2>Findings</h2><table><thead><tr><th>Rule</th><th>Title</th><th>Severity</th><th>Network Function</th><th>Remediation</th></tr></thead><tbody>
  ${findings.map((finding) => `<tr><td>${escapeHtml(finding.rule_id)}</td><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.target_nf)}</td><td>${escapeHtml(finding.remediation)}</td></tr>`).join("")}
  </tbody></table></body></html>`;
  const reportWindow = window.open("", "_blank");
  reportWindow.document.write(html);
  reportWindow.document.close();
  reportWindow.print();
}

function downloadJson() {
  if (!state.currentScan) {
    toast("Run or load a scan before exporting.");
    return;
  }
  const blob = new Blob([JSON.stringify(state.currentScan, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `susignal-${state.currentScan.scan_id}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function showPage(id) {
  $$(".page").forEach((page) => page.classList.remove("active"));
  $("#" + id)?.classList.add("active");
}

function showUtilityPage(page) {
  showPage("utilityPage");
  const titles = {
    rules: "RULE CATALOG",
    findings: "SECURITY FINDINGS",
    remediation: "REMEDIATION CENTER",
    history: "SCAN HISTORY",
    reports: "REPORTS",
    analytics: "RISK ANALYTICS",
    settings: "SETTINGS"
  };
  $("#utilityTitle").textContent = titles[page] || "SECURITY";
  $("#pageTitle").textContent = titles[page] || "SECURITY";

  if (page === "rules") {
    openModal("catalogModal");
  } else if (page === "history") {
    openModal("historyModal");
  } else if (page === "reports") {
    openModal("exportModal");
  } else if (page === "findings") {
    const findings = state.currentScan?.findings || [];
    $("#utilityContent").innerHTML = findings.length ? `
      <div class="rule-table findings-table">
        <div class="rule-row header"><strong>RULE ID</strong><strong>VULNERABILITY</strong><strong>SEVERITY</strong><strong>NETWORK</strong><strong>ACTION</strong></div>
        ${findings.map((finding) => `<div class="rule-row"><strong>${escapeHtml(finding.rule_id)}</strong><p>${escapeHtml(finding.title)}</p><span class="severity-pill ${finding.severity.toLowerCase()}">${escapeHtml(finding.severity)}</span><strong>${escapeHtml(finding.target_nf)}</strong><button class="secondary-action finding-open" data-rule-id="${escapeHtml(finding.rule_id)}">DETAIL</button></div>`).join("")}
      </div>` : `<div class="analytics-empty"><strong>NO FINDINGS AVAILABLE</strong><span>Run or select a scan to populate security findings.</span></div>`;
    $$(".finding-open").forEach((button) => button.addEventListener("click", () => openFinding(findings.find((finding) => finding.rule_id === button.dataset.ruleId))));
  } else if (page === "remediation") {
    renderRemediation();
    $("#utilityContent").innerHTML = `<div class="chart-card"><div class="chart-header"><div><span>R</span><h3>REMEDIATION INTELLIGENCE</h3></div><small>BACKEND-PROVIDED GUIDANCE</small></div><div class="remediation-list" id="remediationListUtility"></div></div>`;
    const target = $("#remediationListUtility");
    target.innerHTML = $("#remediationList")?.innerHTML || `<div class="analytics-empty"><strong>NO RECOMMENDATIONS</strong></div>`;
  } else if (page === "analytics") {
    $("#utilityContent").innerHTML = `<div class="analytics-grid" style="grid-template-columns:1fr 1fr"><section class="chart-card"><div class="chart-header"><div><span>A</span><h3>VULNERABILITY CATEGORIES</h3></div></div><div class="category-chart" id="categoryChartUtility"></div></section><section class="chart-card"><div class="chart-header"><div><span>B</span><h3>RULE FREQUENCY</h3></div></div><div class="frequency-chart" id="frequencyChartUtility"></div></section></div>`;
    const originalCategory = $("#categoryChart");
    $("#categoryChartUtility").innerHTML = originalCategory?.innerHTML || "";
  } else if (page === "settings") {
    $("#utilityContent").innerHTML = `<div class="chart-card"><div class="chart-header"><div><span>S</span><h3>APPEARANCE</h3></div></div><button class="primary-action" id="utilityTheme">TOGGLE DARK / LIGHT</button></div>`;
    $("#utilityTheme").addEventListener("click", () => setTheme(document.documentElement.classList.contains("dark") ? "light" : "dark"));
  }
}

function bindEvents() {
  $("#themeToggle").addEventListener("click", () => setTheme(document.documentElement.classList.contains("dark") ? "light" : "dark"));
  $("#openScan").addEventListener("click", () => $("#scanPanel").classList.add("open"));
  $("#browseButton").addEventListener("click", () => $("#fileInput").click());
  $("#fileInput").addEventListener("change", (event) => selectUpload(event.target.files[0]));
  $("#sampleSelect").addEventListener("change", (event) => selectSample(event.target.value));
  $("#startScan").addEventListener("click", startScan);
  const dropZone = $("#dropZone");
  ["dragenter", "dragover"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  }));
  ["dragleave", "drop"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  }));
  dropZone.addEventListener("drop", (event) => selectUpload(event.dataTransfer.files[0]));

  $$("[data-close]").forEach((button) => button.addEventListener("click", () => {
    if (button.classList.contains("modal-backdrop")) {
      $("#" + button.dataset.close)?.classList.remove("open");
    } else {
      $("#" + button.dataset.close)?.classList.remove("open");
    }
  }));
  $$("[data-view]").forEach((button) => button.addEventListener("click", () => {
    const view = button.dataset.view;
    $$(".nav-tab").forEach((tab) => tab.classList.toggle("active", tab === button));
    if (view === "rules") openModal("catalogModal");
    if (view === "history") openModal("historyModal");
  }));
  $$("[data-view-trigger]").forEach((button) => button.addEventListener("click", () => openModal("historyModal")));
  $("#exportButton").addEventListener("click", () => openModal("exportModal"));
  $("#downloadJson").addEventListener("click", downloadJson);
  $("#printReport").addEventListener("click", printReport);
  $("#ruleSearch").addEventListener("input", renderRuleTable);
  $("#ruleNF").addEventListener("change", renderRuleTable);
  $("#ruleSeverity").addEventListener("change", renderRuleTable);
  $("#severityView").querySelectorAll("button").forEach((button) => button.addEventListener("click", () => {
    state.severityView = button.dataset.severityView;
    $$("#severityView button").forEach((item) => item.classList.toggle("active", item === button));
    renderSeverity(state.currentScan?.summary || {});
  }));
  $("#zoomIn").addEventListener("click", () => { state.zoom = Math.min(1.8, state.zoom + .15); setCamera(); });
  $("#zoomOut").addEventListener("click", () => { state.zoom = Math.max(.7, state.zoom - .15); setCamera(); });
  $("#fitView").addEventListener("click", () => { state.zoom = 1; setCamera(); });
  $("#toggleLabels").addEventListener("click", () => {
    state.labels = !state.labels;
    $$(".node-label, .node-status, .node-count").forEach((label) => label.style.display = state.labels ? "" : "none");
  });
  $("#modeToolbar").querySelectorAll("button").forEach((button) => button.addEventListener("click", () => {
    state.mode = button.dataset.mode;
    $$("#modeToolbar button").forEach((item) => item.classList.toggle("active", item === button));
    $$(".connection-line").forEach((line) => line.style.opacity = state.mode === "connections" ? "1" : "");
    updateTopology(state.currentScan?.summary);
  }));
  $$("#canvasViews button").forEach((button) => button.addEventListener("click", () => {
    $$("#canvasViews button").forEach((item) => item.classList.toggle("active", item === button));
    if (button.textContent.includes("Finding")) openModal("historyModal");
  }));
  $("#sidebarCollapse").addEventListener("click", () => {
    $("#sidebar").classList.toggle("collapsed");
    $(".app-shell").classList.toggle("sidebar-collapsed");
  });
  $("#mobileMenu").addEventListener("click", () => $("#sidebar").classList.toggle("mobile-open"));
  $("#newScanButton").addEventListener("click", () => $("#scanPanel").classList.add("open"));
  $("#settingsButton").addEventListener("click", () => setTheme(document.documentElement.classList.contains("dark") ? "light" : "dark"));
  $$(".nav-item").forEach((item) => item.addEventListener("click", () => {
    $$(".nav-item").forEach((nav) => nav.classList.remove("active"));
    item.classList.add("active");
    const page = item.dataset.page;
    $("#sidebar").classList.remove("mobile-open");
    if (page === "topology") {
      showPage("topologyPage");
      $("#pageTitle").textContent = "NETWORK TOPOLOGY";
    } else if (page === "scanner") {
      $("#scanPanel").classList.add("open");
      showPage("overviewPage");
    } else if (["rules", "findings", "remediation", "history", "reports", "analytics", "settings"].includes(page)) {
      showUtilityPage(page);
    } else {
      showPage("overviewPage");
      $("#pageTitle").textContent = "SECURITY DASHBOARD";
    }
  }));
  $("#scanFilter").addEventListener("change", (event) => {
    if (event.target.value) loadScan(event.target.value);
  });
  window.addEventListener("resize", setCamera);
}

async function init() {
  setTheme(localStorage.getItem("susignal-theme") || "light");
  $("#scanPanel")?.classList.remove("open");
  $("#inspector")?.classList.remove("open");
  createTopology();
  bindEvents();
  renderHealth(null);
  renderHistory();
  await Promise.all([checkBackend(), loadRules(), loadHistory()]);
  renderTrend();
  if (state.history.length) await loadScan(state.history[0].scan_id);
}

init();
