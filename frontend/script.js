// Real DDoS/Honeypot Alert Data from API
let allAlerts = [];
let currentPage = 1;
const itemsPerPage = 10;
let filteredAttacks = [];

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  loadRealAlerts();
  setupEventListeners();
  setupLiveStreaming();
});

// Load real alerts from the backend
async function loadRealAlerts() {
  try {
    const response = await fetch("/api/alerts");
    const data = await response.json();

    // Transform real alert data to match table format
    allAlerts = data.map((alert) => ({
      timestamp: new Date(alert.detected_at || alert.window_start),
      pkts: alert.pkts || 0,
      unique_srcs: alert.unique_srcs || 0,
      entropy_src: alert.entropy_src || 0,
      probability: alert.probability || 0,
      top_srcs: alert.top_srcs || {},
      predicted_label: alert.predicted_label || 0,
      status:
        alert.predicted_label === 1 || alert.probability > 0.8
          ? "attacked"
          : "normal",
    }));

    filteredAttacks = [...allAlerts];
    updateStatistics();
    updateAttackTable();
    initTimelineChart();
    initTopSourcesChart();
    initProbabilityChart();
    updateIOCs();

    console.log("[v0] Loaded", allAlerts.length, "real alerts from API");
  } catch (error) {
    console.log("[v0] Error loading alerts:", error);
    // Fallback to sample data if API unavailable
    loadSampleAlerts();
  }
}

// Sample data for demo/offline mode
function loadSampleAlerts() {
  const sampleAlerts = [
    {
      timestamp: new Date(Date.now() - 2000000),
      pkts: 1250,
      unique_srcs: 12,
      entropy_src: 3.2,
      probability: 0.92,
      top_srcs: { "192.168.1.100": 120, "10.0.0.50": 85 },
      predicted_label: 1,
      status: "attacked",
    },
    {
      timestamp: new Date(Date.now() - 1800000),
      pkts: 890,
      unique_srcs: 8,
      entropy_src: 2.8,
      probability: 0.78,
      top_srcs: { "203.0.113.45": 156 },
      predicted_label: 1,
      status: "attacked",
    },
    {
      timestamp: new Date(Date.now() - 1600000),
      pkts: 2100,
      unique_srcs: 25,
      entropy_src: 4.1,
      probability: 0.95,
      top_srcs: { "172.16.0.25": 200, "198.51.100.12": 98 },
      predicted_label: 1,
      status: "attacked",
    },
    {
      timestamp: new Date(Date.now() - 1400000),
      pkts: 450,
      unique_srcs: 5,
      entropy_src: 1.9,
      probability: 0.45,
      top_srcs: { "10.0.0.51": 450 },
      predicted_label: 0,
      status: "normal",
    },
    {
      timestamp: new Date(Date.now() - 1200000),
      pkts: 1680,
      unique_srcs: 18,
      entropy_src: 3.7,
      probability: 0.88,
      top_srcs: { "192.0.2.33": 245 },
      predicted_label: 1,
      status: "attacked",
    },
    {
      timestamp: new Date(Date.now() - 1000000),
      pkts: 520,
      unique_srcs: 6,
      entropy_src: 2.1,
      probability: 0.55,
      top_srcs: { "203.0.113.46": 520 },
      predicted_label: 0,
      status: "normal",
    },
    {
      timestamp: new Date(Date.now() - 800000),
      pkts: 3200,
      unique_srcs: 32,
      entropy_src: 4.5,
      probability: 0.97,
      top_srcs: { "10.0.0.52": 312, "172.16.0.26": 289 },
      predicted_label: 1,
      status: "attacked",
    },
    {
      timestamp: new Date(Date.now() - 600000),
      pkts: 780,
      unique_srcs: 9,
      entropy_src: 2.6,
      probability: 0.72,
      top_srcs: { "192.168.1.102": 780 },
      predicted_label: 1,
      status: "attacked",
    },
    {
      timestamp: new Date(Date.now() - 400000),
      pkts: 1450,
      unique_srcs: 15,
      entropy_src: 3.4,
      probability: 0.85,
      top_srcs: { "10.0.0.53": 450, "203.0.113.47": 320 },
      predicted_label: 1,
      status: "attacked",
    },
    {
      timestamp: new Date(Date.now() - 200000),
      pkts: 380,
      unique_srcs: 4,
      entropy_src: 1.6,
      probability: 0.38,
      top_srcs: { "198.51.100.13": 380 },
      predicted_label: 0,
      status: "normal",
    },
  ];

  allAlerts = sampleAlerts;
  filteredAttacks = [...allAlerts];
}

// Stream live alerts using Server-Sent Events
function setupLiveStreaming() {
  try {
    const eventSource = new EventSource("/stream");
    eventSource.onmessage = (event) => {
      try {
        const alert = JSON.parse(event.data);
        const newAlert = {
          timestamp: new Date(alert.detected_at || alert.window_start),
          pkts: alert.pkts || 0,
          unique_srcs: alert.unique_srcs || 0,
          entropy_src: alert.entropy_src || 0,
          probability: alert.probability || 0,
          top_srcs: alert.top_srcs || {},
          predicted_label: alert.predicted_label || 0,
          status:
            alert.predicted_label === 1 || alert.probability > 0.8
              ? "attacked"
              : "normal",
        };

        allAlerts.unshift(newAlert);
        filteredAttacks = [...allAlerts];
        updateStatistics();
        updateAttackTable();
        initTimelineChart();
        initTopSourcesChart();
        initProbabilityChart();
        updateIOCs();

        console.log("[v0] New alert received via stream");
      } catch (e) {
        console.log("[v0] Error parsing stream alert:", e);
      }
    };

    eventSource.onerror = () => {
      console.log("[v0] Stream connection error");
      eventSource.close();
    };
  } catch (error) {
    console.log("[v0] Stream not available:", error);
  }
}

// Event Listeners
function setupEventListeners() {
  document.getElementById("timeRange").addEventListener("change", (e) => {
    filterByTimeRange(e.target.value);
  });

  document.getElementById("exportBtn").addEventListener("click", exportIOCs);
  document
    .getElementById("reportBtn")
    .addEventListener("click", generatePDFReport);
  document.getElementById("clearBtn").addEventListener("click", clearAlerts);
  document.getElementById("prevPage").addEventListener("click", previousPage);
  document.getElementById("nextPage").addEventListener("click", nextPage);
}

// Filter by Time Range
function filterByTimeRange(range) {
  const now = Date.now();
  let startTime;

  switch (range) {
    case "24h":
      startTime = now - 24 * 60 * 60 * 1000;
      break;
    case "7d":
      startTime = now - 7 * 24 * 60 * 60 * 1000;
      break;
    case "30d":
      startTime = now - 30 * 24 * 60 * 60 * 1000;
      break;
    default:
      startTime = 0;
  }

  filteredAttacks = allAlerts.filter(
    (alert) => alert.timestamp.getTime() >= startTime,
  );
  currentPage = 1;
  updateStatistics();
  updateAttackTable();
  initTimelineChart();
  initTopSourcesChart();
  initProbabilityChart();
  updateIOCs();
}

// Update Statistics
function updateStatistics() {
  const totalAlerts = filteredAttacks.length;
  const detectedAttacks = filteredAttacks.filter(
    (a) => a.status === "attacked",
  ).length;
  const totalPackets = filteredAttacks.reduce((sum, a) => sum + a.pkts, 0);
  const avgProbability =
    filteredAttacks.length > 0
      ? (
          (filteredAttacks.reduce((sum, a) => sum + a.probability, 0) /
            filteredAttacks.length) *
          100
        ).toFixed(2)
      : 0;

  // Extract all source IPs from top_srcs
  const allSrcs = [];
  filteredAttacks.forEach((alert) => {
    if (alert.top_srcs && typeof alert.top_srcs === "object") {
      Object.keys(alert.top_srcs).forEach((ip) => {
        allSrcs.push(ip);
      });
    }
  });

  const uniqueAttackers = new Set(allSrcs).size;
  const topAttacker = getTopItem(allSrcs);

  document.getElementById("totalAttacks").textContent = totalAlerts;
  document.getElementById("uniqueAttackers").textContent = uniqueAttackers;
  document.getElementById("topUsername").textContent =
    detectedAttacks + " detected";
  document.getElementById("topPassword").textContent = avgProbability + "%";
}

function getTopItem(items) {
  if (items.length === 0) return null;
  const counts = {};
  items.forEach((item) => {
    counts[item] = (counts[item] || 0) + 1;
  });
  return Object.keys(counts).reduce((a, b) => (counts[a] > counts[b] ? a : b));
}

// Update Attack Table with DDoS alert data
function updateAttackTable() {
  const tbody = document.getElementById("attackTable");
  const start = (currentPage - 1) * itemsPerPage;
  const end = start + itemsPerPage;
  const pageAttacks = filteredAttacks.slice(start, end);

  tbody.innerHTML = pageAttacks
    .map((alert) => {
      const topSrc = alert.top_srcs ? Object.keys(alert.top_srcs)[0] : "N/A";
      return `
            <tr>
                <td>${alert.timestamp.toLocaleString()}</td>
                <td><code>${topSrc}</code></td>
                <td>${alert.pkts} pkts</td>
                <td><code>${(alert.probability * 100).toFixed(1)}%</code></td>
                <td><span class="status ${alert.status}">${alert.status.toUpperCase()}</span></td>
            </tr>
        `;
    })
    .join("");

  updatePagination();
}

function updatePagination() {
  const totalPages = Math.ceil(filteredAttacks.length / itemsPerPage);
  document.getElementById("pageInfo").textContent =
    `Page ${currentPage} of ${totalPages}`;
  document.getElementById("prevPage").disabled = currentPage === 1;
  document.getElementById("nextPage").disabled = currentPage === totalPages;
}

function previousPage() {
  if (currentPage > 1) {
    currentPage--;
    updateAttackTable();
  }
}

function nextPage() {
  const totalPages = Math.ceil(filteredAttacks.length / itemsPerPage);
  if (currentPage < totalPages) {
    currentPage++;
    updateAttackTable();
  }
}

// Timeline Chart
let timelineChartInstance;
function initTimelineChart() {
  const attacksByMinute = getAttacksByMinute();
  const labels = Object.keys(attacksByMinute).sort();
  const data = labels.map((label) => attacksByMinute[label]);

  const ctx = document.getElementById("timelineChart").getContext("2d");

  if (timelineChartInstance) {
    timelineChartInstance.destroy();
  }

  timelineChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: labels,
      datasets: [
        {
          label: "Attacks per Minute",
          data: data,
          borderColor: "#06b6d4",
          backgroundColor: "rgba(6, 182, 212, 0.1)",
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointBackgroundColor: "#06b6d4",
          pointBorderColor: "#0a0e27",
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          labels: { color: "#e0e0ff", font: { size: 12 } },
        },
      },
      scales: {
        y: {
          ticks: { color: "#9ca3af" },
          grid: { color: "#1e293b" },
          beginAtZero: true,
        },
        x: {
          ticks: { color: "#9ca3af" },
          grid: { color: "#1e293b" },
        },
      },
    },
  });
}

function getAttacksByMinute() {
  const grouped = {};
  filteredAttacks.forEach((attack) => {
    const minute = new Date(attack.timestamp);
    minute.setSeconds(0, 0);
    const key = minute.toLocaleTimeString();
    grouped[key] = (grouped[key] || 0) + 1;
  });
  return grouped;
}

// Top Source IPs Chart
let sourceChartInstance;
function initTopSourcesChart() {
  const srcs = [];
  filteredAttacks.forEach((alert) => {
    if (alert.top_srcs && typeof alert.top_srcs === "object") {
      Object.entries(alert.top_srcs).forEach(([ip, count]) => {
        srcs.push({ ip, count });
      });
    }
  });

  // Aggregate counts by IP
  const ipCounts = {};
  srcs.forEach(({ ip, count }) => {
    ipCounts[ip] = (ipCounts[ip] || 0) + count;
  });

  const sortedSrcs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const ctx = document.getElementById("usernameChart").getContext("2d");

  if (sourceChartInstance) {
    sourceChartInstance.destroy();
  }

  sourceChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: sortedSrcs.map(([ip]) => ip),
      datasets: [
        {
          label: "Packets",
          data: sortedSrcs.map(([, count]) => count),
          backgroundColor: "#4f46e5",
          borderColor: "#06b6d4",
          borderWidth: 1,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { labels: { color: "#e0e0ff", font: { size: 12 } } },
      },
      scales: {
        y: { ticks: { color: "#e0e0ff" }, grid: { color: "#1e293b" } },
        x: { ticks: { color: "#9ca3af" }, grid: { color: "#1e293b" } },
      },
    },
  });
}

// Probability Distribution Chart
let probabilityChartInstance;
function initProbabilityChart() {
  const probabilities = filteredAttacks.map((a) => a.probability);
  const bins = { low: 0, medium: 0, high: 0, critical: 0 };

  probabilities.forEach((p) => {
    if (p < 0.3) bins.low++;
    else if (p < 0.6) bins.medium++;
    else if (p < 0.8) bins.high++;
    else bins.critical++;
  });

  const ctx = document.getElementById("passwordChart").getContext("2d");

  if (probabilityChartInstance) {
    probabilityChartInstance.destroy();
  }

  probabilityChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: [
        "Low (0-30%)",
        "Medium (30-60%)",
        "High (60-80%)",
        "Critical (80-100%)",
      ],
      datasets: [
        {
          data: [bins.low, bins.medium, bins.high, bins.critical],
          backgroundColor: ["#10b981", "#f59e0b", "#ef4444", "#8b1a1a"],
          borderColor: "#0a0e27",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { labels: { color: "#e0e0ff", font: { size: 12 } } },
      },
    },
  });
}

// Update IOCs - Display malicious source IPs and high-probability attacks
function updateIOCs() {
  const maliciousIPs = [];
  const highProbAttacks = [];

  filteredAttacks.forEach((alert) => {
    if (alert.top_srcs && typeof alert.top_srcs === "object") {
      Object.keys(alert.top_srcs).forEach((ip) => maliciousIPs.push(ip));
    }
    if (alert.probability > 0.8) {
      highProbAttacks.push({
        timestamp: alert.timestamp,
        probability: alert.probability,
        pkts: alert.pkts,
        srcs: alert.unique_srcs,
      });
    }
  });

  const uniqueIPs = [...new Set(maliciousIPs)];

  const ipsContainer = document.getElementById("maliciousIPs");
  ipsContainer.innerHTML = uniqueIPs
    .slice(0, 20)
    .map((ip) => `<div class="ioc-item">${ip}</div>`)
    .join("");

  const credsContainer = document.getElementById("credentials");
  credsContainer.innerHTML = highProbAttacks
    .slice(0, 20)
    .map(
      (attack) =>
        `<div class="ioc-item">${attack.timestamp.toLocaleTimeString()} - ${(attack.probability * 100).toFixed(1)}% (${attack.pkts} pkts)</div>`,
    )
    .join("");
}

// Export IOCs as JSON
function exportIOCs() {
  const maliciousIPs = [];

  filteredAttacks.forEach((alert) => {
    if (alert.top_srcs && typeof alert.top_srcs === "object") {
      Object.keys(alert.top_srcs).forEach((ip) => maliciousIPs.push(ip));
    }
  });

  const uniqueIPs = [...new Set(maliciousIPs)];
  const highProbAttacks = filteredAttacks.filter((a) => a.probability > 0.8);

  const iocs = {
    exportDate: new Date().toISOString(),
    totalAlerts: filteredAttacks.length,
    detectedAttacks: highProbAttacks.length,
    maliciousSourceIPs: uniqueIPs,
    highProbabilityAlerts: highProbAttacks.map((a) => ({
      timestamp: a.timestamp.toISOString(),
      probability: (a.probability * 100).toFixed(2) + "%",
      packets: a.pkts,
      uniqueSources: a.unique_srcs,
      topSource: a.top_srcs ? Object.keys(a.top_srcs)[0] : "N/A",
    })),
    uniqueAttackers: uniqueIPs.length,
    analysisTimeRange: {
      start:
        filteredAttacks.length > 0
          ? filteredAttacks[filteredAttacks.length - 1].timestamp.toISOString()
          : null,
      end:
        filteredAttacks.length > 0
          ? filteredAttacks[0].timestamp.toISOString()
          : null,
    },
  };

  const dataStr = JSON.stringify(iocs, null, 2);
  const dataBlob = new Blob([dataStr], { type: "application/json" });
  const url = URL.createObjectURL(dataBlob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `honeypot-iocs-${new Date().toISOString().split("T")[0]}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

// Generate PDF Report for DDoS/Honeypot Detection
function generatePDFReport() {
  const maliciousIPs = [];
  filteredAttacks.forEach((alert) => {
    if (alert.top_srcs && typeof alert.top_srcs === "object") {
      Object.keys(alert.top_srcs).forEach((ip) => maliciousIPs.push(ip));
    }
  });

  const uniqueIPs = [...new Set(maliciousIPs)];
  const detectedAttacks = filteredAttacks.filter(
    (a) => a.status === "attacked",
  );
  const avgProbability =
    filteredAttacks.length > 0
      ? (
          (filteredAttacks.reduce((sum, a) => sum + a.probability, 0) /
            filteredAttacks.length) *
          100
        ).toFixed(2)
      : 0;

  const reportWindow = window.open("", "_blank");
  reportWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Honeypot Detection Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
                h1 { color: #4f46e5; border-bottom: 2px solid #06b6d4; padding-bottom: 10px; }
                h2 { color: #06b6d4; margin-top: 30px; }
                table { width: 100%; border-collapse: collapse; margin: 15px 0; }
                th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f0f0f0; font-weight: bold; }
                .stat { display: inline-block; margin: 15px 30px 15px 0; }
                .stat-label { font-weight: bold; color: #4f46e5; }
                .stat-value { font-size: 24px; color: #06b6d4; }
                .critical { color: #ef4444; font-weight: bold; }
            </style>
        </head>
        <body>
            <h1>Honeypot Distribution - DDoS Detection Report</h1>
            <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
            
            <h2>Summary Statistics</h2>
            <div class="stat">
                <div class="stat-label">Total Alerts</div>
                <div class="stat-value">${filteredAttacks.length}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Detected Attacks</div>
                <div class="stat-value critical">${detectedAttacks.length}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Detection Accuracy</div>
                <div class="stat-value">${avgProbability}%</div>
            </div>
            <div class="stat">
                <div class="stat-label">Unique Sources</div>
                <div class="stat-value">${uniqueIPs.length}</div>
            </div>

            <h2>Malicious Source IPs</h2>
            <table>
                <thead><tr><th>IP Address</th><th>Detected Attacks</th><th>Avg Probability</th></tr></thead>
                <tbody>
                    ${uniqueIPs
                      .slice(0, 50)
                      .map((ip) => {
                        const alertsFromIP = filteredAttacks.filter((a) => {
                          if (!a.top_srcs || typeof a.top_srcs !== "object")
                            return false;
                          return ip in a.top_srcs;
                        });
                        const avgProb =
                          alertsFromIP.length > 0
                            ? (
                                (alertsFromIP.reduce(
                                  (sum, a) => sum + a.probability,
                                  0,
                                ) /
                                  alertsFromIP.length) *
                                100
                              ).toFixed(1)
                            : 0;
                        return `<tr><td>${ip}</td><td>${alertsFromIP.length}</td><td>${avgProb}%</td></tr>`;
                      })
                      .join("")}
                </tbody>
            </table>

            <h2>High Probability Alerts (>80%)</h2>
            <table>
                <thead><tr><th>Timestamp</th><th>Probability</th><th>Packets</th><th>Unique Sources</th><th>Top Source</th></tr></thead>
                <tbody>
                    ${detectedAttacks
                      .slice(0, 30)
                      .map(
                        (alert) =>
                          `<tr><td>${alert.timestamp.toLocaleString()}</td><td><span class="critical">${(alert.probability * 100).toFixed(1)}%</span></td><td>${alert.pkts}</td><td>${alert.unique_srcs}</td><td>${alert.top_srcs ? Object.keys(alert.top_srcs)[0] : "N/A"}</td></tr>`,
                      )
                      .join("")}
                </tbody>
            </table>

            <h2>Detection Model Metrics</h2>
            <div class="stat">
                <div class="stat-label">Total Alerts Processed</div>
                <div class="stat-value">${filteredAttacks.length}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Attack Detection Rate</div>
                <div class="stat-value">${((detectedAttacks.length / filteredAttacks.length) * 100).toFixed(1)}%</div>
            </div>
            <div class="stat">
                <div class="stat-label">Avg Detection Confidence</div>
                <div class="stat-value">${avgProbability}%</div>
            </div>
        </body>
        </html>
    `);
  reportWindow.document.close();
  setTimeout(() => reportWindow.print(), 500);
}

// Clear Alerts
function clearAlerts() {
  if (
    confirm(
      "Are you sure you want to clear all alerts? This action cannot be undone.",
    )
  ) {
    allAlerts.length = 0;
    filteredAttacks = [];
    currentPage = 1;
    updateStatistics();
    updateAttackTable();
    initTimelineChart();
    initTopSourcesChart();
    initProbabilityChart();
    updateIOCs();
    alert("All alerts have been cleared.");
  }
}
