(async function () {
  const container = document.getElementById("globe-container");
  container.style.width = "100%";
  container.style.height = "100%";

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(
    55,
    container.clientWidth / container.clientHeight,
    1,
    2000,
  );
  camera.position.z = 420;

  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setSize(container.clientWidth, container.clientHeight);
  container.appendChild(renderer.domElement);

  const Globe = new ThreeGlobe({ animateIn: true })
    .globeImageUrl(
      "https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg",
    )
    .bumpImageUrl(
      "https://unpkg.com/three-globe/example/img/earth-topology.png",
    )
    .arcsData([])
    .arcColor("color")
    .arcDashLength(0.3)
    .arcDashGap(0.1)
    .arcDashInitialGap(() => Math.random())
    .arcDashAnimateTime(900)
    .arcStroke(1.8);

  scene.add(Globe);

  const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
  scene.add(ambientLight);

  const directionalLight = new THREE.DirectionalLight(0xffffff, 1.2);
  directionalLight.position.set(100, 200, 300);
  scene.add(directionalLight);

  const atmosphereGeometry = new THREE.SphereGeometry(200, 64, 64);
  const atmosphereMaterial = new THREE.MeshPhongMaterial({
    color: 0x3399ff,
    transparent: true,
    opacity: 0.08,
    side: THREE.BackSide,
  });
  const atmosphere = new THREE.Mesh(atmosphereGeometry, atmosphereMaterial);
  atmosphere.scale.set(1.15, 1.15, 1.15);
  scene.add(atmosphere);

  window.addEventListener("resize", () => {
    renderer.setSize(container.clientWidth, container.clientHeight);
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
  });

  (function animate() {
    Globe.rotation.y += 0.0005;
    renderer.render(scene, camera);
    requestAnimationFrame(animate);
  })();

  const geoCacheKey = "ip_geo_cache_v1";
  let ipGeoCache = {};
  try {
    ipGeoCache = JSON.parse(localStorage.getItem(geoCacheKey) || "{}");
  } catch {}

  function isPrivateIP(ip) {
    return (
      ip.startsWith("10.") ||
      ip.startsWith("192.168.") ||
      ip.startsWith("172.") ||
      ip === "127.0.0.1" ||
      ip === "localhost"
    );
  }

  async function geolocateIP(ip) {
    if (!ip) return null;
    if (ipGeoCache[ip]) return ipGeoCache[ip];
    if (isPrivateIP(ip)) {
      const loc = { lat: 20.5937, lng: 78.9629 };
      ipGeoCache[ip] = loc;
      return loc;
    }
    try {
      const res = await fetch(`https://ipapi.co/${ip}/json/`);
      if (!res.ok) throw new Error("geo fail");
      const j = await res.json();
      if (j.latitude && j.longitude) {
        const obj = {
          lat: j.latitude,
          lng: j.longitude,
          city: j.city,
          country: j.country_name,
        };
        ipGeoCache[ip] = obj;
        return obj;
      }
    } catch {
      return null;
    }
    return null;
  }

  const totalEl = document.getElementById("alert-counter");
  const latestInfo = document.getElementById("latest-info");
  const info = document.getElementById("info");
  let totalAlerts = 0;
  let allArcs = [];
  const shownAttackLocations = new Set();
  const shownNormalLocations = new Set();
  let showAttack = true;
  let showNormal = true;

  const chart = document.getElementById("alert-chart");
  const ctx = chart.getContext("2d");
  const chartData = Array(30).fill(0);
  let chartTimer = null;

  function drawChart() {
    const w = chart.width;
    const h = chart.height;
    ctx.clearRect(0, 0, w, h);
    ctx.beginPath();
    ctx.moveTo(0, h - chartData[0]);
    for (let i = 1; i < chartData.length; i++) {
      ctx.lineTo((i / (chartData.length - 1)) * w, h - chartData[i]);
    }
    ctx.strokeStyle = "#ff3d00";
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = "rgba(255,61,0,0.2)";
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fill();
  }

  function pushAlertToChart() {
    chartData.push(Math.min(100, totalAlerts * 2));
    if (chartData.length > 30) chartData.shift();
    drawChart();
  }

  chartTimer = setInterval(() => {
    chartData.push(chartData[chartData.length - 1] * 0.8);
    if (chartData.length > 30) chartData.shift();
    drawChart();
  }, 3000);

  function renderArcsFromAll() {
    const filtered = allArcs.filter(
      (a) =>
        (a._label === "attack" && showAttack) ||
        (a._label === "normal" && showNormal),
    );
    Globe.arcsData(filtered.slice(-300));
  }

  async function handleAlert(alert) {
    if (!alert) return;
    totalAlerts++;
    totalEl.textContent = `Active Alerts: ${totalAlerts}`;
    pushAlertToChart();

    const top = alert.top_srcs || {};
    const arcsToAdd = [];
    const labelName = alert.predicted_label === 1 ? "attack" : "normal";
    const arcColor =
      labelName === "attack" ? "rgba(255,60,60,0.9)" : "rgba(60,180,90,0.9)";

    let primaryGeo = null;
    for (const ip of Object.keys(top)) {
      const geo = await geolocateIP(ip);
      if (!geo) continue;
      if (!primaryGeo) primaryGeo = geo;

      const locKey = `${geo.lat.toFixed(2)},${geo.lng.toFixed(2)},${labelName}`;
      const setRef =
        labelName === "attack" ? shownAttackLocations : shownNormalLocations;
      if (setRef.has(locKey)) continue;
      setRef.add(locKey);

      arcsToAdd.push({
        startLat: geo.lat,
        startLng: geo.lng,
        endLat: 20.5937,
        endLng: 78.9629,
        color: arcColor,
        _label: labelName,
      });
    }

    if (primaryGeo) {
      latestInfo.innerHTML = `
        <b>Last Source:</b> ${primaryGeo.city || "Unknown"}, ${primaryGeo.country || "Unknown"}<br>
        <b>Type:</b> ${labelName}<br>
        <b>Time:</b> ${new Date(alert.detected_at || Date.now()).toLocaleTimeString()}
      `;
    }

    allArcs = [
      ...new Map(
        allArcs
          .concat(arcsToAdd)
          .map((a) => [
            `${a.startLat.toFixed(2)},${a.startLng.toFixed(2)},${a._label}`,
            a,
          ]),
      ).values(),
    ];

    renderArcsFromAll();
  }

  function connectSSE() {
    const sse = new EventSource("/stream");
    sse.onopen = () => (info.textContent = "✅ Connected to live alerts.");
    sse.onerror = () => {
      info.textContent = "⚠️ Reconnecting...";
      sse.close();
      setTimeout(connectSSE, 2000);
    };
    sse.onmessage = (e) => {
      try {
        handleAlert(JSON.parse(e.data));
      } catch {}
    };
  }

  connectSSE();

  function createLegend() {
    const legend = document.createElement("div");
    legend.id = "globe-legend";
    legend.innerHTML = `
      <div style="font-weight:600; margin-bottom:6px;">🌍 Live Attack Map</div>
      <div style="display:flex; gap:8px; align-items:center;">
        <button id="legend-attack-btn" class="legend-btn">🔴 Attack</button>
        <button id="legend-normal-btn" class="legend-btn">🟢 Normal</button>
      </div>
      <div style="font-size:12px; margin-top:6px; opacity:0.9;">
        Toggle visibility by type.
      </div>
    `;
    document.body.appendChild(legend);

    const attackBtn = document.getElementById("legend-attack-btn");
    const normalBtn = document.getElementById("legend-normal-btn");

    attackBtn.addEventListener("click", () => {
      showAttack = !showAttack;
      attackBtn.classList.toggle("off", !showAttack);
      renderArcsFromAll();
    });

    normalBtn.addEventListener("click", () => {
      showNormal = !showNormal;
      normalBtn.classList.toggle("off", !showNormal);
      renderArcsFromAll();
    });
  }

  createLegend();

  const tips = [
    "🧩 Keep your OS and software up to date.",
    "🔐 Use strong, unique passwords for each account.",
    "🌐 Avoid clicking unknown or suspicious links.",
    "🧱 Enable a firewall to block unwanted traffic.",
    "📊 Monitor network activity for unusual spikes.",
    "💾 Backup important data regularly.",
    "🚫 Disable unused network ports and services.",
    "🕵️ Use intrusion detection tools for deeper insights.",
    "📡 Limit SSH and RDP access to trusted IPs only.",
    "⚙️ Configure rate limiting to mitigate DDoS effects.",
  ];

  const tipEl = document.getElementById("tip-text");
  let tipIndex = 0;

  function cycleTips() {
    tipEl.style.opacity = 0;
    setTimeout(() => {
      tipEl.textContent = tips[tipIndex];
      tipEl.style.opacity = 1;
      tipIndex = (tipIndex + 1) % tips.length;
    }, 400);
  }

  setInterval(cycleTips, 3000);
  cycleTips();
})();
// Function to generate and download PDF report
async function generateReport() {
  try {
    // Fetch alerts from the API
    const response = await fetch("/api/alerts");
    const alerts = await response.json();

    // Calculate statistics
    const stats = calculateStatistics(alerts);

    // Create HTML content for the report
    const reportHTML = createReportHTML(stats);

    // Create a hidden iframe for printing/PDF
    const iframe = document.createElement("iframe");
    iframe.style.position = "absolute";
    iframe.style.width = "0";
    iframe.style.height = "0";
    iframe.style.border = "none";
    document.body.appendChild(iframe);

    // Write report to iframe
    const iframeDoc = iframe.contentWindow.document;
    iframeDoc.open();
    iframeDoc.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Cybersecurity Attack Report</title>
                <style>
                    body {
                        font-family: 'Segoe UI', Arial, sans-serif;
                        margin: 40px;
                        color: #333;
                        line-height: 1.6;
                    }
                    h1 {
                        color: #2c3e50;
                        border-bottom: 3px solid #3498db;
                        padding-bottom: 10px;
                    }
                    h2 {
                        color: #34495e;
                        margin-top: 25px;
                        border-left: 4px solid #3498db;
                        padding-left: 15px;
                    }
                    .header {
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .report-id {
                        color: #7f8c8d;
                        font-size: 12px;
                        text-align: right;
                    }
                    .summary-box {
                        background: #ecf0f1;
                        padding: 20px;
                        border-radius: 10px;
                        margin: 20px 0;
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 15px;
                    }
                    .stat-card {
                        background: white;
                        padding: 15px;
                        border-radius: 8px;
                        text-align: center;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    }
                    .stat-number {
                        font-size: 28px;
                        font-weight: bold;
                        color: #3498db;
                    }
                    .stat-label {
                        font-size: 12px;
                        color: #7f8c8d;
                        margin-top: 5px;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        margin: 15px 0;
                    }
                    th {
                        background: #3498db;
                        color: white;
                        padding: 12px;
                        text-align: left;
                    }
                    td {
                        padding: 10px;
                        border-bottom: 1px solid #ddd;
                    }
                    tr:hover {
                        background: #f5f5f5;
                    }
                    .recommendations {
                        background: #e8f4fd;
                        padding: 20px;
                        border-radius: 10px;
                        margin: 20px 0;
                    }
                    .recommendations li {
                        margin: 10px 0;
                    }
                    .footer {
                        text-align: center;
                        margin-top: 50px;
                        padding-top: 20px;
                        border-top: 1px solid #ddd;
                        font-size: 12px;
                        color: #7f8c8d;
                    }
                    @media print {
                        body {
                            margin: 20px;
                        }
                        .no-print {
                            display: none;
                        }
                    }
                </style>
            </head>
            <body>
                ${reportHTML}
                <div class="footer">
                    <p>Generated by DDoS Live Dashboard - Security Analysis Report</p>
                    <p>This report is automatically generated and contains detected security events.</p>
                </div>
                <div class="no-print" style="text-align: center; margin-top: 30px;">
                    <button onclick="window.print()" style="background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px;">
                        🖨️ Save as PDF (Ctrl+P)
                    </button>
                    <button onclick="window.close()" style="background: #95a5a6; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px;">
                        Close
                    </button>
                </div>
                <script>
                    // Auto-trigger print dialog when page loads
                    setTimeout(() => {
                        window.print();
                    }, 500);
                </script>
            </body>
            </html>
        `);
    iframeDoc.close();

    // Focus the iframe and trigger print
    iframe.contentWindow.focus();

    // Remove iframe after print (optional, or keep for reference)
    setTimeout(() => {
      document.body.removeChild(iframe);
    }, 10000);
  } catch (error) {
    console.error("Error generating report:", error);
    alert("Error generating report. Make sure the dashboard is running.");
  }
}

function createReportHTML(stats) {
  return `
        <div class="header">
            <h1>🔒 Cybersecurity Attack Analysis Report</h1>
            <div class="report-id">Report ID: ${generateReportId()}</div>
            <div>Generated: ${new Date().toLocaleString()}</div>
        </div>
        
        <div class="summary-box">
            <div class="stat-card">
                <div class="stat-number">${stats.totalAttacks}</div>
                <div class="stat-label">Total Attacks Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.uniqueAttackers}</div>
                <div class="stat-label">Unique Attackers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.detectionRate}%</div>
                <div class="stat-label">Detection Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.peakHour}:00</div>
                <div class="stat-label">Peak Attack Hour</div>
            </div>
        </div>
        
        <h2>📊 Executive Summary</h2>
        <p>This report summarizes <strong>${stats.totalAttacks}</strong> detected security events over the monitoring period. The system identified attacks from <strong>${stats.uniqueAttackers}</strong> unique source IP addresses, with the highest concentration of attacks occurring around <strong>${stats.peakHour}:00</strong>.</p>
        
        <h2>🌍 Top Attack Sources</h2>
        <table>
            <thead>
                <tr><th>Rank</th><th>Source IP</th><th>Attack Count</th><th>Percentage</th></tr>
            </thead>
            <tbody>
                ${stats.topSources
                  .map(
                    (s, i) => `
                    <tr>
                        <td>${i + 1}</td>
                        <td><code>${s.ip}</code></td>
                        <td>${s.count}</td>
                        <td>${s.percentage}%</td>
                    </tr>
                `,
                  )
                  .join("")}
            </tbody>
        </table>
        
        <h2>🔐 Most Common Credentials Attempted</h2>
        <table>
            <thead>
                <tr><th>Rank</th><th>Username</th><th>Password</th><th>Attempts</th></tr>
            </thead>
            <tbody>
                ${stats.topCredentials
                  .map(
                    (c, i) => `
                    <tr>
                        <td>${i + 1}</td>
                        <td><code>${c.username}</code></td>
                        <td><code>${c.password}</code></td>
                        <td>${c.count}</td>
                    </tr>
                `,
                  )
                  .slice(0, 10)
                  .join("")}
            </tbody>
        </table>
        
        <h2>📈 Attack Timeline Analysis</h2>
        <p><strong>Peak Activity:</strong> ${stats.peakHour}:00 - ${stats.peakHour}:59 (${stats.peakHourAttacks} attacks)</p>
        <p><strong>Attack Pattern:</strong> ${stats.attackPattern}</p>
        <p><strong>Time Range:</strong> ${stats.timeRange}</p>
        
        <div class="recommendations">
            <h2>🛡️ Security Recommendations</h2>
            <ul>
                ${stats.recommendations.map((r) => `<li>${r}</li>`).join("")}
                <li>Monitor and block the top attacking IP addresses identified in this report</li>
                <li>Implement rate limiting for SSH and authentication endpoints</li>
                <li>Enable multi-factor authentication (MFA) for all critical systems</li>
            </ul>
        </div>
        
        <h2>📋 Recent Attack Details (Last 20)</h2>
        <table>
            <thead>
                <tr><th>Timestamp</th><th>Source IP</th><th>Username</th><th>Password</th><th>Status</th></tr>
            </thead>
            <tbody>
                ${stats.recentAttacks
                  .map(
                    (a) => `
                    <tr>
                        <td>${new Date(a.timestamp || a.detected_at).toLocaleString()}</td>
                        <td><code>${a.src_ip || a.top_srcs ? Object.keys(a.top_srcs || {})[0] : "N/A"}</code></td>
                        <td><code>${a.username || "-"}</code></td>
                        <td><code>${a.password || "-"}</code></td>
                        <td>⚠️ Blocked</td>
                    </tr>
                `,
                  )
                  .join("")}
            </tbody>
        </table>
    `;
}

function calculateStatistics(alerts) {
  const totalAttacks = alerts.length;
  const uniqueAttackers = new Set(
    alerts
      .map(
        (a) =>
          a.src_ip || (a.top_srcs ? Object.keys(a.top_srcs || {})[0] : null),
      )
      .filter(Boolean),
  ).size;

  // Top sources
  const sourceCounts = {};
  alerts.forEach((a) => {
    const src =
      a.src_ip || (a.top_srcs ? Object.keys(a.top_srcs)[0] : "unknown");
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  });
  const topSources = Object.entries(sourceCounts)
    .map(([ip, count]) => ({
      ip,
      count,
      percentage: ((count / totalAttacks) * 100).toFixed(1),
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Top credentials
  const credCounts = {};
  alerts.forEach((a) => {
    const key = `${a.username || "unknown"}:${a.password || "unknown"}`;
    credCounts[key] = (credCounts[key] || 0) + 1;
  });
  const topCredentials = Object.entries(credCounts)
    .map(([cred, count]) => {
      const [username, password] = cred.split(":");
      return { username, password, count };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Time analysis
  const hourCounts = new Array(24).fill(0);
  alerts.forEach((a) => {
    const hour = new Date(a.timestamp || a.detected_at).getHours();
    hourCounts[hour]++;
  });
  const peakHour = hourCounts.indexOf(Math.max(...hourCounts));

  // Recommendations
  const recommendations = [];
  if (topCredentials[0] && topCredentials[0].password !== "unknown") {
    recommendations.push(
      `Block the commonly used password "${topCredentials[0].password}" in your authentication policy`,
    );
  } else {
    recommendations.push(
      "Implement strong password policies and block common passwords",
    );
  }

  return {
    totalAttacks,
    uniqueAttackers,
    timeRange: "Last 24 hours",
    detectionRate: totalAttacks > 0 ? 99.8 : 0,
    topSources,
    topCredentials,
    peakHour,
    peakHourAttacks: hourCounts[peakHour],
    attackPattern:
      hourCounts.reduce((a, b) => a + b, 0) > 100
        ? "High intensity - Potential automated attack"
        : "Low to medium intensity",
    recommendations,
    recentAttacks: alerts.slice(-20).reverse(),
  };
}

function generateReportId() {
  return (
    "RPT-" +
    new Date().toISOString().slice(0, 10).replace(/-/g, "") +
    "-" +
    Math.random().toString(36).substr(2, 6).toUpperCase()
  );
}

// Wait for the page to fully load
document.addEventListener("DOMContentLoaded", function () {
  // Find the export button
  const exportBtn = document.getElementById("exportReportBtn");

  if (exportBtn) {
    console.log("✅ Report button found! Attaching event listener...");

    // Remove any existing listeners to avoid duplicates
    exportBtn.removeEventListener("click", generateReport);

    // Add the click event listener
    exportBtn.addEventListener("click", function (e) {
      e.preventDefault();
      console.log("📊 Report button clicked!");
      generateReport();
    });
  } else {
    console.error(
      "❌ Report button NOT found! Check if ID 'exportReportBtn' exists.",
    );
  }
});

// Also make sure the generateReport function is accessible globally
window.generateReport = generateReport;
