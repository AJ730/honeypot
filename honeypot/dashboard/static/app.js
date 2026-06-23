/* honeypot ops console — telemetry wiring: KPIs, system gauges, live feed, charts. */
(function () {
  "use strict";

  var C = {
    real: "#36C6A0", fake: "#E0A33E", blocked: "#E0556E", accent: "#5B8DEF",
    grid: "rgba(42,52,80,.6)", tick: "#8A97B5", text: "#E6ECF7"
  };

  // ---------- helpers ----------
  function $(id) { return document.getElementById(id); }
  function fmtBytes(n) {
    if (n == null) return "—";
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(1) + " " + u[i];
  }
  function fmtUptime(s) {
    if (s == null) return "—";
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return d + "d " + h + "h"; if (h) return h + "h " + m + "m"; return m + "m";
  }
  function fmtTime(ts) {
    if (!ts) return new Date().toLocaleTimeString();
    var d = new Date(ts.replace(" ", "T"));
    return isNaN(d) ? ts : d.toLocaleTimeString();
  }
  function meterClass(el, pct) { el.classList.toggle("hot", pct >= 85); el.style.width = Math.min(100, pct || 0) + "%"; }

  // ---------- tab switching ----------
  function showTab(name) {
    document.querySelectorAll(".tab").forEach(function (t) { t.classList.toggle("active", t.dataset.tab === name); });
    document.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.toggle("active", p.id === "tab-" + name); });
    try { history.replaceState(null, "", "#" + name); } catch (e) {}
    // Charts created while hidden have zero size — resize them when revealed.
    if (name === "analytics" && window.Chart && typeof charts !== "undefined" && charts) {
      Object.keys(charts).forEach(function (k) { try { charts[k].resize(); } catch (e) {} });
    }
  }
  document.querySelectorAll(".tab").forEach(function (t) {
    t.addEventListener("click", function () { showTab(t.dataset.tab); });
  });
  var initial = (location.hash || "").slice(1);
  if (initial && document.getElementById("tab-" + initial)) showTab(initial);

  // ---------- KPIs + routing ribbon ----------
  function applyStats(s) {
    var routed = s.by_routed || {};
    var real = routed.real || 0, fake = routed.fake || 0, blocked = routed.blocked || 0;
    var tot = s.total_requests || 0;
    $("kpi-total").textContent = tot.toLocaleString();
    $("kpi-real").textContent = real.toLocaleString();
    $("kpi-fake").textContent = fake.toLocaleString();
    $("kpi-blocked").textContent = blocked.toLocaleString();
    $("kpi-ips").textContent = (s.top_source_ips || []).length;
    $("rib-real").textContent = real; $("rib-fake").textContent = fake; $("rib-blocked").textContent = blocked;
    var sum = real + fake + blocked || 1, segs = document.querySelectorAll("#routing-ribbon .seg");
    segs[0].style.width = (real / sum * 100) + "%";
    segs[1].style.width = (fake / sum * 100) + "%";
    segs[2].style.width = (blocked / sum * 100) + "%";
  }

  // ---------- system gauges ----------
  function applySystem(d) {
    if (!d || !d.available) { $("sys-cores").textContent = "metrics unavailable"; return; }
    if (d.cpu_count != null) $("sys-cores").textContent = d.cpu_count + " cores";
    if (d.cpu_percent != null) { $("cpu-val").textContent = d.cpu_percent.toFixed(0) + "%"; meterClass($("cpu-bar"), d.cpu_percent); }
    if (d.load_avg) $("load-val").textContent = "load " + d.load_avg.map(function (x) { return x.toFixed(2); }).join("  ");
    if (d.mem) {
      $("mem-val").textContent = d.mem.percent.toFixed(0) + "%"; meterClass($("mem-bar"), d.mem.percent);
      $("mem-detail").textContent = fmtBytes(d.mem.used) + " / " + fmtBytes(d.mem.total) + " · " + fmtBytes(d.mem.available) + " free";
    }
    if (d.disk) {
      $("disk-val").textContent = d.disk.percent.toFixed(0) + "%"; meterClass($("disk-bar"), d.disk.percent);
      $("disk-detail").textContent = fmtBytes(d.disk.used) + " / " + fmtBytes(d.disk.total) + " · " + fmtBytes(d.disk.free) + " free";
    }
    if (d.swap) { $("swap-val").textContent = d.swap.percent.toFixed(0) + "%"; meterClass($("swap-bar"), d.swap.percent); }
    if (d.uptime_seconds != null) $("uptime").textContent = "up " + fmtUptime(d.uptime_seconds);
  }

  // ---------- live feed (SSE) ----------
  var body = $("live-table-body"), MAX = 150;
  function badge(r) { return '<span class="badge ' + (r || "") + '">' + (r || "—") + "</span>"; }
  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }
  function extractPrompt(rawBody) {
    if (!rawBody) return "";
    try {
      var b = JSON.parse(rawBody);
      if (b.prompt != null) return String(b.prompt);
      if (Array.isArray(b.messages)) {
        var users = b.messages.filter(function (m) { return m && m.role === "user"; });
        if (users.length) return String(users[users.length - 1].content || "");
      }
      if (b.input != null) return String(b.input);   // /api/embed
      return "";
    } catch (e) { return ""; }
  }
  function addRow(row) {
    var empty = body.querySelector(".feed-empty"); if (empty) empty.remove();
    var tr = document.createElement("tr");
    tr.className = "new r-" + (row.routed || "");
    var prompt = extractPrompt(row.request_body);
    var trip = row.guardrail_trip ? ' <span class="trip mono">⛔ ' + esc(row.guardrail_trip) + "</span>" : "";
    var promptCell = prompt
      ? '<span class="prompt-text" title="' + esc(prompt) + '">' + esc(prompt) + "</span>" + trip
      : '<span class="dim">—</span>' + trip;
    tr.innerHTML =
      "<td class='mono dim nowrap'>" + esc(fmtTime(row.ts)) + "</td>" +
      "<td class='mono'>" + esc(row.source_ip) + "</td>" +
      "<td class='mono'>" + esc(row.endpoint) + "</td>" +
      "<td class='mono dim'>" + esc(row.model || "—") + "</td>" +
      "<td>" + badge(row.routed) + "</td>" +
      "<td class='prompt-col'>" + promptCell + "</td>";
    body.insertBefore(tr, body.firstChild);
    while (body.children.length > MAX) body.removeChild(body.lastChild);
  }
  try {
    var es = new EventSource("/feed");
    es.onmessage = function (e) { try { addRow(JSON.parse(e.data)); } catch (x) {} };
  } catch (x) {}

  // ---------- charts ----------
  var charts = {};
  if (window.Chart) {
    Chart.defaults.color = C.tick; Chart.defaults.font.family = "'JetBrains Mono', monospace"; Chart.defaults.font.size = 11;
  }
  function mkLine(id) {
    return new Chart($(id), { type: "line",
      data: { labels: [], datasets: [{ data: [], borderColor: C.accent, backgroundColor: "rgba(91,141,239,.12)", fill: true, tension: .3, pointRadius: 0, borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
        scales: { x: { grid: { color: C.grid }, ticks: { maxTicksLimit: 6 } }, y: { grid: { color: C.grid }, beginAtZero: true, ticks: { precision: 0 } } } } });
  }
  function mkDoughnut(id) {
    return new Chart($(id), { type: "doughnut",
      data: { labels: ["real", "faked", "blocked"], datasets: [{ data: [0, 0, 0], backgroundColor: [C.real, C.fake, C.blocked], borderColor: "#161D2E", borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: "62%", plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 12 } } } } });
  }
  function mkBar(id, color) {
    return new Chart($(id), { type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: color, borderRadius: 4, barThickness: 14 }] },
      options: { indexAxis: "y", responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
        scales: { x: { grid: { color: C.grid }, beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } } } });
  }
  if (window.Chart) {
    charts.time = mkLine("chart-time");
    charts.routing = mkDoughnut("chart-routing");
    charts.endpoints = mkBar("chart-endpoints", C.accent);
    charts.ips = mkBar("chart-ips", "#8a7bef");
  }
  function applyCharts(s) {
    if (!window.Chart) return;
    var t = s.requests_over_time || [];
    charts.time.data.labels = t.map(function (d) { return (d.bucket || "").slice(11, 16) || d.bucket; });
    charts.time.data.datasets[0].data = t.map(function (d) { return d.count; });
    charts.time.update("none");
    var r = s.by_routed || {};
    charts.routing.data.datasets[0].data = [r.real || 0, r.fake || 0, r.blocked || 0];
    charts.routing.update("none");
    var ep = (s.by_endpoint || []).slice(0, 8);
    charts.endpoints.data.labels = ep.map(function (d) { return d.endpoint; });
    charts.endpoints.data.datasets[0].data = ep.map(function (d) { return d.count; });
    charts.endpoints.update("none");
    var ips = (s.top_source_ips || []).slice(0, 8);
    charts.ips.data.labels = ips.map(function (d) { return d.source_ip; });
    charts.ips.data.datasets[0].data = ips.map(function (d) { return d.count; });
    charts.ips.update("none");
  }

  // ---------- model count KPI (from the models partial) ----------
  function updateModelCount() {
    var rows = document.querySelectorAll("#models-list table.data tbody tr");
    if (rows.length) $("kpi-models").textContent = rows.length;
  }
  document.body.addEventListener("htmx:afterSwap", function (e) {
    if (e.target && (e.target.id === "models-list" || e.target.id === "models-panel")) updateModelCount();
  });

  // ---------- model combobox (custom, dark, typeahead) ----------
  (function () {
    var combo = $("model-combo"); if (!combo) return;
    var input = $("model-input"), dd = $("model-list-dd");
    var MODELS = [
      ["qwen2.5:3b", "Qwen2.5 3B · fast tier"], ["qwen2.5:7b", "Qwen2.5 7B · default tier"],
      ["qwen2.5:14b", "Qwen2.5 14B · larger"], ["llama3.2:1b", "Llama 3.2 1B · tiny"],
      ["llama3.2:3b", "Llama 3.2 3B"], ["llama3.1:8b", "Llama 3.1 8B"],
      ["gemma2:2b", "Gemma 2 2B"], ["gemma2:9b", "Gemma 2 9B"],
      ["phi3:mini", "Phi-3 Mini"], ["mistral:7b", "Mistral 7B"],
      ["codellama:7b", "Code Llama 7B · coding"], ["deepseek-coder:6.7b", "DeepSeek Coder 6.7B · coding"],
      ["llama-guard3:1b", "Llama Guard 3 1B · safety classifier"], ["llama-guard3:8b", "Llama Guard 3 8B · safety classifier"]
    ];
    var hl = -1, shown = [];
    function render() {
      var f = input.value.toLowerCase();
      shown = MODELS.filter(function (m) { return m[0].toLowerCase().indexOf(f) >= 0 || m[1].toLowerCase().indexOf(f) >= 0; });
      if (!shown.length) { dd.hidden = true; input.setAttribute("aria-expanded", "false"); return; }
      hl = -1;
      dd.innerHTML = shown.map(function (m) { return '<div class="combo-item" data-v="' + esc(m[0]) + '"><span class="combo-v">' + esc(m[0]) + '</span><span class="combo-l">' + esc(m[1]) + "</span></div>"; }).join("");
      dd.hidden = false; input.setAttribute("aria-expanded", "true");
    }
    function close() { dd.hidden = true; input.setAttribute("aria-expanded", "false"); }
    function pick(v) { input.value = v; close(); }
    input.addEventListener("focus", render);
    input.addEventListener("input", render);
    dd.addEventListener("mousedown", function (e) { var it = e.target.closest(".combo-item"); if (it) { e.preventDefault(); pick(it.getAttribute("data-v")); } });
    input.addEventListener("keydown", function (e) {
      if (dd.hidden) return;
      var items = dd.querySelectorAll(".combo-item");
      if (e.key === "ArrowDown") { e.preventDefault(); hl = Math.min(hl + 1, items.length - 1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); hl = Math.max(hl - 1, 0); }
      else if (e.key === "Enter" && hl >= 0) { e.preventDefault(); pick(shown[hl][0]); return; }
      else if (e.key === "Escape") { close(); return; }
      else return;
      items.forEach(function (n, i) { n.classList.toggle("hl", i === hl); });
      if (items[hl]) items[hl].scrollIntoView({ block: "nearest" });
    });
    document.addEventListener("click", function (e) { if (!combo.contains(e.target)) close(); });
  })();

  // ---------- pollers ----------
  function pollStats() { fetch("/stats").then(function (r) { return r.json(); }).then(function (s) { applyStats(s); applyCharts(s); }).catch(function () {}); }
  function pollSystem() { fetch("/system").then(function (r) { return r.json(); }).then(applySystem).catch(function () {}); }
  pollStats(); pollSystem();
  setInterval(pollStats, 5000);
  setInterval(pollSystem, 3000);
})();
