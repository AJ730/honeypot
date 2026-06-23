/* app.js — Live feed (SSE) + Analytics (Chart.js) wiring */

(function () {
  "use strict";

  /* ---- Live Feed (EventSource) ---- */
  var liveBody = document.getElementById("live-table-body");

  if (liveBody) {
    var es = new EventSource("/feed");

    es.addEventListener("message", function (evt) {
      var data;
      try { data = JSON.parse(evt.data); } catch (e) { return; }
      var tr = document.createElement("tr");
      var cells = [
        data.ts || "",
        data.source_ip || "",
        data.model || "",
        data.endpoint || "",
        data.routed || "",
      ];
      cells.forEach(function (text) {
        var td = document.createElement("td");
        td.textContent = text;
        tr.appendChild(td);
      });
      liveBody.insertBefore(tr, liveBody.firstChild);
      // Keep table to last 100 rows
      while (liveBody.rows.length > 100) {
        liveBody.removeChild(liveBody.lastChild);
      }
    });

    es.onerror = function () {
      // Reconnect is automatic for EventSource; log only on console
      console.warn("SSE connection error — browser will retry.");
    };
  }

  /* ---- Analytics (Chart.js) ---- */
  function renderCharts(stats) {
    // Requests over time (line chart)
    var timeCtx = document.getElementById("chart-time");
    if (timeCtx && stats.requests_over_time) {
      var timeLabels = stats.requests_over_time.map(function (r) { return r.bucket; });
      var timeCounts = stats.requests_over_time.map(function (r) { return r.count; });
      new Chart(timeCtx, {
        type: "line",
        data: {
          labels: timeLabels,
          datasets: [{
            label: "Requests/hour",
            data: timeCounts,
            fill: false,
            borderColor: "#1d4ed8",
            tension: 0.1,
          }],
        },
        options: { responsive: true, plugins: { legend: { display: true } } },
      });
    }

    // Routing breakdown (bar chart)
    var routeCtx = document.getElementById("chart-routed");
    if (routeCtx && stats.by_routed) {
      var routed = stats.by_routed;
      new Chart(routeCtx, {
        type: "bar",
        data: {
          labels: ["real", "fake", "blocked"],
          datasets: [{
            label: "Routing",
            data: [routed.real || 0, routed.fake || 0, routed.blocked || 0],
            backgroundColor: ["#16a34a", "#d97706", "#dc2626"],
          }],
        },
        options: { responsive: true, plugins: { legend: { display: false } } },
      });
    }

    // Top endpoints (bar chart)
    var epCtx = document.getElementById("chart-endpoints");
    if (epCtx && stats.by_endpoint && stats.by_endpoint.length) {
      new Chart(epCtx, {
        type: "bar",
        data: {
          labels: stats.by_endpoint.map(function (r) { return r.endpoint; }),
          datasets: [{
            label: "Hits",
            data: stats.by_endpoint.map(function (r) { return r.count; }),
            backgroundColor: "#6366f1",
          }],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          plugins: { legend: { display: false } },
        },
      });
    }
  }

  var analyticsSection = document.getElementById("analytics");
  if (analyticsSection) {
    fetch("/stats")
      .then(function (r) { return r.json(); })
      .then(renderCharts)
      .catch(function (err) { console.error("Failed to load /stats:", err); });
  }
})();
