/* SysSpectogram fake demo — no backend, synthetic metrics only. */
(() => {
  "use strict";

  const HOST = "demo-vps";
  const WINDOW = 60;
  const TICK_MS = 280;
  const THRESHOLD = 0.75;

  const SCENARIOS = {
    idle: {
      label: "idle baseline",
      cpu: [8, 4],
      mem: [32, 2],
      net: [40, 15],
      score: [0.1, 0.05],
      amplify: null,
      alert: null,
    },
    cpu: {
      label: "CPU spike / compute",
      cpu: [88, 6],
      mem: [38, 3],
      net: [55, 20],
      score: [0.91, 0.03],
      amplify: "cpu",
      alert: {
        severity: "high",
        kind: "host",
        title: "HOST ANOMALY · CPU spike / compute",
        body: "Template: high CPU load (cpu≈88%); top: python(pid=4242,cpu=99%). Miner / runaway compute possible.",
      },
    },
    mem: {
      label: "memory pressure",
      cpu: [22, 5],
      mem: [86, 4],
      net: [48, 18],
      score: [0.84, 0.04],
      amplify: "mem",
      alert: {
        severity: "high",
        kind: "host",
        title: "HOST ANOMALY · memory pressure",
        body: "Template: elevated mem≈86% / swap pressure. Leak or heavy alloc possible.",
      },
    },
    net: {
      label: "network flood",
      cpu: [28, 6],
      mem: [40, 3],
      net: [4200, 400],
      score: [0.87, 0.04],
      amplify: "net",
      alert: {
        severity: "high",
        kind: "host",
        title: "HOST ANOMALY · network flood",
        body: "Template: packet/byte rates far above baseline. Local flood or exfil-like burst.",
      },
    },
    brute: {
      label: "SSH brute (perimeter)",
      cpu: [12, 4],
      mem: [34, 2],
      net: [90, 25],
      score: [0.18, 0.05],
      amplify: null,
      alert: {
        severity: "critical",
        kind: "perimeter",
        title: "PERIMETER · bruteforce_ssh",
        body: "Template: SSH auth failures spike from 203.0.113.50 (12 fails / 60s). Credential stuffing likely.",
        ip: "203.0.113.50",
      },
    },
    egress: {
      label: "egress denylist",
      cpu: [14, 4],
      mem: [35, 2],
      net: [180, 40],
      score: [0.22, 0.05],
      amplify: "net",
      alert: {
        severity: "critical",
        kind: "perimeter",
        title: "PERIMETER · egress_denylist_hit",
        body: "Template: outbound to denylisted 198.51.100.66:4444. Possible beacon / C2.",
        ip: "198.51.100.66",
        recon: "PTR: none · ASN: EXAMPLE-NET · country: ZZ · nmap: lab-gated (skipped)",
      },
    },
    train: {
      label: "training pipeline (fake)",
      cpu: [45, 8],
      mem: [55, 4],
      net: [70, 20],
      score: [0.35, 0.08],
      amplify: "cpu",
      alert: null,
    },
  };

  function randn() {
    let u = 0;
    let v = 0;
    while (u === 0) u = Math.random();
    while (v === 0) v = Math.random();
    return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
  }

  function sample(meanStd) {
    const [mean, std] = meanStd;
    return Math.max(0, mean + randn() * std);
  }

  function makeSeries(fill) {
    return Array.from({ length: WINDOW }, () => fill);
  }

  const state = {
    scenario: "idle",
    cpu: makeSeries(10),
    mem: makeSeries(32),
    net: makeSeries(40),
    score: 0.12,
    tick: 0,
    lastAlertKey: null,
    trainTimer: null,
    trainRunning: false,
  };

  let charts = { cpu: null, mem: null, net: null };

  function chartOpts(color) {
    return {
      type: "line",
      data: {
        labels: Array.from({ length: WINDOW }, (_, i) => i),
        datasets: [
          {
            data: [],
            borderColor: color,
            backgroundColor: color + "22",
            fill: true,
            tension: 0.25,
            pointRadius: 0,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        animation: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: {
            beginAtZero: true,
            ticks: { font: { size: 9, family: "IBM Plex Mono" }, color: "#2a3b34" },
            grid: { color: "rgba(20,32,28,0.08)" },
          },
        },
      },
    };
  }

  function initCharts() {
    if (typeof Chart === "undefined") return;
    charts.cpu = new Chart(document.getElementById("chart-cpu"), chartOpts("#0f766e"));
    charts.mem = new Chart(document.getElementById("chart-mem"), chartOpts("#c45c26"));
    charts.net = new Chart(document.getElementById("chart-net"), chartOpts("#1d4e89"));
    pushCharts();
  }

  function pushCharts() {
    if (!charts.cpu) return;
    charts.cpu.data.datasets[0].data = state.cpu.slice();
    charts.mem.data.datasets[0].data = state.mem.slice();
    charts.net.data.datasets[0].data = state.net.slice();
    const netMax = Math.max(100, ...state.net);
    charts.net.options.scales.y.suggestedMax = netMax * 1.15;
    charts.cpu.update("none");
    charts.mem.update("none");
    charts.net.update("none");
  }

  function drawHeatmap() {
    const canvas = document.getElementById("heatmap");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const rows = 12;
    const cols = WINDOW;
    const cw = canvas.width;
    const ch = canvas.height;
    const cellW = cw / cols;
    const cellH = ch / rows;
    const cfg = SCENARIOS[state.scenario];

    ctx.fillStyle = "#0f1a17";
    ctx.fillRect(0, 0, cw, ch);

    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        let v = 0.15 + Math.random() * 0.2;
        const t = c / cols;
        if (cfg.amplify === "cpu" && r < 4) v = 0.55 + state.cpu[c] / 140 + Math.random() * 0.15;
        if (cfg.amplify === "mem" && r >= 4 && r < 7) v = 0.45 + state.mem[c] / 140 + Math.random() * 0.12;
        if (cfg.amplify === "net" && r >= 7) v = 0.35 + Math.min(1, state.net[c] / 5000) + Math.random() * 0.1;
        if (!cfg.amplify) v *= 0.7 + 0.2 * Math.sin(t * Math.PI * 2 + r);
        v = Math.min(1, Math.max(0, v));
        ctx.fillStyle = heatColor(v);
        ctx.fillRect(c * cellW, r * cellH, Math.ceil(cellW) + 0.5, Math.ceil(cellH) + 0.5);
      }
    }

    // second strip label feel (process heat)
    ctx.fillStyle = "rgba(245,255,251,0.55)";
    ctx.font = "10px IBM Plex Mono";
    ctx.fillText("metrics", 8, 14);
    ctx.fillText("top-PID heat (fake)", 8, ch - 8);
  }

  function heatColor(v) {
    // teal → amber → near-white (not purple)
    const stops = [
      [15, 30, 28],
      [15, 118, 110],
      [196, 140, 38],
      [240, 248, 240],
    ];
    const x = v * (stops.length - 1);
    const i = Math.min(stops.length - 2, Math.floor(x));
    const f = x - i;
    const a = stops[i];
    const b = stops[i + 1];
    const r = Math.round(a[0] + (b[0] - a[0]) * f);
    const g = Math.round(a[1] + (b[1] - a[1]) * f);
    const bl = Math.round(a[2] + (b[2] - a[2]) * f);
    return `rgb(${r},${g},${bl})`;
  }

  function setScenario(name) {
    if (!SCENARIOS[name]) return;
    state.scenario = name;
    state.lastAlertKey = null;
    document.querySelectorAll(".scenario").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.scenario === name);
    });
    document.getElementById("pattern-label").textContent = `pattern: ${SCENARIOS[name].label}`;

    const trainPanel = document.getElementById("train-panel");
    if (name === "train") {
      trainPanel.hidden = false;
      startFakeTrain();
    } else {
      stopFakeTrain();
      trainPanel.hidden = true;
    }

    const cfg = SCENARIOS[name];
    if (cfg.alert) {
      maybeAlert(true);
    }
  }

  function pushPoint(arr, value) {
    arr.push(value);
    if (arr.length > WINDOW) arr.shift();
  }

  function tick() {
    const cfg = SCENARIOS[state.scenario];
    pushPoint(state.cpu, sample(cfg.cpu));
    pushPoint(state.mem, sample(cfg.mem));
    pushPoint(state.net, sample(cfg.net));
    state.score = sample(cfg.score);
    state.tick += 1;

    document.getElementById("score-val").textContent = state.score.toFixed(2);
    const scoreEl = document.getElementById("score-val");
    scoreEl.style.color = state.score >= THRESHOLD ? "var(--crit)" : "inherit";

    pushCharts();
    if (state.tick % 2 === 0) drawHeatmap();
  }

  function maybeAlert(force) {
    const cfg = SCENARIOS[state.scenario];
    if (!cfg.alert) return;
    const key = state.scenario + ":" + cfg.alert.title;
    if (state.lastAlertKey === key && !force) return;
    if (force) {
      state.lastAlertKey = key;
      pushAlert(cfg.alert);
      return;
    }
    // host alerts only when score crosses threshold once per scenario
    if (cfg.alert.kind === "host" && state.score < THRESHOLD) return;
    if (state.lastAlertKey === key) return;
    state.lastAlertKey = key;
    pushAlert(cfg.alert);
  }

  function pushAlert(alert) {
    const box = document.getElementById("alerts");
    const empty = box.querySelector(".alert.empty");
    if (empty) empty.remove();

    const el = document.createElement("article");
    el.className = `alert ${alert.severity || "medium"}`;
    const sev = (alert.severity || "medium").toUpperCase();
    el.innerHTML = `
      <div class="alert-meta">
        <span>[${HOST}] · ${sev}</span>
        <span>${new Date().toLocaleTimeString()}</span>
      </div>
      <h4 class="alert-title"></h4>
      <p class="alert-body"></p>
    `;
    el.querySelector(".alert-title").textContent = alert.title;
    el.querySelector(".alert-body").textContent = alert.body;
    if (alert.recon) {
      const recon = document.createElement("pre");
      recon.className = "alert-recon";
      recon.textContent = alert.recon;
      el.appendChild(recon);
    }
    box.prepend(el);
    while (box.children.length > 6) box.removeChild(box.lastChild);
  }

  function ensureEmptyAlert() {
    const box = document.getElementById("alerts");
    if (!box.children.length) {
      const el = document.createElement("div");
      el.className = "alert empty";
      el.textContent = "No alerts yet — pick a scenario.";
      box.appendChild(el);
    }
  }

  function stopFakeTrain() {
    if (state.trainTimer) {
      clearInterval(state.trainTimer);
      state.trainTimer = null;
    }
    state.trainRunning = false;
    document.querySelectorAll("#train-steps li").forEach((li) => {
      li.classList.remove("active", "done");
    });
    document.getElementById("train-bar-fill").style.width = "0%";
    document.getElementById("train-status").textContent = "Idle";
  }

  function startFakeTrain() {
    stopFakeTrain();
    state.trainRunning = true;
    const steps = ["collect", "build", "train", "ready"];
    let i = 0;
    document.getElementById("train-status").textContent = "Starting fake pipeline…";

    state.trainTimer = setInterval(() => {
      if (i >= steps.length) {
        clearInterval(state.trainTimer);
        state.trainTimer = null;
        document.getElementById("train-status").textContent =
          "Done (fake). Clone the repo to train on real CSV.";
        pushAlert({
          severity: "medium",
          title: "TRAIN · artifacts ready (simulated)",
          body: "cnn.pt · iforest.joblib · scaler.joblib · meta.json — demo only, not written to disk.",
        });
        return;
      }
      const step = steps[i];
      document.querySelectorAll("#train-steps li").forEach((li) => {
        const idx = steps.indexOf(li.dataset.step);
        li.classList.toggle("done", idx < i);
        li.classList.toggle("active", li.dataset.step === step);
      });
      const pct = ((i + 1) / steps.length) * 100;
      document.getElementById("train-bar-fill").style.width = pct + "%";
      const labels = {
        collect: "collect → data/normal.csv + anomaly.csv",
        build: "build-dataset → dataset/real windows",
        train: "train → CNN + Isolation Forest",
        ready: "artifacts/real ready",
      };
      document.getElementById("train-status").textContent = labels[step];
      i += 1;
    }, 1100);
  }

  function bindUi() {
    document.querySelectorAll(".scenario").forEach((btn) => {
      btn.addEventListener("click", () => setScenario(btn.dataset.scenario));
    });
  }

  function boot() {
    bindUi();
    ensureEmptyAlert();
    initCharts();
    drawHeatmap();
    setInterval(tick, TICK_MS);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
