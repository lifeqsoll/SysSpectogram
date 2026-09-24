(() => {
  "use strict";

  const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  let charts = { cpu: null, mem: null, net: null };
  let lastAlertSig = "";
  let pendingAction = null;

  function applyTgChrome(theme) {
    if (!tg) return;
    const bg = theme === "dark" ? "#0e1613" : "#f4f7f4";
    try {
      tg.setHeaderColor(bg);
      tg.setBackgroundColor(bg);
    } catch (_) {}
    try {
      document.documentElement.style.colorScheme = theme;
    } catch (_) {}
  }

  function refreshChartTheme() {
    const tick = chartColor("--ink-soft", "#c5d4cc");
    const grid = chartColor("--chart-grid", "rgba(255,255,255,0.14)");
    Object.values(charts).forEach((chart) => {
      if (!chart) return;
      chart.options.scales.y.ticks.color = tick;
      chart.options.scales.y.grid.color = grid;
      chart.update("none");
    });
  }

  function themeInit() {
    const saved = localStorage.getItem("ss_theme");
    const theme = saved || "dark";
    document.documentElement.setAttribute("data-theme", theme);
    applyTgChrome(theme);
    const btn = document.getElementById("theme-toggle");
    btn.textContent = theme === "dark" ? "Light" : "Dark";
    btn.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("ss_theme", next);
      btn.textContent = next === "dark" ? "Light" : "Dark";
      applyTgChrome(next);
      refreshChartTheme();
    });
  }

  function chartColor(varName, fallback) {
    return getComputedStyle(document.documentElement).getPropertyValue(varName).trim() || fallback;
  }

  function mkChart(id, color) {
    return new Chart(document.getElementById(id), {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            data: [],
            borderColor: color,
            backgroundColor: color + "33",
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
            ticks: { font: { size: 9, family: "IBM Plex Mono" }, color: chartColor("--ink-soft", "#9bb0a4") },
            grid: { color: chartColor("--chart-grid", "rgba(255,255,255,0.08)") },
          },
        },
      },
    });
  }

  function updateCharts(snap) {
    const apply = (chart, series) => {
      chart.data.labels = series.map((_, i) => i);
      chart.data.datasets[0].data = series;
      chart.update("none");
    };
    if (charts.cpu) apply(charts.cpu, snap.cpu || []);
    if (charts.mem) apply(charts.mem, snap.mem || []);
    if (charts.net) {
      apply(charts.net, snap.net || []);
      const mx = Math.max(50, ...(snap.net || [0]));
      charts.net.options.scales.y.suggestedMax = mx * 1.2;
    }
  }

  function drawHeatmap(snap) {
    const canvas = document.getElementById("heatmap");
    const ctx = canvas.getContext("2d");
    const rows = 12;
    const cols = Math.max(1, (snap.cpu || []).length || 60);
    const cw = canvas.width;
    const ch = canvas.height;
    const cellW = cw / cols;
    const cellH = ch / rows;
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--heat-bg").trim() || "#07110e";
    ctx.fillRect(0, 0, cw, ch);
    const cpu = snap.cpu || [];
    const mem = snap.mem || [];
    const net = snap.net || [];
    const netMax = Math.max(1, ...net, 1);
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        let v = 0.12 + Math.random() * 0.08;
        if (r < 4) v = 0.2 + (cpu[c] || 0) / 120;
        else if (r < 8) v = 0.2 + (mem[c] || 0) / 130;
        else v = 0.15 + (net[c] || 0) / (netMax * 1.2);
        v = Math.min(1, Math.max(0, v));
        ctx.fillStyle = heatColor(v);
        ctx.fillRect(c * cellW, r * cellH, Math.ceil(cellW) + 0.5, Math.ceil(cellH) + 0.5);
      }
    }
  }

  function heatColor(v) {
    const stops = [
      [7, 17, 14],
      [15, 118, 110],
      [196, 140, 38],
      [232, 242, 236],
    ];
    const x = v * (stops.length - 1);
    const i = Math.min(stops.length - 2, Math.floor(x));
    const f = x - i;
    const a = stops[i];
    const b = stops[i + 1];
    return `rgb(${Math.round(a[0] + (b[0] - a[0]) * f)},${Math.round(a[1] + (b[1] - a[1]) * f)},${Math.round(a[2] + (b[2] - a[2]) * f)})`;
  }

  function setIp(ip) {
    if (ip) document.getElementById("ip-input").value = ip;
  }

  function renderAlerts(alerts) {
    const box = document.getElementById("alerts");
    const sig = JSON.stringify((alerts || []).slice(0, 5).map((a) => [a.ts, a.title]));
    if (sig === lastAlertSig) return;
    lastAlertSig = sig;
    if (!alerts || !alerts.length) {
      box.innerHTML = '<div class="alert empty">No alerts yet — waiting for host / perimeter events.</div>';
      return;
    }
    box.innerHTML = "";
    alerts.slice(0, 8).forEach((a) => {
      const el = document.createElement("article");
      el.className = `alert ${a.severity || "medium"}`;
      const t = a.ts ? new Date(a.ts * 1000).toLocaleTimeString() : "";
      const ip = (a.extras && a.extras.ip) || "";
      el.innerHTML = `<div class="alert-meta"><span>${(a.severity || "").toUpperCase()} · ${a.kind || ""}</span><span>${t}</span></div>
        <h4 class="alert-title"></h4><p class="alert-body"></p>
        <div class="alert-actions"></div>`;
      el.querySelector(".alert-title").textContent = a.title || a.rule_id || "alert";
      el.querySelector(".alert-body").textContent = a.body || "";
      const actions = el.querySelector(".alert-actions");
      if (ip && a.kind !== "action") {
        [
          ["Ban 1h", () => askAction("ban", { ip, ttl: 3600 }, `Ban ${ip} for 1h?`)],
          ["Allow", () => askAction("allow", { ip }, `Allowlist ${ip}?`)],
          ["Mute", () => askAction("mute", { ip, ttl: 3600 }, `Mute ${ip} 1h?`)],
          ["Recon", () => askAction("recon", { ip }, `OSINT recon ${ip}?`)],
          ["Use IP", () => setIp(ip)],
        ].forEach(([label, fn]) => {
          const b = document.createElement("button");
          b.type = "button";
          b.textContent = label;
          if (label.startsWith("Ban")) b.classList.add("danger");
          b.addEventListener("click", fn);
          actions.appendChild(b);
        });
      }
      box.appendChild(el);
    });
  }

  function renderProcs(procs) {
    const box = document.getElementById("procs-box");
    if (!box) return;
    if (!procs || !procs.length) {
      box.innerHTML = '<div class="alert empty">No process snapshot yet — wait or Refresh.</div>';
      return;
    }
    box.innerHTML = "";
    procs.forEach((p) => {
      const row = document.createElement("div");
      row.className = "proc-row";
      const name = p.name || "?";
      const pid = p.pid || 0;
      const cpu = p.cpu_percent != null ? Number(p.cpu_percent).toFixed(1) : "?";
      const mem = p.memory_percent != null ? Number(p.memory_percent).toFixed(1) : "?";
      row.innerHTML = `<div><strong></strong><div class="meta"></div></div><span class="meta"></span><button type="button">Kill</button>`;
      row.querySelector("strong").textContent = name;
      row.querySelector(".meta").textContent = `pid=${pid}`;
      row.children[1].textContent = `cpu ${cpu}% · mem ${mem}%`;
      row.querySelector("button").addEventListener("click", () => {
        askAction("kill", { pid: Number(pid) }, `Kill pid ${pid} (${name})?`);
      });
      box.appendChild(row);
    });
  }

  function renderStatus(snap) {
    const dry = document.getElementById("dry-val");
    if (dry) dry.textContent = snap.dry_run === undefined ? "—" : String(snap.dry_run);
    const box = document.getElementById("bans-box");
    const bans = snap.bans || [];
    const allow = snap.allowlist || [];
    const lines = [
      `quiet=${snap.quiet} lockdown=${snap.lockdown} dry_run=${snap.dry_run}`,
      `allowlist: ${allow.length ? allow.join(", ") : "(empty)"}`,
      "bans:",
    ];
    if (!bans.length) lines.push("  (none)");
    else
      bans.forEach((b) => {
        if (b.error) lines.push("  error: " + b.error);
        else lines.push(`  ${b.ip} backend=${b.backend} handle=${b.handle} exp=${b.expires || "perm"}`);
      });
    box.textContent = lines.join("\n");
    const chk = document.getElementById("set-dry");
    if (chk && document.activeElement !== chk) chk.checked = !!snap.dry_run;
    renderProcs(snap.processes || []);
  }

  function applySnap(snap) {
    document.getElementById("host-id").textContent = snap.host_id || "—";
    document.getElementById("score-val").textContent = Number(snap.score || 0).toFixed(3);
    document.getElementById("thr-val").textContent = Number(snap.threshold || 0).toFixed(3);
    document.getElementById("cnn-val").textContent = Number(snap.cnn || 0).toFixed(3);
    document.getElementById("ifo-val").textContent = Number(snap.iforest || 0).toFixed(3);
    document.getElementById("model-val").textContent = snap.model_loaded ? "yes" : "metrics-only";
    document.getElementById("pattern-label").textContent = `pattern: ${snap.pattern || "—"}`;
    const anom = !!snap.is_anomaly;
    document.getElementById("score-val").style.color = anom ? "var(--crit)" : "inherit";
    document.getElementById("status-dot").classList.toggle("warn", anom);
    updateCharts(snap);
    drawHeatmap(snap);
    renderAlerts(snap.alerts || []);
    renderStatus(snap);
  }

  async function postAction(action, payload) {
    const msg = document.getElementById("action-msg");
    msg.textContent = "…";
    try {
      const res = await fetch("/api/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ action, payload }),
      });
      const data = await res.json();
      if (!data.ok) {
        msg.textContent = "error: " + (data.error || res.status);
        return;
      }
      msg.textContent = String(data.result || "ok");
      if (data.status) renderStatus({ ...data.status });
    } catch (e) {
      msg.textContent = "error: " + e;
    }
  }

  function askAction(action, payload, text) {
    pendingAction = { action, payload };
    document.getElementById("confirm-text").textContent = text;
    document.getElementById("confirm-dlg").showModal();
  }

  function bindControls() {
    document.querySelectorAll(".controls [data-act]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const act = btn.dataset.act;
        const ip = document.getElementById("ip-input").value.trim();
        const port = document.getElementById("port-input").value;
        const pid = document.getElementById("pid-input").value;
        let payload = {};
        let text = act;
        if (["ban", "unban", "allow", "mute", "recon"].includes(act)) {
          if (!ip) {
            document.getElementById("action-msg").textContent = "IP required";
            return;
          }
          payload = { ip };
          if (btn.dataset.ttl) payload.ttl = btn.dataset.ttl === "perm" ? "perm" : Number(btn.dataset.ttl);
          text = `${act} ${ip}` + (payload.ttl ? ` ttl=${payload.ttl}` : "");
        } else if (act === "quiet") {
          payload = { on: btn.dataset.on === "true" };
          text = `quiet ${payload.on ? "on" : "off"}`;
        } else if (act === "lockdown") {
          text = "LOCKDOWN — drop new inbound SYN?";
        } else if (act === "shield") {
          if (!port) {
            document.getElementById("action-msg").textContent = "port required";
            return;
          }
          payload = { port: Number(port), ttl: 3600 };
          text = `shield :${port}`;
        } else if (act === "kill") {
          if (!pid) {
            document.getElementById("action-msg").textContent = "pid required";
            return;
          }
          payload = { pid: Number(pid) };
          text = `kill pid ${pid}`;
        }
        askAction(act, payload, `Confirm ${text}?`);
      });
    });

    document.getElementById("confirm-ok").addEventListener("click", () => {
      const dlg = document.getElementById("confirm-dlg");
      dlg.close();
      if (pendingAction) postAction(pendingAction.action, pendingAction.payload);
      pendingAction = null;
    });

    document.getElementById("btn-settings").addEventListener("click", () => {
      document.getElementById("settings-dlg").showModal();
    });
    document.getElementById("set-save").addEventListener("click", async () => {
      const dry = document.getElementById("set-dry").checked;
      await postAction("set_dry_run", { dry_run: dry });
      document.getElementById("settings-dlg").close();
    });
    const rp = document.getElementById("btn-refresh-procs");
    if (rp) {
      rp.addEventListener("click", () => postAction("refresh_processes", {}));
    }
  }

  async function authTelegram() {
    if (!tg || !tg.initData) return false;
    try {
      tg.ready();
      tg.expand();
      applyTgChrome(document.documentElement.getAttribute("data-theme") || "dark");
      const res = await fetch("/api/auth/telegram", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ initData: tg.initData }),
        credentials: "same-origin",
      });
      const data = await res.json();
      if (data.ok) {
        document.getElementById("auth-note").textContent =
          "Auth: Telegram Mini App OK (only TELEGRAM_CHAT_ID owner)";
        document.getElementById("live-badge").textContent = "LIVE · Telegram Web App";
        return true;
      }
      document.getElementById("auth-note").textContent = "Auth failed: " + (data.error || res.status);
      return false;
    } catch (e) {
      document.getElementById("auth-note").textContent = "Auth error: " + e;
      return false;
    }
  }

  function startStream() {
    const es = new EventSource("/api/stream");
    es.onmessage = (ev) => {
      try {
        applySnap(JSON.parse(ev.data));
      } catch (_) {}
    };
    es.onerror = () => {
      es.close();
      setInterval(async () => {
        try {
          const r = await fetch("/api/snapshot", { credentials: "same-origin" });
          if (r.ok) applySnap(await r.json());
        } catch (_) {}
      }, 1000);
    };
  }

  async function boot() {
    themeInit();
    bindControls();
    if (typeof Chart !== "undefined") {
      charts.cpu = mkChart("chart-cpu", "#2dd4bf");
      charts.mem = mkChart("chart-mem", "#f0a060");
      charts.net = mkChart("chart-net", "#60a5fa");
    }
    if (tg && tg.initData) {
      const ok = await authTelegram();
      if (!ok) return;
    }
    startStream();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
