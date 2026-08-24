(() => {
  const TABS = [
    { id: "overview", label: "Overview", inner: [
      ["pulse", "Pulse"], ["talkers", "Top Talkers"], ["strip", "Alert Strip"], ["capture", "Capture Status"],
    ]},
    { id: "packets", label: "Packets", inner: [
      ["live", "Live table"], ["decode", "Decode / inspect"], ["charts", "Size and rate"], ["conversation", "Conversation"],
    ]},
    { id: "flows", label: "Flows", inner: [
      ["active", "Active"], ["elephant", "Elephant"], ["scan", "Scan-like / short"], ["detail", "Flow detail"],
    ]},
    { id: "alerts", label: "Alerts", inner: [
      ["feed", "Feed"], ["signature", "By signature"], ["host", "By host"], ["timeline", "Timeline"],
    ]},
    { id: "hosts", label: "Hosts", inner: [
      ["list", "Directory"], ["relations", "Relationships"],
    ]},
    { id: "protocols", label: "Protocols", inner: [
      ["mix", "Mix"], ["flags", "TCP flags"], ["ports", "Ports"],
    ]},
    { id: "maps", label: "Maps / Diagrams", inner: [
      ["l3", "L3 conversations"], ["l4", "L4 services"], ["hmap", "Host map"], ["geo", "Geo"],
      ["path", "Data path"], ["topo", "Capture topology"],
    ]},
    { id: "statistics", label: "Statistics", inner: [
      ["series", "Time series"], ["sizes", "Sizes"], ["iat", "Timing"],
    ]},
    { id: "health", label: "Capture Health", inner: [
      ["sensor", "Sensor"], ["tools", "Tools"],
    ]},
    { id: "settings", label: "Settings", inner: [
      ["capture", "Capture"], ["demo", "Demo / PCAP"],
    ]},
  ];

  const state = {
    page: localStorage.getItem("nids.page") || "overview",
    inner: localStorage.getItem("nids.inner") || "pulse",
    range: localStorage.getItem("nids.range") || "15m",
    tsFrom: null, tsTo: null,
    q: "", ip: "", port: "", proto: "",
    paused: false, offset: 0, refreshMs: 5000,
    ws: null, meta: null, live: false, badges: { alerts: 0, pps: 0, drops: 0 },
    showMore: false, inspect: null, graphCtl: null,
    alert: { sevs: { critical: true, high: true, medium: true, low: true, info: true }, hideDemo: false, includeAcked: false },
  };

  const $ = (s) => document.querySelector(s);
  const main = $("#main");
  const banner = $("#banner");

  function fmtNum(n) {
    n = Number(n || 0);
    if (n >= 1e9) return (n / 1e9).toFixed(2) + "G";
    if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
    if (Math.abs(n) < 10 && n % 1) return n.toFixed(2);
    return String(Math.round(n));
  }
  function fmtBps(n) {
    n = Number(n || 0);
    if (n >= 1e9) return (n / 1e9).toFixed(2) + " Gbps";
    if (n >= 1e6) return (n / 1e6).toFixed(2) + " Mbps";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + " kbps";
    return Math.round(n) + " bps";
  }
  function fmtTs(ts) {
    if (!ts) return "—";
    return new Date(Number(ts) * 1000).toISOString().replace("T", " ").replace("Z", "");
  }
  function esc(s) {
    return String(s ?? "").replace(/[&<>"'`]/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;",
    }[c]));
  }
  function showErr(e) {
    banner.textContent = e.message || String(e);
    banner.classList.remove("hidden");
    banner.classList.add("error");
  }
  function clearErr() { banner.classList.add("hidden"); banner.classList.remove("error"); }
  function params(extra) {
    return Object.assign({
      range: state.range, q: state.q, ip: state.ip, port: state.port, proto: state.proto,
      ts_from: state.tsFrom, ts_to: state.tsTo,
    }, extra || {});
  }
  function pill(sev) {
    sev = (sev || "info").toLowerCase();
    return `<span class="pill ${esc(sev)}">${esc(sev)}</span>`;
  }
  function tabSpec(id) { return TABS.find((t) => t.id === id) || TABS[0]; }

  function writeHash() {
    const u = new URLSearchParams();
    if (state.range) u.set("range", state.range);
    if (state.ip) u.set("ip", state.ip);
    if (state.port) u.set("port", state.port);
    if (state.proto) u.set("proto", state.proto);
    if (state.q) u.set("q", state.q);
    const q = u.toString();
    const hash = `#/${state.page}/${state.inner}${q ? "?" + q : ""}`;
    if (location.hash !== hash) history.replaceState(null, "", hash);
    localStorage.setItem("nids.page", state.page);
    localStorage.setItem("nids.inner", state.inner);
    localStorage.setItem("nids.range", state.range);
  }
  function readHash() {
    const raw = (location.hash || "").replace(/^#\/?/, "");
    const [path, qs] = raw.split("?");
    const parts = (path || "").split("/").filter(Boolean);
    if (parts[0] && TABS.some((t) => t.id === parts[0])) state.page = parts[0];
    const spec = tabSpec(state.page);
    if (parts[1] && spec.inner.some((i) => i[0] === parts[1])) state.inner = parts[1];
    else if (!spec.inner.some((i) => i[0] === state.inner)) state.inner = spec.inner[0][0];
    const u = new URLSearchParams(qs || "");
    if (u.get("range")) state.range = u.get("range");
    if (u.get("ip")) state.ip = u.get("ip");
    if (u.get("port")) state.port = u.get("port");
    if (u.get("proto")) state.proto = u.get("proto");
    if (u.get("q")) state.q = u.get("q");
    if (u.get("sev")) {
      Object.keys(state.alert.sevs).forEach((k) => { state.alert.sevs[k] = k === u.get("sev"); });
    }
  }

  function drawTabs() {
    $("#tabs").innerHTML = TABS.map((t) => {
      let badge = "";
      if (t.id === "alerts") badge = `<span class="badge ${state.badges.alerts ? "hot" : ""}">${fmtNum(state.badges.alerts)}</span>`;
      if (t.id === "packets") badge = `<span class="badge">${fmtNum(state.badges.pps)}/s</span>`;
      if (t.id === "health") badge = `<span class="badge ${state.badges.drops ? "warn" : ""}">${fmtNum(state.badges.drops)}</span>`;
      return `<a href="#/${t.id}/${tabSpec(t.id).inner[0][0]}" data-page="${t.id}" class="${t.id === state.page ? "active" : ""}">${esc(t.label)}${badge}</a>`;
    }).join("");
    const spec = tabSpec(state.page);
    $("#subtabs").innerHTML = spec.inner.map(([id, lab]) =>
      `<button data-inner="${id}" class="${id === state.inner ? "on" : ""}">${esc(lab)}</button>`
    ).join("");
    $("#tabs").querySelectorAll("a").forEach((a) => {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        go(a.dataset.page, tabSpec(a.dataset.page).inner[0][0]);
      });
    });
    $("#subtabs").querySelectorAll("button").forEach((b) => {
      b.addEventListener("click", () => go(state.page, b.dataset.inner));
    });
  }
  function go(page, inner) {
    state.page = page;
    state.inner = inner || tabSpec(page).inner[0][0];
    state.offset = 0;
    writeHash();
    drawTabs();
    render();
  }

  function kpiRow(kpis, sparks) {
    const items = [
      ["pps", fmtNum(kpis.pps), sparks.pps],
      ["bps", fmtBps(kpis.bps), sparks.pps],
      ["flows", fmtNum(kpis.active_flows), sparks.flows],
      ["alerts/min", fmtNum((kpis.alert_rate || 0) * 60), sparks.alerts],
      ["unique hosts", fmtNum(kpis.unique_hosts)],
      ["drops", fmtNum(kpis.drops)],
    ];
    return `<section class="kpis">${items.map(([k, v]) =>
      `<div class="kpi"><div class="k">${k}</div><div class="v">${esc(v)}</div><canvas class="spark"></canvas></div>`
    ).join("")}</section>`;
  }
  function table(headers, rows, empty) {
    if (!rows.length) return `<div class="empty">${esc(empty || "No data in this time range.")}</div>`;
    return `<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>
      <tbody>${rows.map((r) => `<tr>${r}</tr>`).join("")}</tbody></table></div>`;
  }
  function barsHtml(items, nameKey, valKey) {
    const max = Math.max(1, ...items.map((i) => Number(i[valKey] || 0)));
    return items.map((i) => {
      const n = Number(i[valKey] || 0);
      return `<div class="bar-row"><span class="lab mono" title="${esc(i[nameKey])}">${esc(i[nameKey])}</span>
        <div class="track"><div class="fill" style="width:${Math.round((n / max) * 100)}%"></div></div>
        <span class="mono">${fmtNum(n)}</span></div>`;
    }).join("") || `<div class="empty">No series.</div>`;
  }
  function pager(data) {
    const total = data.total || 0;
    return `<div class="pager"><button id="pg-prev">Prev</button>
      <span>${state.offset + 1}–${Math.min(state.offset + (data.limit || 200), total)} of ${fmtNum(total)}</span>
      <button id="pg-next">Next</button></div>`;
  }
  function bindPager(reload) {
    $("#pg-prev")?.addEventListener("click", () => { state.offset = Math.max(0, state.offset - 200); (reload || render)(); });
    $("#pg-next")?.addEventListener("click", () => { state.offset += 200; (reload || render)(); });
  }
  function filterHost(ip) {
    if (!ip || ip === "others" || ip.startsWith("svc:")) return;
    state.ip = ip;
    $("#g-ip").value = ip;
    writeHash();
    render();
  }
  function openDrawer(title, html) {
    $("#drawer-title").textContent = title;
    $("#drawer-body").innerHTML = html;
    $("#drawer").classList.add("open");
    $("#drawer").setAttribute("aria-hidden", "false");
  }
  function closeDrawer() {
    $("#drawer").classList.remove("open");
    $("#drawer").setAttribute("aria-hidden", "true");
  }
  $("#drawer-close").addEventListener("click", closeDrawer);

  async function inspectPacket(id) {
    const p = await API.packet(id);
    const pkts = await API.packets({ flow_id: p.flow_id, limit: 12, range: "7d" });
    const swim = (pkts.rows || []).map((r) => {
      const dir = r.src_ip === p.src_ip ? "→" : "←";
      return `<div class="swim"><span class="mono">${esc(r.src_ip)}</span><span class="arr">${dir} ${esc(r.tcp_flags_s || r.proto)} ${esc(r.length)}B</span><span class="mono">${esc(r.dst_ip)}</span></div>`;
    }).join("");
    openDrawer("Packet " + id, `
      <p>${esc(p.src_ip)}:${p.src_port ?? ""} → ${esc(p.dst_ip)}:${p.dst_port ?? ""} · ${esc(p.proto)} · ${esc(p.l7 || "")}</p>
      <h2>Conversation</h2>${swim || "<p class='hint'>No related packets.</p>"}
      <canvas id="d-mini" height="160"></canvas>
      <pre>${esc(JSON.stringify(p, null, 2))}</pre>`);
    const g = await API.graph(params({ kind: "conversations", ip: p.src_ip, limit: 12 }));
    Charts.graph("#d-mini", g, { onNode: (n) => filterHost(n.id) });
  }
  async function inspectFlow(id) {
    const f = await API.flow(id);
    const pkts = await API.packets({ flow_id: id, limit: 16, range: "7d" });
    const swim = (pkts.rows || []).map((r) => {
      const dir = r.src_ip === f.src_ip ? "→" : "←";
      return `<div class="swim"><span class="mono">${esc(r.src_ip)}</span><span class="arr">${dir} ${esc(r.tcp_flags_s || r.proto)}</span><span class="mono">${esc(r.dst_ip)}</span></div>`;
    }).join("");
    openDrawer("Flow " + id, `
      <p class="mono">${esc(f.src_ip)}:${f.src_port ?? ""} → ${esc(f.dst_ip)}:${f.dst_port ?? ""}</p>
      <p>${fmtNum(f.total_bytes)} bytes · ${esc(f.tcp_state || "")} · ${esc(f.l7 || "")}</p>
      <h2>Sequence</h2>${swim}
      <canvas id="d-mini" height="160"></canvas>`);
    const g = await API.graph(params({ kind: "conversations", ip: f.src_ip, limit: 12 }));
    Charts.graph("#d-mini", g, { onNode: (n) => filterHost(n.id) });
  }

  function pathDiagram() {
    return `<div class="path">
      <div class="box">NIC / iface</div><span class="arrow">→</span>
      <div class="box">dumpcap / tshark</div><span class="arrow">→</span>
      <div class="box">Parser</div><span class="arrow">→</span>
      <div class="box">Flow engine</div><span class="arrow">→</span>
      <div class="box">STAT IDS</div><span class="arrow">→</span>
      <div class="box">Dashboard</div>
    </div>
    <p class="hint">Metadata only. Payloads stay off unless explicitly enabled in Settings.</p>`;
  }

  async function renderOverview(kpis, stats, ts, alerts) {
    if (state.inner === "talkers") {
      main.innerHTML = `${kpiRow(kpis, ts)}
        <section class="grid-2">
          <div class="panel"><h2>Top talkers</h2><canvas id="c-talk" height="220"></canvas>${barsHtml(stats.talkers, "ip", "bytes")}</div>
          <div class="panel"><h2>Top destinations</h2><canvas id="c-dst" height="220"></canvas>${barsHtml(stats.destinations, "ip", "bytes")}</div>
        </section>`;
      Charts.bars("#c-talk", stats.talkers);
      Charts.bars("#c-dst", stats.destinations, "#7aa2ff");
      return;
    }
    if (state.inner === "strip") {
      main.innerHTML = `${kpiRow(kpis, ts)}
        <div class="panel"><h2>Alert timeline</h2><canvas id="c-tl" height="180"></canvas>
          <div class="legend"><span><i style="background:#ff4d4f"></i>Critical</span><span><i style="background:#ff7a45"></i>High</span>
          <span><i style="background:#f5c542"></i>Medium</span><span><i style="background:#3dd6d0"></i>Low</span>
          <span><i style="background:#7aa2ff"></i>Info</span></div></div>
        <div class="panel"><h2>Latest</h2>${alertTable(alerts.rows)}</div>`;
      Charts.timeline("#c-tl", stats.alert_timeline);
      bindAlertClicks();
      return;
    }
    if (state.inner === "capture") {
      const h = await API.health();
      main.innerHTML = `${kpiRow(kpis, ts)}
        <div class="panel"><h2>Capture path</h2>${pathDiagram()}</div>
        <div class="grid-2">
          <div class="panel"><h2>Sensor</h2><pre>${esc(JSON.stringify({ iface: h.iface, capture: h.capture, drops: h.iface_stats }, null, 2))}</pre></div>
          <div class="panel"><h2>Drops / errors</h2><canvas id="c-drop" height="160"></canvas></div>
        </div>`;
      Charts.area("#c-drop", ts.drops || ts.pps, "#ff7a45");
      return;
    }
    main.innerHTML = `${kpiRow(kpis, ts)}
      <section class="grid-12">
        <div class="panel span-8"><h2>Traffic</h2><canvas id="c-pps" height="180"></canvas></div>
        <div class="panel span-4"><h2>Protocol mix</h2><canvas id="c-pie" height="180"></canvas></div>
        <div class="panel span-6"><h2>Alert rate</h2><canvas id="c-al" height="160"></canvas></div>
        <div class="panel span-6"><h2>New flows</h2><canvas id="c-fl" height="160"></canvas></div>
        <div class="panel span-12"><h2>L3 conversations</h2><canvas id="c-g" height="560"></canvas>
          <div class="legend"><span><i style="background:#3dd6d0"></i>Internal</span><span><i style="background:#c9a0ff"></i>External</span>
          <span><i style="background:#ff7a45"></i>Has alerts</span><span><i style="background:#7aa2ff"></i>TCP</span>
          <span><i style="background:#3dd6d0"></i>UDP</span><button id="g-reset" class="ghost">Reset layout</button></div></div>
      </section>`;
    Charts.area("#c-pps", ts.pps, "#3dd6d0", { onBrush: brushRange });
    Charts.pie("#c-pie", stats.protocols);
    Charts.area("#c-al", ts.alerts, "#ff7a45", { onBrush: brushRange });
    Charts.area("#c-fl", ts.flows, "#7aa2ff", { onBrush: brushRange });
    const g = await API.graph(params({ kind: "conversations", show_more: state.showMore }));
    state.graphCtl = Charts.graph("#c-g", g, { onNode: (n) => filterHost(n.id), onEdge: (e) => e.flow_id && inspectFlow(e.flow_id) });
    $("#g-reset")?.addEventListener("click", () => state.graphCtl && state.graphCtl.reset());
    document.querySelectorAll(".kpi canvas.spark").forEach((c, i) => {
      const src = [ts.pps, ts.pps, ts.flows, ts.alerts, ts.pps, ts.pps][i] || [];
      Charts.line(c, src.map((p) => p.v), "#3dd6d0");
    });
  }

  function brushRange(a, b) {
    if (!a || !b || !a.t || !b.t) return;
    state.tsFrom = Math.min(a.t, b.t);
    state.tsTo = Math.max(a.t, b.t);
    writeHash();
    render();
  }

  function alertTable(rows) {
    return table(["Sev", "When", "Signature", "Src", "Dst", "Count"],
      rows.map((a) => `
        <td>${pill(a.severity)}${a.is_demo ? ' <span class="pill demo">DEMO</span>' : ""}</td>
        <td class="mono">${esc(fmtTs(a.last_seen))}</td>
        <td class="linkish" data-alert='${esc(JSON.stringify(a))}'>${esc(a.signature)}</td>
        <td class="mono linkish" data-ip="${esc(a.src_ip || "")}">${esc(a.src_ip || "—")}</td>
        <td class="mono">${esc(a.dst_ip || "—")}</td>
        <td class="mono">${esc(a.count)}</td>`),
      "No alerts in range.");
  }
  function bindAlertClicks() {
    main.querySelectorAll("[data-ip]").forEach((el) => el.addEventListener("click", () => filterHost(el.dataset.ip)));
    main.querySelectorAll("[data-alert]").forEach((el) => el.addEventListener("click", () => {
      const a = JSON.parse(el.dataset.alert);
      openDrawer("Alert", `<p>${pill(a.severity)} ${esc(a.signature)}</p><pre>${esc(JSON.stringify(a, null, 2))}</pre>
        <p><button class="ghost" data-ack="${a.id}">Ack</button> <button class="ghost" data-mute="${a.id}">Mute</button></p>`);
      $("#drawer-body").querySelector("[data-ack]")?.addEventListener("click", async () => { await API.ack(a.id); render(); });
      $("#drawer-body").querySelector("[data-mute]")?.addEventListener("click", async () => { await API.mute(a.id); render(); });
    }));
  }

  async function renderPackets() {
    const extra = { limit: 150, offset: state.offset };
    const data = await API.packets(params(extra));
    const stats = await API.stats(params());
    const ts = await API.timeseries(params({ metric: "pps" }));
    if (state.inner === "charts") {
      main.innerHTML = `<section class="grid-2">
        <div class="panel"><h2>Packet rate</h2><canvas id="c-r" height="200"></canvas></div>
        <div class="panel"><h2>Size histogram</h2><canvas id="c-s" height="200"></canvas></div>
      </section>
      <div class="panel"><h2>TCP flags</h2>${barsHtml(stats.tcp_flags, "name", "n")}</div>`;
      Charts.area("#c-r", ts.points, "#3dd6d0", { onBrush: brushRange });
      Charts.bars("#c-s", stats.sizes);
      return;
    }
    if (state.inner === "conversation") {
      const g = await API.graph(params({ kind: "conversations" }));
      main.innerHTML = `<div class="panel"><h2>Conversations from packets/flows</h2>
        <canvas id="c-g" height="560"></canvas>
        <button id="g-reset" class="ghost">Reset layout</button>
        <label class="chk"><input type="checkbox" id="more" ${state.showMore ? "checked" : ""} /> Show more nodes</label></div>`;
      state.graphCtl = Charts.graph("#c-g", g, { onNode: (n) => filterHost(n.id), onEdge: (e) => e.flow_id && inspectFlow(e.flow_id) });
      $("#g-reset").onclick = () => state.graphCtl.reset();
      $("#more").onchange = () => { state.showMore = $("#more").checked; render(); };
      return;
    }
    if (state.inner === "decode") {
      main.innerHTML = `<div class="panel"><h2>Select a packet from Live table, or the latest frame</h2>
        ${table(["Time", "5-tuple", "Proto", "Len", "Info"],
          data.rows.slice(0, 12).map((p) => `
            <td class="mono">${esc(fmtTs(p.ts))}</td>
            <td class="mono linkish" data-pkt="${p.id}">${esc(p.src_ip)}:${p.src_port ?? ""} → ${esc(p.dst_ip)}:${p.dst_port ?? ""}</td>
            <td>${esc(p.proto)}</td><td>${esc(p.length)}</td><td>${esc(p.info || p.sni || p.l7 || "")}</td>`),
          "No packets.")}</div>`;
      main.querySelectorAll("[data-pkt]").forEach((el) => el.addEventListener("click", () => inspectPacket(el.dataset.pkt)));
      return;
    }
    main.innerHTML = `<section class="grid-12">
      <div class="panel span-4"><h2>Rate</h2><canvas id="c-r" height="140"></canvas></div>
      <div class="panel span-8"><h2>Live packets ${fmtNum(data.total)}</h2>
        ${table(["Time", "Src", "Dst", "Proto", "Len", "Flags", "L7"],
          data.rows.map((p) => `
            <td class="mono">${esc(fmtTs(p.ts))}</td>
            <td class="mono">${esc(p.src_ip || "")}${p.src_port != null ? ":" + p.src_port : ""}</td>
            <td class="mono">${esc(p.dst_ip || "")}${p.dst_port != null ? ":" + p.dst_port : ""}</td>
            <td>${esc(p.proto)}</td><td class="mono">${esc(p.length)}</td>
            <td class="mono">${esc(p.tcp_flags_s || "")}</td>
            <td class="linkish" data-pkt="${p.id}">${esc(p.l7 || "")} ${esc(p.info || "")}</td>`),
          "No packets. Load DEMO or start live capture.")}
        ${pager(data)}
      </div></section>`;
    Charts.area("#c-r", ts.points, "#3dd6d0");
    main.querySelectorAll("[data-pkt]").forEach((el) => el.addEventListener("click", () => inspectPacket(el.dataset.pkt)));
    bindPager();
  }

  async function renderFlows() {
    const view = { active: "", elephant: "elephant", scan: "scan", detail: "" }[state.inner];
    const extra = { view: state.inner === "scan" ? "scan" : view, limit: 120, offset: state.offset, sort: "bytes" };
    if (state.inner === "scan") {
      const short = await API.flows(params({ view: "short", limit: 80, sort: "start_ts" }));
      const scan = await API.flows(params({ view: "scan", limit: 80 }));
      main.innerHTML = `<div class="grid-2">
        <div class="panel"><h2>Scan-like</h2>${flowTable(scan.rows)}</div>
        <div class="panel"><h2>Short-lived</h2>${flowTable(short.rows)}</div>
      </div>`;
      bindFlows();
      return;
    }
    if (state.inner === "detail") {
      main.innerHTML = `<div class="panel empty">Click a flow in Active or Elephant. The inspect drawer shows sequence + mini graph.</div>`;
      return;
    }
    const data = await API.flows(params(extra));
    const g = await API.graph(params({ kind: "conversations" }));
    main.innerHTML = `<section class="grid-12">
      <div class="panel span-5"><h2>Volume graph</h2><canvas id="c-g" height="560"></canvas>
        <button id="g-reset" class="ghost">Reset layout</button></div>
      <div class="panel span-7"><h2>Flows ${fmtNum(data.total)}</h2>${flowTable(data.rows)}${pager(data)}</div>
    </section>`;
    state.graphCtl = Charts.graph("#c-g", g, { onNode: (n) => filterHost(n.id), onEdge: (e) => e.flow_id && inspectFlow(e.flow_id) });
    $("#g-reset").onclick = () => state.graphCtl.reset();
    bindFlows();
    bindPager();
  }
  function flowTable(rows) {
    return table(["Start", "Orig → Resp", "Proto", "Bytes", "Dur", "State", "L7"],
      rows.map((f) => `
        <td class="mono">${esc(fmtTs(f.start_ts))}</td>
        <td class="mono linkish" data-flow="${f.id}">${esc(f.src_ip)}:${esc(f.src_port ?? "")} → ${esc(f.dst_ip)}:${esc(f.dst_port ?? "")}</td>
        <td>${esc(f.proto)}</td><td class="mono">${fmtNum(f.total_bytes)}</td>
        <td class="mono">${Number(f.duration || 0).toFixed(2)}s</td>
        <td>${esc(f.tcp_state || "")}</td><td>${esc(f.l7 || "")}</td>`),
      "No flows.");
  }
  function bindFlows() {
    main.querySelectorAll("[data-flow]").forEach((el) => el.addEventListener("click", () => inspectFlow(el.dataset.flow)));
  }

  async function renderAlerts() {
    const sevs = Object.entries(state.alert.sevs).filter(([, on]) => on).map(([k]) => k).join(",");
    const data = await API.alerts(params({
      limit: 200, offset: state.offset, severity: sevs,
      hide_demo: state.alert.hideDemo ? "true" : "",
      include_acked: state.alert.includeAcked ? "true" : "",
    }));
    const stats = await API.stats(params());
    const filters = `<div class="chk-row">
      ${["critical", "high", "medium", "low", "info"].map((s) =>
        `<label class="chk"><input type="checkbox" data-sev="${s}" ${state.alert.sevs[s] ? "checked" : ""} /> ${s}</label>`).join("")}
      <label class="chk"><input type="checkbox" id="hide-demo" ${state.alert.hideDemo ? "checked" : ""} /> Hide DEMO</label>
    </div>`;
    if (state.inner === "signature") {
      main.innerHTML = `<div class="panel"><h2>By signature</h2>${filters}
        <canvas id="c-s" height="180"></canvas>${barsHtml(stats.top_signatures, "signature", "hits")}</div>`;
      Charts.bars("#c-s", stats.top_signatures.map((x) => ({ name: x.signature, n: x.hits })));
      bindSev();
      return;
    }
    if (state.inner === "host") {
      main.innerHTML = `<div class="grid-2">
        <div class="panel"><h2>Alerting hosts</h2>${barsHtml(stats.top_alert_src, "ip", "n")}</div>
        <div class="panel"><h2>Victims</h2>${barsHtml(stats.top_alert_dst, "ip", "n")}</div>
      </div>`;
      return;
    }
    if (state.inner === "timeline") {
      main.innerHTML = `<div class="panel"><h2>Alert timeline</h2>${filters}<canvas id="c-tl" height="220"></canvas>
        <div class="legend"><span><i style="background:#ff4d4f"></i>Critical</span><span><i style="background:#ff7a45"></i>High</span>
        <span><i style="background:#f5c542"></i>Medium</span><span><i style="background:#3dd6d0"></i>Low</span>
        <span><i style="background:#7aa2ff"></i>Info</span></div></div>
        <div class="panel">${alertTable(data.rows.slice(0, 20))}</div>`;
      Charts.timeline("#c-tl", stats.alert_timeline);
      bindSev(); bindAlertClicks();
      return;
    }
    main.innerHTML = `<div class="panel"><h2>Feed (${fmtNum(data.total)})</h2>${filters}
      ${alertTable(data.rows)}${pager(data)}</div>`;
    bindSev(); bindAlertClicks(); bindPager();
  }
  function bindSev() {
    main.querySelectorAll("[data-sev]").forEach((el) => {
      el.addEventListener("change", () => { state.alert.sevs[el.dataset.sev] = el.checked; render(); });
    });
    $("#hide-demo")?.addEventListener("change", () => { state.alert.hideDemo = $("#hide-demo").checked; render(); });
  }

  async function renderHosts() {
    const data = await API.hosts(params({ limit: 200 }));
    const g = await API.graph(params({ kind: "hosts" }));
    if (state.inner === "relations") {
      main.innerHTML = `<div class="panel"><h2>Host relationships</h2><canvas id="c-g" height="560"></canvas>
        <button id="g-reset" class="ghost">Reset layout</button></div>`;
      state.graphCtl = Charts.graph("#c-g", g, { onNode: (n) => filterHost(n.id) });
      $("#g-reset").onclick = () => state.graphCtl.reset();
      return;
    }
    main.innerHTML = `<section class="grid-12">
      <div class="panel span-5"><h2>Map</h2><canvas id="c-g" height="560"></canvas></div>
      <div class="panel span-7"><h2>Hosts ${fmtNum(data.total)}</h2>
        ${table(["IP", "Out", "In", "Alerts"],
          data.rows.map((h) => `
            <td class="mono linkish" data-ip="${esc(h.ip)}">${esc(h.ip)}</td>
            <td class="mono">${fmtNum(h.bytes_out)}</td><td class="mono">${fmtNum(h.bytes_in)}</td>
            <td class="mono">${esc(h.alert_count)}</td>`), "No hosts.")}
      </div></section>`;
    Charts.graph("#c-g", g, { onNode: (n) => filterHost(n.id) });
    main.querySelectorAll("[data-ip]").forEach((el) => el.addEventListener("click", () => filterHost(el.dataset.ip)));
  }

  async function renderProtocols() {
    const stats = await API.stats(params());
    main.innerHTML = `<section class="grid-2">
      <div class="panel"><h2>Mix</h2><canvas id="c-pie" height="220"></canvas></div>
      <div class="panel"><h2>Stacked protocols</h2><canvas id="c-st" height="220"></canvas>
        <div class="legend"><span><i style="background:#7aa2ff"></i>TCP</span><span><i style="background:#3dd6d0"></i>UDP</span>
        <span><i style="background:#f5c542"></i>ICMP</span><span><i style="background:#c9a0ff"></i>ARP</span></div></div>
    </section>
    <div class="panel"><h2>TCP flags</h2><canvas id="c-f" height="160"></canvas>${barsHtml(stats.tcp_flags, "name", "n")}</div>
    <div class="panel"><h2>Top ports</h2><div class="heatmap">${(stats.ports || []).map((p) => {
      const n = Number(p.n || 0);
      return `<div class="heatcell" style="background:rgba(61,214,208,${Math.min(0.85, 0.2 + n / 80)})">${esc(p.port)}<br>${esc(p.proto)}<br>${fmtNum(n)}</div>`;
    }).join("")}</div></div>`;
    Charts.pie("#c-pie", stats.protocols);
    Charts.stacked("#c-st", stats.proto_stack, ["TCP", "UDP", "ICMP", "ARP", "OTHER"]);
    Charts.bars("#c-f", stats.tcp_flags);
  }

  async function renderMaps() {
    const kind = { l3: "conversations", l4: "services", hmap: "hosts", geo: "subnet", path: null, topo: "subnet" }[state.inner];
    if (state.inner === "path") {
      main.innerHTML = `<div class="panel"><h2>Data path</h2>${pathDiagram()}
        <p class="hint">Click a node on other map tabs to filter the global IP box.</p></div>`;
      return;
    }
    if (state.inner === "geo") {
      const g = await API.graph(params({ kind: "subnet" }));
      if (!g.geo) {
        main.innerHTML = `<div class="panel empty">No public IPs in this window — geo map hidden. Subnet split still available under Capture topology.</div>`;
        return;
      }
      main.innerHTML = `<div class="panel empty">Public IPs present, but GeoLite2 MMDB is not installed. Geo map stays stubbed on purpose.</div>
        <div class="panel"><h2>Internal vs external</h2><canvas id="c-g" height="560"></canvas></div>`;
      Charts.graph("#c-g", g, { onNode: (n) => filterHost(n.id) });
      return;
    }
    if (state.inner === "topo") {
      const h = await API.health();
      const g = await API.graph(params({ kind: "subnet" }));
      main.innerHTML = `<div class="panel"><h2>Capture topology</h2>
        <div class="path">
          <div class="box">${esc(h.iface || "iface")}</div><span class="arrow">→</span>
          <div class="box">${esc(h.capture?.source || "idle")}</div><span class="arrow">→</span>
          <div class="box">parser</div><span class="arrow">→</span>
          <div class="box">SQLite</div><span class="arrow">→</span>
          <div class="box">UI 127.0.0.1</div>
        </div></div>
        <div class="panel"><h2>Internal / external</h2><canvas id="c-g" height="560"></canvas>
          <button id="g-reset" class="ghost">Reset layout</button></div>`;
      state.graphCtl = Charts.graph("#c-g", g, { onNode: (n) => filterHost(n.id) });
      $("#g-reset").onclick = () => state.graphCtl.reset();
      return;
    }
    const g = await API.graph(params({ kind, show_more: state.showMore }));
    const title = { l3: "L3 conversation graph", l4: "L4 service map", hmap: "Host relationship map" }[state.inner];
    main.innerHTML = `<div class="panel"><h2>${title}</h2>
      <canvas id="c-g" height="560"></canvas>
      <div class="legend">
        <span><i style="background:#3dd6d0"></i>Internal host</span>
        <span><i style="background:#c9a0ff"></i>External</span>
        <span><i style="background:#7aa2ff"></i>TCP / service</span>
        <span><i style="background:#ff7a45"></i>Alerting</span>
        <label class="chk"><input type="checkbox" id="more" ${state.showMore ? "checked" : ""} /> Show more (top 60)</label>
        <button id="g-reset" class="ghost">Reset layout</button>
      </div></div>
      <div class="panel"><h2>Source → destination</h2><canvas id="c-sk" height="420"></canvas></div>`;
    state.graphCtl = Charts.graph("#c-g", g, {
      onNode: (n) => filterHost(n.id.replace(/^svc:/, "")),
      onEdge: (e) => e.flow_id && inspectFlow(e.flow_id),
    });
    Charts.sankey("#c-sk", g.edges, { onNode: (id) => filterHost(String(id).replace(/^svc:/, "")) });
    $("#g-reset").onclick = () => state.graphCtl.reset();
    $("#more").onchange = () => { state.showMore = $("#more").checked; render(); };
  }

  async function renderStatistics() {
    const stats = await API.stats(params());
    const ts = {
      pps: await API.timeseries(params({ metric: "pps" })),
      bps: await API.timeseries(params({ metric: "bps" })),
      flows: await API.timeseries(params({ metric: "flows" })),
      alerts: await API.timeseries(params({ metric: "alerts" })),
    };
    if (state.inner === "sizes") {
      main.innerHTML = `<div class="panel"><h2>Packet size</h2><canvas id="c-s" height="220"></canvas></div>
        <div class="panel"><h2>Top ports</h2><div class="heatmap">${(stats.ports || []).map((p) =>
          `<div class="heatcell">${esc(p.port)} ${esc(p.proto)} ${fmtNum(p.n)}</div>`).join("")}</div></div>`;
      Charts.bars("#c-s", stats.sizes);
      return;
    }
    if (state.inner === "iat") {
      main.innerHTML = `<div class="panel"><h2>Inter-arrival</h2>
        <p>mean ${esc(stats.interarrival.mean_ms)} ms · p50 ${esc(stats.interarrival.p50_ms)} · p95 ${esc(stats.interarrival.p95_ms)}</p>
        <h2>Direction</h2>${barsHtml([
          { name: "orig→resp", bytes: stats.direction.outbound },
          { name: "resp→orig", bytes: stats.direction.inbound },
        ], "name", "bytes")}</div>`;
      return;
    }
    main.innerHTML = `<section class="grid-2">
      <div class="panel"><h2>pps</h2><canvas id="a" height="160"></canvas></div>
      <div class="panel"><h2>bps</h2><canvas id="b" height="160"></canvas></div>
      <div class="panel"><h2>new flows</h2><canvas id="c" height="160"></canvas></div>
      <div class="panel"><h2>alert rate</h2><canvas id="d" height="160"></canvas></div>
    </section>`;
    Charts.area("#a", ts.pps.points, "#3dd6d0", { onBrush: brushRange });
    Charts.area("#b", ts.bps.points, "#7aa2ff", { onBrush: brushRange });
    Charts.area("#c", ts.flows.points, "#f5c542", { onBrush: brushRange });
    Charts.area("#d", ts.alerts.points, "#ff7a45", { onBrush: brushRange });
  }

  async function renderHealth() {
    const h = await API.health();
    if (state.inner === "tools") {
      main.innerHTML = `<div class="panel"><h2>Local tools</h2><pre>${esc(JSON.stringify(h.tools, null, 2))}</pre></div>`;
      return;
    }
    main.innerHTML = `${kpiRow({ pps: 0, bps: 0, active_flows: 0, alert_rate: 0, unique_hosts: 0, drops: h.iface_stats?.rx_dropped }, { pps: [], flows: [], alerts: [] })}
      <div class="panel"><h2>Path</h2>${pathDiagram()}</div>
      <div class="grid-2">
        <div class="panel"><h2>Sensor</h2><pre>${esc(JSON.stringify({ iface: h.iface, capture: h.capture, stats: h.iface_stats, demo: h.demo_loaded }, null, 2))}</pre></div>
        <div class="panel"><h2>Database</h2><p>packets ${fmtNum(h.packets)} · flows ${fmtNum(h.flows)} · alerts ${fmtNum(h.alerts)} · ${fmtNum(h.db_bytes)} bytes</p></div>
      </div>`;
  }

  async function renderSettings() {
    const [health, sensor, settings] = await Promise.all([API.health(), API.sensor(), API.settings()]);
    const ifaces = settings.ifaces || sensor.ifaces || [];
    const presets = settings.bpf_presets || state.meta?.bpf_presets || [];
    main.innerHTML = `<section class="grid-2">
      <div class="panel">
        <h2>Capture</h2>
        <label class="field"><span>Interface</span><select id="iface">${ifaces.map((i) =>
          `<option value="${esc(i.name)}" ${settings.iface === i.name ? "selected" : ""}>${esc(i.label || i.name)}</option>`).join("")}</select></label>
        <label class="field"><span>BPF preset</span><select id="set-bpf">${presets.map((p) =>
          `<option value="${esc(p.id)}">${esc(p.label)}</option>`).join("")}</select></label>
        <label class="field hidden" id="set-bpf-custom-wrap"><span>Custom</span><input id="bpf" value="${esc(settings.bpf || "")}" /></label>
        <div class="chk-row">
          <label class="chk"><input type="checkbox" id="opt-pcap" ${settings.store_pcap ? "checked" : ""} /> Rotating PCAP</label>
          <label class="chk"><input type="checkbox" id="opt-payload" ${settings.payload_enabled ? "checked" : ""} /> Payload previews (capped)</label>
          <label class="chk"><input type="checkbox" id="opt-demo" ${settings.autoload_demo ? "checked" : ""} /> Autoload DEMO</label>
        </div>
        <div class="filters">
          <button id="save-set" class="primary">Save</button>
          <button id="cap-start" class="primary">Start live</button>
          <button id="cap-stop">Stop</button>
        </div>
        <p class="hint">Live capture needs group wireshark / dumpcap capabilities. Bind stays localhost.</p>
      </div>
      <div class="panel">
        <h2>Demo / PCAP</h2>
        <button id="load-demo" class="primary">Load DEMO dataset</button>
        <p class="hint">Replaces telemetry. Alerts tagged DEMO.</p>
        <form id="pcap-form">
          <input type="file" id="pcap-file" accept=".pcap,.pcapng,*" />
          <label class="chk"><input type="checkbox" id="pcap-replace" checked /> Replace telemetry</label>
          <button type="submit">Ingest</button>
        </form>
      </div>
    </section>`;
    const bpfVal = () => {
      const id = $("#set-bpf").value;
      if (id === "custom") return ($("#bpf").value || "").trim();
      const p = presets.find((x) => x.id === id);
      return p && p.bpf != null ? p.bpf : "";
    };
    $("#set-bpf").onchange = () => $("#set-bpf-custom-wrap").classList.toggle("hidden", $("#set-bpf").value !== "custom");
    const collect = () => ({
      iface: $("#iface").value, bpf: bpfVal(),
      store_pcap: $("#opt-pcap").checked, payload_enabled: $("#opt-payload").checked, autoload_demo: $("#opt-demo").checked,
    });
    $("#save-set").onclick = async () => { await API.saveSettings(collect()); await refreshMeta(); render(); };
    $("#cap-start").onclick = async () => { try { const b = collect(); await API.saveSettings(b); await API.startLive(b); await refreshMeta(); render(); } catch (e) { showErr(e); } };
    $("#cap-stop").onclick = async () => { await API.stopLive(); await refreshMeta(); render(); };
    $("#load-demo").onclick = async () => { await API.loadDemo(); $("#demo-flag").classList.remove("off"); await refreshMeta(); render(); };
    $("#pcap-form").onsubmit = async (e) => {
      e.preventDefault();
      const f = $("#pcap-file").files[0];
      if (!f) return;
      const fd = new FormData(); fd.append("file", f);
      const r = await fetch("/api/pcap/load?replace=" + $("#pcap-replace").checked, { method: "POST", body: fd });
      if (!r.ok) showErr(new Error("upload failed")); else { await refreshMeta(); render(); }
    };
    void health;
  }

  async function render() {
    clearErr();
    drawTabs();
    try {
      if (state.page === "overview") {
        const [kpis, stats, pps, alerts, flows, al] = await Promise.all([
          API.kpis(params()), API.stats(params()),
          API.timeseries(params({ metric: "pps" })),
          API.alerts(params({ limit: 8 })),
          API.timeseries(params({ metric: "flows" })),
          API.timeseries(params({ metric: "alerts" })),
        ]);
        await renderOverview(kpis, stats, { pps: pps.points, flows: flows.points, alerts: al.points }, alerts);
      } else if (state.page === "packets") await renderPackets();
      else if (state.page === "flows") await renderFlows();
      else if (state.page === "alerts") await renderAlerts();
      else if (state.page === "hosts") await renderHosts();
      else if (state.page === "protocols") await renderProtocols();
      else if (state.page === "maps") await renderMaps();
      else if (state.page === "statistics") await renderStatistics();
      else if (state.page === "health") await renderHealth();
      else if (state.page === "settings") await renderSettings();
    } catch (e) {
      showErr(e);
      main.innerHTML = `<div class="panel empty">${esc(e.message)}</div>`;
    }
  }

  function opts(items, selected) {
    return (items || []).map((i) => {
      const val = i.name || i.id || i;
      const lab = i.label || i.name || i;
      return `<option value="${esc(val)}" ${String(val) === String(selected) ? "selected" : ""}>${esc(lab)}</option>`;
    }).join("");
  }
  function currentBpf() {
    const preset = $("#global-bpf")?.value;
    if (preset === "custom") return ($("#global-bpf-custom")?.value || "").trim();
    const found = (state.meta?.bpf_presets || []).find((p) => p.id === preset);
    return found && found.bpf != null ? found.bpf : "";
  }
  async function refreshMeta() {
    state.meta = await API.meta();
    const ifaces = state.meta.ifaces || [];
    const presets = state.meta.bpf_presets || [];
    $("#global-iface").innerHTML = opts(ifaces, state.meta.settings?.iface);
    $("#global-bpf").innerHTML = presets.map((p) => `<option value="${esc(p.id)}">${esc(p.label)}</option>`).join("");
    setLiveUi(!!state.meta.capture?.running);
    if (state.meta.settings && (await API.health()).demo_loaded) $("#demo-flag").classList.remove("off");
    return state.meta;
  }
  function setLiveUi(running) {
    state.live = running;
    const b = $("#btn-live");
    b.textContent = running ? "Stop live" : "Start live";
    b.classList.toggle("live-on", running);
  }

  document.querySelectorAll("#timepicker button").forEach((b) => {
    b.addEventListener("click", () => {
      state.range = b.dataset.range;
      state.tsFrom = null;
      state.tsTo = null;
      document.querySelectorAll("#timepicker button").forEach((x) => x.classList.toggle("on", x === b));
      writeHash(); render();
    });
  });
  $("#q").addEventListener("keydown", (e) => { if (e.key === "Enter") { state.q = e.target.value.trim(); writeHash(); render(); } });
  $("#g-ip").addEventListener("change", () => { state.ip = $("#g-ip").value.trim(); writeHash(); render(); });
  $("#g-port").addEventListener("change", () => { state.port = $("#g-port").value.trim(); writeHash(); render(); });
  $("#g-proto").addEventListener("change", () => { state.proto = $("#g-proto").value; writeHash(); render(); });
  $("#autorefresh").addEventListener("change", (e) => { state.paused = !e.target.checked; });
  $("#refresh-interval").addEventListener("change", (e) => { state.refreshMs = Number(e.target.value) || 5000; });
  $("#global-bpf").addEventListener("change", () => {
    $("#bpf-custom-wrap").classList.toggle("hidden", $("#global-bpf").value !== "custom");
    API.saveSettings({ iface: $("#global-iface").value, bpf: currentBpf() }).catch(() => {});
  });
  $("#global-iface").addEventListener("change", () => {
    API.saveSettings({ iface: $("#global-iface").value, bpf: currentBpf() }).catch(() => {});
  });
  $("#btn-live").addEventListener("click", async () => {
    try {
      if (state.live) { await API.stopLive(); setLiveUi(false); }
      else {
        const body = { iface: $("#global-iface").value, bpf: currentBpf() };
        await API.saveSettings(body); await API.startLive(body); setLiveUi(true);
      }
      await refreshMeta();
    } catch (e) { showErr(e); }
  });
  window.addEventListener("hashchange", () => { readHash(); drawTabs(); render(); });
  window.addEventListener("keydown", (e) => {
    const tag = (e.target && e.target.tagName) || "";
    if (["INPUT", "SELECT", "TEXTAREA"].includes(tag)) return;
    if (e.ctrlKey && e.key >= "1" && e.key <= "9") {
      const t = TABS[Number(e.key) - 1];
      if (t) { e.preventDefault(); go(t.id, t.inner[0][0]); }
    }
    if (e.key === "[" || e.key === "]") {
      const i = TABS.findIndex((t) => t.id === state.page);
      const n = e.key === "]" ? (i + 1) % TABS.length : (i - 1 + TABS.length) % TABS.length;
      go(TABS[n].id, TABS[n].inner[0][0]);
    }
  });

  async function tickStatus() {
    try {
      const h = await API.health();
      const k = await API.kpis({ range: "5m" });
      $("#health-pill").textContent = h.ok ? "healthy" : "degraded";
      $("#health-pill").className = "pill " + (h.ok ? "low" : "high");
      $("#sb-iface").textContent = "iface " + (h.iface || "—") + " / " + (h.capture?.source || "idle");
      $("#sb-pps").textContent = "pps " + fmtNum(k.pps);
      $("#sb-bps").textContent = fmtBps(k.bps);
      $("#sb-drops").textContent = "drops " + fmtNum(k.drops);
      $("#sb-bind").textContent = "bind " + h.bind;
      state.badges = { alerts: k.alerts || 0, pps: k.pps || 0, drops: k.drops || 0 };
      drawTabs();
      setLiveUi(!!h.capture?.running);
      $("#demo-flag").classList.toggle("off", !h.demo_loaded);
    } catch (_) {
      $("#health-pill").textContent = "api down";
      $("#health-pill").className = "pill critical";
    }
  }
  function connectWs() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws/live`);
    state.ws = ws;
    ws.onopen = () => { $("#sb-ws").textContent = "ws live"; };
    ws.onclose = () => { $("#sb-ws").textContent = "ws down"; setTimeout(connectWs, 4000); };
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "kpi" && msg.data) {
          $("#sb-pps").textContent = "pps " + fmtNum(msg.data.pps);
          $("#sb-bps").textContent = fmtBps(msg.data.bps);
        }
      } catch (_) {}
    };
  }
  let tickTimer = null;
  function loopTick() {
    if (tickTimer) clearTimeout(tickTimer);
    tickTimer = setTimeout(async () => {
      if (!state.paused) {
        tickStatus();
        if (state.page === "overview" && state.inner === "pulse") render().catch(() => {});
        if (state.page === "maps" && !state.paused) render().catch(() => {});
      }
      loopTick();
    }, state.refreshMs);
  }

  readHash();
  $("#g-ip").value = state.ip;
  $("#g-port").value = state.port;
  $("#g-proto").value = state.proto;
  $("#q").value = state.q;
  document.querySelectorAll("#timepicker button").forEach((b) => b.classList.toggle("on", b.dataset.range === state.range));
  drawTabs();
  refreshMeta().catch(() => {});
  render();
  tickStatus();
  connectWs();
  loopTick();
})();
