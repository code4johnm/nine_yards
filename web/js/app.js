(() => {
  const state = {
    page: "overview",
    range: "15m",
    q: "",
    paused: false,
    offset: 0,
    sort: {},
    ws: null,
  };

  const $ = (sel) => document.querySelector(sel);
  const main = $("#main");
  const banner = $("#banner");
  const demoBanner = $("#demo-banner");

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
    const d = new Date(Number(ts) * 1000);
    return d.toISOString().replace("T", " ").replace("Z", "");
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
  function clearErr() {
    banner.classList.add("hidden");
    banner.classList.remove("error");
  }
  function params(extra) {
    return Object.assign({ range: state.range, q: state.q }, extra || {});
  }
  function pill(sev) {
    sev = (sev || "info").toLowerCase();
    return `<span class="pill ${esc(sev)}">${esc(sev)}</span>`;
  }

  function setPage() {
    const hash = (location.hash || "#/overview").replace("#/", "").split("?")[0];
    state.page = hash || "overview";
    state.offset = 0;
    document.querySelectorAll(".nav a").forEach((a) => {
      a.classList.toggle("active", a.dataset.page === state.page);
    });
    render();
  }

  document.querySelectorAll("#timepicker button").forEach((b) => {
    b.addEventListener("click", () => {
      state.range = b.dataset.range;
      document.querySelectorAll("#timepicker button").forEach((x) => x.classList.toggle("on", x === b));
      render();
    });
  });
  $("#q").addEventListener("input", (e) => {
    state.q = e.target.value.trim();
  });
  $("#q").addEventListener("keydown", (e) => {
    if (e.key === "Enter") render();
  });
  $("#btn-pause").addEventListener("click", () => {
    state.paused = !state.paused;
    $("#autorefresh").checked = !state.paused;
    $("#btn-pause").textContent = state.paused ? "Resume" : "Pause";
  });
  $("#autorefresh").addEventListener("change", (e) => {
    state.paused = !e.target.checked;
    $("#btn-pause").textContent = state.paused ? "Resume" : "Pause";
  });
  $("#modal-close").addEventListener("click", () => $("#modal").classList.add("hidden"));
  window.addEventListener("hashchange", setPage);

  function modal(title, obj) {
    $("#modal-title").textContent = title;
    $("#modal-body").textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
    $("#modal").classList.remove("hidden");
  }

  function table(headers, rows, empty) {
    if (!rows.length) return `<div class="empty">${esc(empty || "No data in this time range.")}</div>`;
    const th = headers.map((h) => `<th data-sort="${esc(h.sort || "")}">${esc(h.label)}</th>`).join("");
    const body = rows.map((r) => `<tr>${r}</tr>`).join("");
    return `<div class="table-wrap"><table><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function barsHtml(items, nameKey, valKey) {
    const max = Math.max(1, ...items.map((i) => Number(i[valKey] || 0)));
    return items.map((i) => {
      const n = Number(i[valKey] || 0);
      const pct = Math.round((n / max) * 100);
      return `<div class="bar-row"><span class="lab mono" title="${esc(i[nameKey])}">${esc(i[nameKey])}</span>
        <div class="track"><div class="fill" style="width:${pct}%"></div></div>
        <span class="mono">${fmtNum(n)}</span></div>`;
    }).join("") || `<div class="empty">No series.</div>`;
  }

  async function renderOverview() {
    const [kpis, tsPps, tsAlerts, tsFlows, stats, alerts] = await Promise.all([
      API.kpis(params()),
      API.timeseries(params({ metric: "pps" })),
      API.timeseries(params({ metric: "alerts" })),
      API.timeseries(params({ metric: "flows" })),
      API.stats(params()),
      API.alerts(params({ limit: 8 })),
    ]);
    if (kpis.demo) demoBanner.classList.remove("hidden");
    else demoBanner.classList.add("hidden");
    main.innerHTML = `
      <section class="kpis">
        ${kpiCard("pps", fmtNum(kpis.pps), tsPps.points)}
        ${kpiCard("bps", fmtBps(kpis.bps), tsPps.points)}
        ${kpiCard("active flows", fmtNum(kpis.active_flows), tsFlows.points)}
        ${kpiCard("alert rate", fmtNum(kpis.alert_rate) + "/s", tsAlerts.points)}
        ${kpiCard("unique hosts", fmtNum(kpis.unique_hosts))}
        ${kpiCard("drops / errors", fmtNum(kpis.drops) + " / " + fmtNum(kpis.errors))}
      </section>
      <section class="grid-2">
        <div class="panel"><h2>Traffic volume</h2><canvas id="c-pps" height="140"></canvas></div>
        <div class="panel"><h2>Alert rate</h2><canvas id="c-al" height="140"></canvas></div>
      </section>
      <section class="grid-3">
        <div class="panel"><h2>Top talkers</h2>${barsHtml(stats.talkers, "ip", "bytes")}</div>
        <div class="panel"><h2>Top destinations</h2>${barsHtml(stats.destinations, "ip", "bytes")}</div>
        <div class="panel"><h2>Applications</h2><canvas id="c-app" height="160"></canvas></div>
      </section>
      <section class="panel">
        <div class="panel-head"><h2>Latest alerts</h2><a href="#/alerts">Open feed</a></div>
        ${alertTable(alerts.rows)}
      </section>`;
    Charts.area("#c-pps", tsPps.points, "#3dd6c6");
    Charts.area("#c-al", tsAlerts.points, "#ff8c42");
    Charts.pie("#c-app", stats.apps);
    bindAlertActions();
  }

  function kpiCard(label, value, spark) {
    const id = "sp-" + label.replace(/\W+/g, "");
    return `<div class="kpi"><div class="k">${esc(label)}</div><div class="v">${esc(value)}</div>
      <canvas id="${id}"></canvas></div>`;
  }

  function alertTable(rows) {
    return table(
      [
        { label: "Sev" }, { label: "When" }, { label: "Signature" }, { label: "Src" },
        { label: "Dst" }, { label: "Count" }, { label: "Src sensor" }, { label: "" },
      ],
      rows.map((a) => `
        <td>${pill(a.severity)}${a.is_demo ? ' <span class="pill demo">DEMO</span>' : ""}</td>
        <td class="mono">${esc(fmtTs(a.last_seen))}</td>
        <td class="linkish" data-json='${esc(JSON.stringify(a))}'>${esc(a.signature)}</td>
        <td class="mono linkish" data-ip="${esc(a.src_ip || "")}">${esc(a.src_ip || "—")}</td>
        <td class="mono">${esc(a.dst_ip || "—")}${a.dst_port ? ":" + a.dst_port : ""}</td>
        <td class="mono">${esc(a.count)}</td>
        <td>${esc(a.source || "")}</td>
        <td>
          <button class="ghost" data-ack="${a.id}">Ack</button>
          <button class="ghost" data-mute="${a.id}">Mute</button>
        </td>`),
      "No alerts in range. Load demo data from Settings if this is a new install."
    );
  }

  async function renderPackets() {
    const data = await API.packets(params({ limit: 200, offset: state.offset }));
    main.innerHTML = `
      <div class="panel">
        <div class="panel-head">
          <h2>Packets <span class="muted">${fmtNum(data.total)}</span></h2>
          <div>
            <a href="${API.exportUrl("packets", state.range, "csv")}">CSV</a>
            · <a href="${API.exportUrl("packets", state.range, "json")}">JSON</a>
          </div>
        </div>
        <div class="filters">
          <input id="f-ip" placeholder="IP" />
          <input id="f-port" placeholder="Port" type="number" />
          <input id="f-proto" placeholder="Proto (TCP/UDP)" />
          <button id="f-go" class="primary">Apply</button>
        </div>
        ${table(
          [
            { label: "Time" }, { label: "Src" }, { label: "Dst" }, { label: "Proto" },
            { label: "Len" }, { label: "Flags" }, { label: "VLAN" }, { label: "L7 / info" },
          ],
          data.rows.map((p) => `
            <td class="mono">${esc(fmtTs(p.ts))}</td>
            <td class="mono">${esc(p.src_ip || "")}${p.src_port != null ? ":" + p.src_port : ""}</td>
            <td class="mono">${esc(p.dst_ip || "")}${p.dst_port != null ? ":" + p.dst_port : ""}</td>
            <td>${esc(p.proto)}</td>
            <td class="mono">${esc(p.length)}</td>
            <td class="mono">${esc(p.tcp_flags_s || "")}</td>
            <td class="mono">${p.vlan ?? "—"}</td>
            <td class="linkish" data-pkt="${p.id}">${esc(p.l7 || "")} ${esc(p.info || p.sni || "")}${p.is_retrans ? " RETRANS" : ""}</td>`),
          "No packets. Start live capture or load the DEMO dataset."
        )}
        ${pager(data)}
      </div>`;
    $("#f-go")?.addEventListener("click", async () => {
      const extra = {
        ip: $("#f-ip").value,
        port: $("#f-port").value,
        proto: $("#f-proto").value,
        limit: 200,
        offset: 0,
      };
      const d = await API.packets(params(extra));
      renderPacketRows(d);
    });
    main.querySelectorAll("[data-pkt]").forEach((el) => {
      el.addEventListener("click", () => openPacket(el.dataset.pkt));
    });
    bindPager();
  }

  function renderPacketRows() {}

  async function openPacket(id) {
    const p = await API.packet(id);
    let extra = "";
    try {
      const pay = await API.payload(id);
      extra = `\n\n--- payload (capped) ---\nHEX:\n${pay.hex || "(empty)"}\nASCII:\n${pay.ascii || ""}`;
    } catch (e) {
      extra = `\n\nPayload viewer: ${e.message}`;
    }
    modal("Packet " + id, JSON.stringify(p, null, 2) + extra);
  }

  async function renderFlows() {
    main.innerHTML = `
      <div class="filters">
        <button data-view="">All</button>
        <button data-view="elephant">Elephant</button>
        <button data-view="scan">Scan-like</button>
        <button data-view="long">Long-lived</button>
        <button data-view="short">Short-lived</button>
        <a href="${API.exportUrl("flows", state.range, "csv")}">CSV</a>
      </div>
      <div class="panel" id="flow-panel"></div>`;
    async function load(view) {
      const data = await API.flows(params({ view, limit: 200, offset: state.offset, sort: "bytes" }));
      $("#flow-panel").innerHTML = `
        <div class="panel-head"><h2>Flows ${fmtNum(data.total)}</h2></div>
        ${table(
          [
            { label: "Start" }, { label: "Orig → Resp" }, { label: "Proto" }, { label: "Pkts" },
            { label: "Bytes" }, { label: "Dur" }, { label: "State" }, { label: "Flags" }, { label: "L7" },
          ],
          data.rows.map((f) => `
            <td class="mono">${esc(fmtTs(f.start_ts))}</td>
            <td class="mono linkish" data-flow="${f.id}">${esc(f.src_ip)}:${esc(f.src_port ?? "")} → ${esc(f.dst_ip)}:${esc(f.dst_port ?? "")}</td>
            <td>${esc(f.proto)}</td>
            <td class="mono">${esc(f.packets)}/${esc(f.packets_rev)}</td>
            <td class="mono">${fmtNum(f.total_bytes)}</td>
            <td class="mono">${Number(f.duration || 0).toFixed(3)}s</td>
            <td>${esc(f.tcp_state || "")}</td>
            <td class="mono">${esc(f.tcp_flags_s || "")}</td>
            <td>${esc(f.l7 || "")} ${esc(f.sni || "")}</td>`),
          "No flows in range."
        )}${pager(data)}`;
      $("#flow-panel").querySelectorAll("[data-flow]").forEach((el) => {
        el.addEventListener("click", () => openFlow(el.dataset.flow));
      });
      bindPager(() => load(view));
    }
    main.querySelectorAll("[data-view]").forEach((b) => {
      b.addEventListener("click", () => {
        main.querySelectorAll("[data-view]").forEach((x) => x.classList.toggle("on", x === b));
        state.offset = 0;
        load(b.dataset.view);
      });
    });
    main.querySelector("[data-view='']").classList.add("on");
    await load("");
  }

  async function openFlow(id) {
    const f = await API.flow(id);
    const pkts = await API.packets({ flow_id: id, limit: 80, range: "7d" });
    modal("Flow " + id, { flow: f, packets: pkts.rows });
  }

  async function renderAlerts() {
    const data = await API.alerts(params({ limit: 250 }));
    const stats = await API.stats(params());
    if (data.demo) demoBanner.classList.remove("hidden");
    main.innerHTML = `
      <section class="grid-3">
        <div class="panel"><h2>Top signatures</h2>${barsHtml(stats.top_signatures, "signature", "hits")}</div>
        <div class="panel"><h2>Alerting hosts</h2>${barsHtml(stats.top_alert_src, "ip", "n")}</div>
        <div class="panel"><h2>Victim hosts</h2>${barsHtml(stats.top_alert_dst, "ip", "n")}</div>
      </section>
      <div class="panel">
        <div class="panel-head">
          <h2>Alert feed (${fmtNum(data.total)})</h2>
          <a href="${API.exportUrl("alerts", state.range, "csv")}">CSV</a>
        </div>
        ${alertTable(data.rows)}
        ${pager(data)}
      </div>`;
    bindAlertActions();
    bindPager();
  }

  function bindAlertActions() {
    main.querySelectorAll("[data-ack]").forEach((b) => {
      b.addEventListener("click", async () => { await API.ack(b.dataset.ack); render(); });
    });
    main.querySelectorAll("[data-mute]").forEach((b) => {
      b.addEventListener("click", async () => { await API.mute(b.dataset.mute); render(); });
    });
    main.querySelectorAll("[data-json]").forEach((el) => {
      el.addEventListener("click", () => modal("Alert", el.dataset.json));
    });
    main.querySelectorAll("[data-ip]").forEach((el) => {
      el.addEventListener("click", () => { location.hash = "#/hosts"; state.q = el.dataset.ip; $("#q").value = state.q; });
    });
  }

  async function renderProtocols() {
    const stats = await API.stats(params());
    const ts = await API.timeseries(params({ metric: "pps" }));
    main.innerHTML = `
      <section class="grid-2">
        <div class="panel"><h2>Protocol mix</h2><canvas id="c-proto" height="200"></canvas></div>
        <div class="panel"><h2>Packet size histogram</h2><canvas id="c-sz" height="200"></canvas></div>
      </section>
      <section class="grid-2">
        <div class="panel"><h2>TCP flags</h2>${barsHtml(stats.tcp_flags, "name", "n")}</div>
        <div class="panel">
          <h2>Inter-arrival</h2>
          <p class="muted">mean ${esc(stats.interarrival.mean_ms)} ms · p50 ${esc(stats.interarrival.p50_ms)} · p95 ${esc(stats.interarrival.p95_ms)}</p>
          <h2>Inbound vs outbound bytes</h2>
          ${barsHtml([
            { name: "orig→resp", bytes: stats.direction.outbound },
            { name: "resp→orig", bytes: stats.direction.inbound },
          ], "name", "bytes")}
        </div>
      </section>
      <div class="panel">
        <h2>Top destination ports</h2>
        <div class="heatmap">
          ${(stats.ports || []).map((p) => {
            const n = Number(p.n || 0);
            const alpha = Math.min(0.85, 0.15 + n / 80);
            return `<div class="heatcell" style="background:rgba(61,214,198,${alpha})">${esc(p.port)}<br>${esc(p.proto)}<br>${fmtNum(n)}</div>`;
          }).join("")}
        </div>
      </div>
      <div class="panel"><h2>Packet rate</h2><canvas id="c-rate" height="140"></canvas></div>
      <div class="panel"><h2>Geo</h2><div class="empty">Geo map stubbed — GeoLite2 MMDB not installed. Legacy GeoIP.dat is present on this host but unused.</div></div>
    `;
    Charts.pie("#c-proto", stats.protocols);
    Charts.bars("#c-sz", stats.sizes, "#5b8def");
    Charts.area("#c-rate", ts.points);
  }

  async function renderHosts() {
    const data = await API.hosts(params({ limit: 250 }));
    main.innerHTML = `
      <div class="panel">
        <div class="panel-head"><h2>Hosts ${fmtNum(data.total)}</h2></div>
        ${table(
          [
            { label: "IP" }, { label: "First" }, { label: "Last" }, { label: "Bytes out" },
            { label: "Bytes in" }, { label: "Pkts out/in" }, { label: "Alerts" },
          ],
          data.rows.map((h) => `
            <td class="mono linkish" data-host="${esc(h.ip)}">${esc(h.ip)}</td>
            <td class="mono">${esc(fmtTs(h.first_seen))}</td>
            <td class="mono">${esc(fmtTs(h.last_seen))}</td>
            <td class="mono">${fmtNum(h.bytes_out)}</td>
            <td class="mono">${fmtNum(h.bytes_in)}</td>
            <td class="mono">${fmtNum(h.packets_out)} / ${fmtNum(h.packets_in)}</td>
            <td class="mono">${esc(h.alert_count)}</td>`),
          "No hosts observed."
        )}
      </div>`;
    main.querySelectorAll("[data-host]").forEach((el) => {
      el.addEventListener("click", async () => {
        const h = await API.host(el.dataset.host, { range: state.range });
        modal("Host " + el.dataset.host, h);
      });
    });
  }

  async function renderSettings() {
    const [health, sensor, settings] = await Promise.all([API.health(), API.sensor(), API.settings()]);
    const tools = health.tools || {};
    const ifaces = (sensor.ifaces || []).map((i) => `<option value="${esc(i.name)}">${esc(i.label || i.name)}</option>`).join("");
    main.innerHTML = `
      <section class="grid-2">
        <div class="panel">
          <h2>Sensor</h2>
          <p>Status: <span class="pill info">${esc(sensor.status || "idle")}</span> source ${esc(sensor.source || "")}</p>
          <p class="muted">Live capture needs group <span class="mono">wireshark</span> (dumpcap has cap_net_raw). Default bind is localhost.</p>
          <div class="filters">
            <select id="iface">${ifaces}</select>
            <input id="bpf" placeholder="optional BPF (tcp port 80)" value="${esc(settings.bpf || "")}" />
            <button id="cap-start" class="primary">Start live</button>
            <button id="cap-stop">Stop</button>
          </div>
          <p>Interface counters: drops ${fmtNum(health.iface_stats?.rx_dropped)} errors ${fmtNum(health.iface_stats?.rx_errors)}</p>
          <p>Last error: ${esc(health.capture?.last_error || sensor.last_error || "none")}</p>
        </div>
        <div class="panel">
          <h2>Demo / PCAP</h2>
          <p>The dashboard is usable without a tap. Reload the labeled DEMO corpus:</p>
          <button id="load-demo" class="primary">Load DEMO dataset</button>
          <p class="muted">Replaces current telemetry. Alerts tagged DEMO.</p>
          <form id="pcap-form">
            <label>Upload PCAP (metadata only)
              <input type="file" id="pcap-file" accept=".pcap,.pcapng,*" />
            </label>
            <button type="submit">Ingest PCAP</button>
          </form>
        </div>
      </section>
      <section class="grid-2">
        <div class="panel">
          <h2>Health</h2>
          <pre>${esc(JSON.stringify({
            version: health.version,
            bind: health.bind,
            db_bytes: health.db_bytes,
            packets: health.packets,
            flows: health.flows,
            alerts: health.alerts,
            payload_enabled: health.payload_enabled,
            geoip: health.geoip,
          }, null, 2))}</pre>
        </div>
        <div class="panel">
          <h2>Local tools</h2>
          <pre>${esc(JSON.stringify(tools, null, 2))}</pre>
        </div>
      </section>
      <div class="panel">
        <h2>Operator notes</h2>
        <ul>
          <li>Payloads are not stored unless <span class="mono">NIDS_STORE_PAYLOAD=1</span>.</li>
          <li>Capture files land in <span class="mono">data/capture</span> mode 0700, rotated by dumpcap when enabled.</li>
          <li>Optional: set <span class="mono">NIDS_SURICATA_EVE</span> / <span class="mono">NIDS_ZEEK_DIR</span> to tail real NSM logs.</li>
          <li>Optional API token: <span class="mono">NIDS_TOKEN</span>.</li>
        </ul>
      </div>`;
    $("#cap-start").addEventListener("click", async () => {
      try {
        await API.startLive({ iface: $("#iface").value, bpf: $("#bpf").value });
        render();
      } catch (e) { showErr(e); }
    });
    $("#cap-stop").addEventListener("click", async () => { await API.stopLive(); render(); });
    $("#load-demo").addEventListener("click", async () => {
      await API.loadDemo();
      demoBanner.classList.remove("hidden");
      render();
    });
    $("#pcap-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = $("#pcap-file").files[0];
      if (!f) return;
      const fd = new FormData();
      fd.append("file", f);
      const r = await fetch("/api/pcap/load?replace=true", { method: "POST", body: fd });
      if (!r.ok) showErr(new Error("upload failed"));
      else render();
    });
  }

  function pager(data) {
    const total = data.total || 0;
    return `<div class="pager">
      <button id="pg-prev">Prev</button>
      <span>${state.offset + 1}–${Math.min(state.offset + (data.limit || 200), total)} of ${fmtNum(total)}</span>
      <button id="pg-next">Next</button>
    </div>`;
  }
  function bindPager(reload) {
    $("#pg-prev")?.addEventListener("click", () => {
      state.offset = Math.max(0, state.offset - 200);
      (reload || render)();
    });
    $("#pg-next")?.addEventListener("click", () => {
      state.offset += 200;
      (reload || render)();
    });
  }

  async function render() {
    clearErr();
    try {
      if (state.page === "overview") await renderOverview();
      else if (state.page === "packets") await renderPackets();
      else if (state.page === "flows") await renderFlows();
      else if (state.page === "alerts") await renderAlerts();
      else if (state.page === "protocols") await renderProtocols();
      else if (state.page === "hosts") await renderHosts();
      else if (state.page === "settings") await renderSettings();
      afterPaintSparks();
    } catch (e) {
      showErr(e);
      if (state.page !== "settings") {
        main.innerHTML = `<div class="panel empty">
          ${esc(e.message)}. If this is a fresh install, open Settings and load DEMO data, or check that the API is up.
        </div>`;
      }
    }
  }

  function afterPaintSparks() {
    document.querySelectorAll(".kpi canvas").forEach((c) => {
      Charts.line(c, [1, 2, 1.5, 3, 2, 4, 3], "#3dd6c6");
    });
  }

  async function tickStatus() {
    try {
      const h = await API.health();
      const k = await API.kpis({ range: "5m" });
      $("#health-pill").textContent = h.ok ? "healthy" : "degraded";
      $("#health-pill").className = "pill " + (h.ok ? "low" : "high");
      $("#sb-iface").textContent = "iface " + (h.iface || "—") + " / " + (h.capture?.source || h.sensor?.source || "idle");
      $("#sb-pps").textContent = "pps " + fmtNum(k.pps);
      $("#sb-bps").textContent = fmtBps(k.bps);
      $("#sb-drops").textContent = "drops " + fmtNum(k.drops);
      $("#sb-bind").textContent = "bind " + h.bind;
      if (h.demo_loaded) demoBanner.classList.remove("hidden");
    } catch (e) {
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
    ws.onerror = () => { $("#sb-ws").textContent = "ws err"; };
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

  setInterval(() => {
    if (!state.paused) {
      tickStatus();
      if (state.page === "overview") renderOverview().catch(() => {});
    }
  }, 4000);

  setPage();
  tickStatus();
  connectWs();
})();
