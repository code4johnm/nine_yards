(function (g) {
  async function req(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) {
      let detail = r.statusText;
      try {
        const j = await r.json();
        detail = j.detail || JSON.stringify(j);
      } catch (_) {}
      throw new Error(detail);
    }
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) return r.json();
    return r.text();
  }
  const qs = (obj) => {
    const u = new URLSearchParams();
    Object.entries(obj || {}).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") u.set(k, v);
    });
    return u.toString();
  };
  g.API = {
    health: () => req("/api/health"),
    kpis: (p) => req("/api/kpis?" + qs(p)),
    timeseries: (p) => req("/api/timeseries?" + qs(p)),
    packets: (p) => req("/api/packets?" + qs(p)),
    packet: (id) => req("/api/packets/" + id),
    payload: (id) => req("/api/packets/" + id + "/payload"),
    flows: (p) => req("/api/flows?" + qs(p)),
    flow: (id) => req("/api/flows/" + id),
    alerts: (p) => req("/api/alerts?" + qs(p)),
    ack: (id) => req("/api/alerts/" + id + "/ack", { method: "POST" }),
    mute: (id) => req("/api/alerts/" + id + "/mute", { method: "POST" }),
    comment: (id, comment) =>
      req("/api/alerts/" + id + "/comment", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ comment }),
      }),
    stats: (p) => req("/api/stats/overview?" + qs(p)),
    hosts: (p) => req("/api/hosts?" + qs(p)),
    host: (ip, p) => req("/api/hosts/" + encodeURIComponent(ip) + "?" + qs(p)),
    meta: () => req("/api/meta"),
    sensor: () => req("/api/sensor"),
    startLive: (body) =>
      req("/api/sensor/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      }),
    stopLive: () => req("/api/sensor/stop", { method: "POST" }),
    loadDemo: () => req("/api/demo/load", { method: "POST" }),
    settings: () => req("/api/settings"),
    saveSettings: (body) =>
      req("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      }),
    graph: (p) => req("/api/graph?" + qs(p)),
    exportUrl: (kind, range, fmt) => `/api/export/${kind}?range=${encodeURIComponent(range)}&fmt=${fmt}`,
  };
})(window);
