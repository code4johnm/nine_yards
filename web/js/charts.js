/* Canvas charts + graphs. Offline, no CDN. */
(function (g) {
  const PROTO = { TCP: "#7aa2ff", UDP: "#3dd6d0", ICMP: "#f5c542", ARP: "#c9a0ff", OTHER: "#9db0d0" };
  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#3dd6d0";
  }
  function tip() { return document.getElementById("chart-tip"); }
  function showTip(ev, text) {
    const t = tip();
    if (!t) return;
    t.style.display = "block";
    t.textContent = text;
    t.style.left = ev.clientX + 12 + "px";
    t.style.top = ev.clientY + 12 + "px";
  }
  function hideTip() { const t = tip(); if (t) t.style.display = "none"; }
  function ctxOf(el) {
    if (typeof el === "string") el = document.querySelector(el);
    if (!el) return null;
    if (!el.style.width) el.style.width = "100%";
    const isMap = el.classList.contains("map-canvas") || el.classList.contains("sankey-canvas")
      || el.id === "c-g" || el.id === "c-sk";
    // Non-map canvases: pin HTML height as CSS so width:100% does not
    // preserve the 300×attr aspect ratio. Map frames are sized in CSS.
    if (!isMap && !el.style.height) {
      const attrH = el.getAttribute("height");
      if (attrH) el.style.height = Number(attrH) + "px";
    }
    const dpr = window.devicePixelRatio || 1;
    const w = el.clientWidth || 300;
    const h = el.clientHeight || 80;
    el.width = Math.max(1, w * dpr);
    el.height = Math.max(1, h * dpr);
    const c = el.getContext("2d");
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.font = "14px IBM Plex Sans, sans-serif";
    return { c, w, h, el };
  }
  function compactLabel(s, max) {
    s = String(s || "");
    max = max || 18;
    if (s.length <= max) return s;
    const head = Math.max(4, Math.ceil(max * 0.45));
    const tail = Math.max(4, max - head - 1);
    return s.slice(0, head) + "…" + s.slice(-tail);
  }
  function paintLabel(c, text, x, y, align) {
    const parts = String(text || "").split(" | ");
    const ip = parts[0] || "";
    const tldn = parts.length > 1 ? parts.slice(1).join(" | ") : "";
    c.font = "14px IBM Plex Mono, ui-monospace, monospace";
    const ipW = c.measureText(ip).width;
    c.font = "12px IBM Plex Sans, sans-serif";
    const nmW = tldn ? c.measureText(tldn).width : 0;
    const tw = Math.max(ipW, nmW);
    const padX = 6, boxH = tldn ? 32 : 20;
    let tx = x;
    if (align === "right") tx = x - tw;
    else if (align === "center") tx = x - tw / 2;
    const top = tldn ? y - 20 : y - 14;
    c.fillStyle = "rgba(11, 18, 32, 0.9)";
    c.fillRect(tx - padX, top, tw + padX * 2, boxH);
    c.strokeStyle = "rgba(42, 58, 88, 0.95)";
    c.lineWidth = 1;
    c.strokeRect(tx - padX, top, tw + padX * 2, boxH);
    c.font = "14px IBM Plex Mono, ui-monospace, monospace";
    c.fillStyle = "#e8eefc";
    c.fillText(ip, tx, tldn ? y - 4 : y);
    if (tldn) {
      c.font = "12px IBM Plex Sans, sans-serif";
      c.fillStyle = "#9db0d0";
      c.fillText(tldn, tx, y + 10);
    }
    return tw;
  }
  function line(canvas, values, color) {
    const box = ctxOf(canvas);
    if (!box) return;
    const { c, w, h } = box;
    c.clearRect(0, 0, w, h);
    if (!values || !values.length) return;
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    c.beginPath();
    values.forEach((v, i) => {
      const x = (i / Math.max(1, values.length - 1)) * (w - 2) + 1;
      const y = h - 2 - ((v - min) / span) * (h - 4);
      if (i === 0) c.moveTo(x, y);
      else c.lineTo(x, y);
    });
    c.strokeStyle = color || css("--accent");
    c.lineWidth = 2;
    c.stroke();
  }
  function area(canvas, points, color, opts) {
    opts = opts || {};
    const vals = (points || []).map((p) => Number(p.v || 0));
    const box = ctxOf(canvas);
    if (!box || vals.length < 2) return;
    const { c, w, h, el } = box;
    const min = Math.min(...vals);
    const max = Math.max(...vals);
    const span = max - min || 1;
    const xy = vals.map((v, i) => ({
      x: (i / Math.max(1, vals.length - 1)) * (w - 8) + 4,
      y: h - 8 - ((v - min) / span) * (h - 16),
      p: points[i],
    }));
    c.clearRect(0, 0, w, h);
    c.beginPath();
    xy.forEach((p, i) => (i ? c.lineTo(p.x, p.y) : c.moveTo(p.x, p.y)));
    c.lineTo(w - 4, h - 4);
    c.lineTo(4, h - 4);
    c.closePath();
    c.fillStyle = (color || css("--accent")) + "33";
    c.fill();
    c.beginPath();
    xy.forEach((p, i) => (i ? c.lineTo(p.x, p.y) : c.moveTo(p.x, p.y)));
    c.strokeStyle = color || css("--accent");
    c.lineWidth = 2;
    c.stroke();
    el.onmousemove = (ev) => {
      const r = el.getBoundingClientRect();
      const x = ev.clientX - r.left;
      let best = 0, bd = 1e9;
      xy.forEach((p, i) => { const d = Math.abs(p.x - x); if (d < bd) { bd = d; best = i; } });
      const p = xy[best];
      showTip(ev, (p.p.t_iso || p.p.t || "") + "  " + Number(p.p.v || 0).toFixed(2));
      if (opts.onHover) opts.onHover(points[best]);
    };
    el.onmouseleave = hideTip;
    let down = null;
    el.onmousedown = (ev) => { down = ev.clientX; };
    el.onmouseup = (ev) => {
      if (down == null || !opts.onBrush) return;
      const r = el.getBoundingClientRect();
      const a = Math.min(down, ev.clientX) - r.left;
      const b = Math.max(down, ev.clientX) - r.left;
      if (b - a < 12) return;
      const ia = xy.reduce((bi, p, i) => Math.abs(p.x - a) < Math.abs(xy[bi].x - a) ? i : bi, 0);
      const ib = xy.reduce((bi, p, i) => Math.abs(p.x - b) < Math.abs(xy[bi].x - b) ? i : bi, 0);
      opts.onBrush(points[ia], points[ib]);
      down = null;
    };
  }
  function bars(canvas, items, color) {
    const box = ctxOf(canvas);
    if (!box) return;
    const { c, w, h, el } = box;
    c.clearRect(0, 0, w, h);
    const data = items || [];
    const max = Math.max(1, ...data.map((d) => Number(d.n || d.v || d.packets || d.bytes || 0)));
    const bw = Math.max(4, (w - 24) / Math.max(1, data.length) - 6);
    data.forEach((d, i) => {
      const n = Number(d.n || d.v || d.packets || d.bytes || 0);
      const bh = (n / max) * (h - 28);
      const x = 12 + i * (bw + 6);
      const y = h - 22 - bh;
      c.fillStyle = d.color || color || css("--accent2");
      c.fillRect(x, y, bw, bh);
    });
    c.fillStyle = "#e8eefc";
    c.font = "13px sans-serif";
    el.onmousemove = (ev) => {
      const r = el.getBoundingClientRect();
      const i = Math.floor(((ev.clientX - r.left - 12) / (bw + 6)));
      if (i >= 0 && i < data.length) {
        const d = data[i];
        showTip(ev, (d.name || d.app || d.bucket || d.port || "") + "  " + Number(d.n || d.bytes || d.v || 0));
      }
    };
    el.onmouseleave = hideTip;
  }
  function pie(canvas, items) {
    const box = ctxOf(canvas);
    if (!box) return;
    const { c, w, h } = box;
    c.clearRect(0, 0, w, h);
    const palette = ["#3dd6d0", "#7aa2ff", "#f5c542", "#ff7a45", "#ff4d4f", "#c9a0ff", "#9db0d0"];
    const data = (items || []).slice(0, 8);
    const total = data.reduce((s, d) => s + Number(d.packets || d.n || d.bytes || 0), 0) || 1;
    let a = -Math.PI / 2;
    const cx = w * 0.34, cy = h / 2, r = Math.min(w, h) * 0.34;
    data.forEach((d, i) => {
      const v = Number(d.packets || d.n || d.bytes || 0) / total;
      const a2 = a + v * Math.PI * 2;
      c.beginPath();
      c.moveTo(cx, cy);
      c.arc(cx, cy, r, a, a2);
      c.closePath();
      c.fillStyle = PROTO[d.name] || palette[i % palette.length];
      c.fill();
      a = a2;
      const label = d.name || d.app || d.bucket || "?";
      c.fillStyle = "#e8eefc";
      c.font = "14px sans-serif";
      c.fillText(`${label}  ${Math.round(v * 100)}%`, w * 0.62, 22 + i * 20);
    });
  }
  function stacked(canvas, rows, keys) {
    const box = ctxOf(canvas);
    if (!box || !rows || !rows.length) return;
    const { c, w, h } = box;
    c.clearRect(0, 0, w, h);
    const colors = keys.map((k) => PROTO[k] || css("--accent"));
    const max = Math.max(1, ...rows.map((r) => keys.reduce((s, k) => s + Number(r[k] || 0), 0)));
    const bw = (w - 16) / rows.length;
    rows.forEach((r, i) => {
      let y = h - 8;
      keys.forEach((k, ki) => {
        const v = Number(r[k] || 0);
        const bh = (v / max) * (h - 16);
        y -= bh;
        c.fillStyle = colors[ki];
        c.fillRect(8 + i * bw, y, Math.max(1, bw - 1), bh);
      });
    });
  }
  function timeline(canvas, rows) {
    const keys = ["critical", "high", "medium", "low", "info"];
    const colors = ["#ff4d4f", "#ff7a45", "#f5c542", "#3dd6d0", "#7aa2ff"];
    stacked(canvas, rows, keys);
    const box = ctxOf(canvas);
    if (!box) return;
    // stacked already cleared; redraw with severity colors
    const { c, w, h } = box;
    if (!rows || !rows.length) return;
    c.clearRect(0, 0, w, h);
    const max = Math.max(1, ...rows.map((r) => keys.reduce((s, k) => s + Number(r[k] || 0), 0)));
    const bw = (w - 16) / rows.length;
    rows.forEach((r, i) => {
      let y = h - 8;
      keys.forEach((k, ki) => {
        const v = Number(r[k] || 0);
        const bh = (v / max) * (h - 16);
        y -= bh;
        c.fillStyle = colors[ki];
        c.fillRect(8 + i * bw, y, Math.max(1, bw - 1), bh);
      });
    });
  }
  function sankey(canvas, edges, opts) {
    opts = opts || {};
    const box = ctxOf(canvas);
    if (!box) return;
    const { c, w, h, el } = box;
    c.clearRect(0, 0, w, h);
    const left = {};
    const right = {};
    const labels = {};
    (opts.nodes || []).forEach((n) => { if (n && n.id) labels[n.id] = n.label || n.id; });
    (edges || []).forEach((e) => {
      left[e.source] = (left[e.source] || 0) + Number(e.bytes || 0);
      right[e.target] = (right[e.target] || 0) + Number(e.bytes || 0);
      if (e.source_label) labels[e.source] = e.source_label;
      if (e.target_label) labels[e.target] = e.target_label;
    });
    const L = Object.keys(left).slice(0, 18);
    const R = Object.keys(right).slice(0, 18);
    const maxL = Math.max(1, ...L.map((k) => left[k]));
    const colW = Math.min(280, Math.max(160, w * 0.22));
    const barW = 12;
    const lh = h / Math.max(L.length, 1);
    const rh = h / Math.max(R.length, 1);
    const ly = {};
    const ry = {};
    L.forEach((k, i) => {
      ly[k] = 10 + i * lh;
      c.fillStyle = "#7aa2ff";
      c.fillRect(colW, ly[k], barW, Math.max(8, (left[k] / maxL) * Math.max(10, lh - 10)));
      paintLabel(c, labels[k] || k, colW - 8, ly[k] + 16, "right");
    });
    R.forEach((k, i) => {
      ry[k] = 10 + i * rh;
      c.fillStyle = "#3dd6d0";
      c.fillRect(w - colW - barW, ry[k], barW, Math.max(8, (right[k] / maxL) * Math.max(10, rh - 10)));
      paintLabel(c, labels[k] || k, w - colW + 8, ry[k] + 16, "left");
    });
    c.globalAlpha = 0.35;
    edges.slice(0, 40).forEach((e) => {
      if (!(e.source in ly) || !(e.target in ry)) return;
      c.strokeStyle = PROTO[e.proto] || "#7aa2ff";
      c.lineWidth = Math.max(1.5, Math.log10((e.bytes || 1) + 1) * 1.4);
      c.beginPath();
      c.moveTo(colW + barW + 2, ly[e.source] + 8);
      c.bezierCurveTo(w * 0.42, ly[e.source] + 8, w * 0.58, ry[e.target] + 8, w - colW - 2, ry[e.target] + 8);
      c.stroke();
    });
    c.globalAlpha = 1;
    el.onclick = (ev) => {
      const r = el.getBoundingClientRect();
      const x = ev.clientX - r.left, y = ev.clientY - r.top;
      if (x < w / 2) {
        const hit = L.find((k) => Math.abs(ly[k] + 8 - y) < lh / 2);
        if (hit && opts.onNode) opts.onNode(hit);
      } else {
        const hit = R.find((k) => Math.abs(ry[k] + 8 - y) < rh / 2);
        if (hit && opts.onNode) opts.onNode(hit);
      }
    };
  }
  function graph(canvas, data, opts) {
    opts = opts || {};
    const box = ctxOf(canvas);
    if (!box) return { reset() {} };
    const { c, w, h, el } = box;
    const ncount = Math.max(1, (data.nodes || []).length);
    const narrow = w < 720;
    const side = narrow ? 24 : Math.max(64, Math.min(130, w * 0.13));
    const pad = { l: side, r: side, t: 40, b: narrow ? 28 : 40 };
    const cx = w / 2, cy = h / 2;
    const ringX = Math.max(70, cx - pad.r);
    const ringY = Math.max(60, cy - pad.b);
    const nodes = (data.nodes || []).map((n) => Object.assign({}, n, {
      x: cx, y: cy, vx: 0, vy: 0, hub: false,
      short: compactLabel(n.label || n.id, narrow ? 12 : 18),
    }));
    const idm = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const edges = (data.edges || []).filter((e) => idm[e.source] && idm[e.target]);
    const maxB = Math.max(1, ...nodes.map((n) => n.bytes || 1));
    const deg = Object.fromEntries(nodes.map((n) => [n.id, 0]));
    edges.forEach((e) => { deg[e.source]++; deg[e.target]++; });
    function seed() {
      const ranked = nodes.slice().sort((a, b) =>
        (deg[b.id] - deg[a.id]) || ((b.bytes || 0) - (a.bytes || 0)));
      nodes.forEach((n) => { n.hub = false; });
      const useHub = ranked.length >= 6;
      if (useHub && ranked[0]) {
        ranked[0].x = cx;
        ranked[0].y = cy;
        ranked[0].hub = true;
      }
      const rest = nodes.filter((n) => !n.hub);
      rest.forEach((n, i) => {
        const ang = (i / Math.max(1, rest.length)) * Math.PI * 2 - Math.PI / 2;
        n.x = cx + Math.cos(ang) * ringX * 0.92;
        n.y = cy + Math.sin(ang) * ringY * 0.92;
        n.vx = n.vy = 0;
      });
    }
    function separate() {
      const minD = Math.max(narrow ? 92 : 78, Math.sqrt((w * h) / ncount) * 0.4);
      for (let k = 0; k < 50; k++) {
        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            let dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y;
            const d = Math.hypot(dx, dy) || 0.01;
            if (d >= minD) continue;
            const push = (minD - d) * 0.28;
            dx /= d; dy /= d;
            if (!nodes[i].hub) { nodes[i].x -= dx * push; nodes[i].y -= dy * push; }
            if (!nodes[j].hub) { nodes[j].x += dx * push; nodes[j].y += dy * push; }
          }
        }
        nodes.forEach((n) => {
          if (n.hub) { n.x = cx; n.y = cy; return; }
          n.x = Math.max(pad.l, Math.min(w - pad.r, n.x));
          n.y = Math.max(pad.t, Math.min(h - pad.b, n.y));
        });
      }
    }
    function layoutLabels() {
      nodes.forEach((n) => {
        n.r = 8 + Math.sqrt((n.bytes || 1) / maxB) * 14;
        const ipLine = compactLabel(n.id, (n.id || "").includes(":") ? 16 : 20);
        const nameLine = n.tldn ? compactLabel(n.tldn, narrow ? 16 : 24) : "";
        n.short = nameLine ? `${ipLine} | ${nameLine}` : ipLine;
        n.labW = Math.max(ipLine.length, nameLine.length) * 7.6 + 14;
        n.labH = nameLine ? 34 : 20;
        if (n.hub || narrow) n.labAlign = "center";
        else n.labAlign = n.x >= cx ? "left" : "right";
      });
      const ordered = nodes.filter((n) => !n.hub).slice().sort((a, b) => a.y - b.y);
      for (let i = 1; i < ordered.length; i++) {
        const prev = ordered[i - 1], cur = ordered[i];
        const closeX = Math.abs(prev.x - cur.x) < Math.max(prev.labW, cur.labW) + 28;
        const gap = Math.max(prev.labH || 22, 22);
        if (prev.labAlign === cur.labAlign && closeX && cur.y - prev.y < gap) {
          cur.y = Math.min(h - pad.b, prev.y + gap);
        }
      }
    }
    function draw() {
      layoutLabels();
      c.clearRect(0, 0, w, h);
      edges.forEach((e) => {
        const a = idm[e.source], b = idm[e.target];
        c.strokeStyle = PROTO[e.proto] || "#7aa2ff";
        c.lineWidth = Math.max(1.2, Math.log10((e.bytes || 1) + 1) * 1.3);
        c.globalAlpha = 0.42;
        c.beginPath(); c.moveTo(a.x, a.y); c.lineTo(b.x, b.y); c.stroke();
        c.globalAlpha = 1;
      });
      nodes.forEach((n) => {
        c.beginPath();
        c.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        c.fillStyle = n.alerts ? "#ff7a45" : (n.internal === false ? "#c9a0ff" : "#3dd6d0");
        if (n.kind === "service") c.fillStyle = "#7aa2ff";
        if (n.kind === "zone") c.fillStyle = "#f5c542";
        c.fill();
        let lx = n.x, ly = n.y + 5, align = n.labAlign;
        if (n.hub || n.labAlign === "center") {
          ly = n.y + n.r + 20;
          align = "center";
        } else if (n.labAlign === "left") {
          lx = n.x + n.r + 8;
        } else {
          lx = n.x - n.r - 8;
        }
        paintLabel(c, n.short, lx, ly, align);
      });
    }
    seed();
    separate();
    draw();
    function hit(ev) {
      const r = el.getBoundingClientRect();
      const x = ev.clientX - r.left, y = ev.clientY - r.top;
      return nodes.find((n) => (n.x - x) ** 2 + (n.y - y) ** 2 <= (n.r + 10) ** 2)
        || nodes.find((n) => {
          const lx = n.labAlign === "left" ? n.x + n.r + 8
            : n.labAlign === "right" ? n.x - n.r - 8 - n.labW
            : n.x - n.labW / 2;
          const ly = (n.hub || n.labAlign === "center") ? n.y + n.r + 20 : n.y;
          return x >= lx && x <= lx + n.labW && Math.abs(y - ly) < 14;
        });
    }
    el.onmousemove = (ev) => {
      const n = hit(ev);
      if (n) showTip(ev, `${n.label || n.id}  bytes ${n.bytes || 0}  alerts ${n.alerts || 0}`);
      else hideTip();
    };
    el.onmouseleave = hideTip;
    el.onclick = (ev) => {
      const n = hit(ev);
      if (n && opts.onNode) opts.onNode(n);
      else {
        const r = el.getBoundingClientRect();
        const x = ev.clientX - r.left, y = ev.clientY - r.top;
        const e = edges.find((ed) => {
          const a = idm[ed.source], b = idm[ed.target];
          const d = Math.abs((b.y - a.y) * x - (b.x - a.x) * y + b.x * a.y - b.y * a.x) /
            (Math.hypot(b.x - a.x, b.y - a.y) || 1);
          return d < 6;
        });
        if (e && opts.onEdge) opts.onEdge(e);
      }
    };
    return {
      reset() { seed(); separate(); draw(); },
    };
  }
  g.Charts = { line, area, bars, pie, stacked, timeline, sankey, graph, PROTO };
})(window);
