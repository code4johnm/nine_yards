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
    (edges || []).forEach((e) => {
      left[e.source] = (left[e.source] || 0) + Number(e.bytes || 0);
      right[e.target] = (right[e.target] || 0) + Number(e.bytes || 0);
    });
    const L = Object.keys(left).slice(0, 16);
    const R = Object.keys(right).slice(0, 16);
    const maxL = Math.max(1, ...L.map((k) => left[k]));
    const lh = h / Math.max(L.length, 1);
    const rh = h / Math.max(R.length, 1);
    const ly = {};
    const ry = {};
    c.font = "14px sans-serif";
    L.forEach((k, i) => {
      ly[k] = 10 + i * lh;
      c.fillStyle = "#7aa2ff";
      c.fillRect(8, ly[k], 10, Math.max(8, (left[k] / maxL) * (lh - 8)));
      c.fillStyle = "#e8eefc";
      c.fillText(k, 24, ly[k] + 14);
    });
    R.forEach((k, i) => {
      ry[k] = 10 + i * rh;
      c.fillStyle = "#3dd6d0";
      c.fillRect(w - 18, ry[k], 10, Math.max(8, (right[k] / maxL) * (rh - 8)));
      c.fillStyle = "#e8eefc";
      c.fillText(k, w - 170, ry[k] + 14);
    });
    c.globalAlpha = 0.35;
    edges.slice(0, 40).forEach((e) => {
      if (!(e.source in ly) || !(e.target in ry)) return;
      c.strokeStyle = PROTO[e.proto] || "#7aa2ff";
      c.lineWidth = Math.max(1.5, Math.log10((e.bytes || 1) + 1) * 1.4);
      c.beginPath();
      c.moveTo(40, ly[e.source] + 8);
      c.bezierCurveTo(w * 0.4, ly[e.source] + 8, w * 0.6, ry[e.target] + 8, w - 24, ry[e.target] + 8);
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
    const nodes = (data.nodes || []).map((n, i) => {
      const ang = (i / Math.max(1, data.nodes.length)) * Math.PI * 2;
      return Object.assign({
        x: w / 2 + Math.cos(ang) * Math.min(w, h) * 0.32,
        y: h / 2 + Math.sin(ang) * Math.min(w, h) * 0.32,
        vx: 0, vy: 0,
      }, n);
    });
    const idm = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const edges = (data.edges || []).filter((e) => idm[e.source] && idm[e.target]);
    const maxB = Math.max(1, ...nodes.map((n) => n.bytes || 1));
    function step() {
      for (let k = 0; k < 40; k++) {
        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            let dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y;
            let d2 = dx * dx + dy * dy || 1;
            let f = 900 / d2;
            dx /= Math.sqrt(d2); dy /= Math.sqrt(d2);
            nodes[i].vx -= dx * f; nodes[i].vy -= dy * f;
            nodes[j].vx += dx * f; nodes[j].vy += dy * f;
          }
        }
        edges.forEach((e) => {
          const a = idm[e.source], b = idm[e.target];
          const dx = b.x - a.x, dy = b.y - a.y;
          a.vx += dx * 0.01; a.vy += dy * 0.01;
          b.vx -= dx * 0.01; b.vy -= dy * 0.01;
        });
        nodes.forEach((n) => {
          n.vx += (w / 2 - n.x) * 0.004;
          n.vy += (h / 2 - n.y) * 0.004;
          n.vx *= 0.82; n.vy *= 0.82;
          n.x = Math.max(28, Math.min(w - 28, n.x + n.vx));
          n.y = Math.max(28, Math.min(h - 28, n.y + n.vy));
        });
      }
    }
    function draw() {
      c.clearRect(0, 0, w, h);
      edges.forEach((e) => {
        const a = idm[e.source], b = idm[e.target];
        c.strokeStyle = PROTO[e.proto] || "#7aa2ff";
        c.lineWidth = Math.max(1.5, Math.log10((e.bytes || 1) + 1) * 1.6);
        c.globalAlpha = 0.75;
        c.beginPath(); c.moveTo(a.x, a.y); c.lineTo(b.x, b.y); c.stroke();
        c.globalAlpha = 1;
      });
      nodes.forEach((n) => {
        const r = 10 + Math.sqrt((n.bytes || 1) / maxB) * 18;
        n.r = r;
        c.beginPath();
        c.arc(n.x, n.y, r, 0, Math.PI * 2);
        c.fillStyle = n.alerts ? "#ff7a45" : (n.internal === false ? "#c9a0ff" : "#3dd6d0");
        if (n.kind === "service") c.fillStyle = "#7aa2ff";
        if (n.kind === "zone") c.fillStyle = "#f5c542";
        c.fill();
        c.fillStyle = "#e8eefc";
        c.font = "15px IBM Plex Sans, sans-serif";
        c.fillText(n.label || n.id, n.x + r + 4, n.y + 5);
      });
    }
    step();
    draw();
    function hit(ev) {
      const r = el.getBoundingClientRect();
      const x = ev.clientX - r.left, y = ev.clientY - r.top;
      return nodes.find((n) => (n.x - x) ** 2 + (n.y - y) ** 2 <= (n.r + 4) ** 2);
    }
    el.onmousemove = (ev) => {
      const n = hit(ev);
      if (n) showTip(ev, `${n.label}  bytes ${n.bytes || 0}  alerts ${n.alerts || 0}`);
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
      reset() { nodes.forEach((n, i) => {
        const ang = (i / Math.max(1, nodes.length)) * Math.PI * 2;
        n.x = w / 2 + Math.cos(ang) * Math.min(w, h) * 0.32;
        n.y = h / 2 + Math.sin(ang) * Math.min(w, h) * 0.32;
        n.vx = n.vy = 0;
      }); step(); draw(); },
    };
  }
  g.Charts = { line, area, bars, pie, stacked, timeline, sankey, graph, PROTO };
})(window);
