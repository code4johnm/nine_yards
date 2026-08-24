/* Minimal canvas charts — no CDN. */
(function (g) {
  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#3dd6c6";
  }
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
    c.lineWidth = 1.5;
    c.stroke();
  }
  function area(canvas, points, color) {
    const vals = (points || []).map((p) => Number(p.v || 0));
    line(canvas, vals, color);
    const box = ctxOf(canvas);
    if (!box || vals.length < 2) return;
    // redraw with fill
    const { c, w, h } = box;
    const min = Math.min(...vals);
    const max = Math.max(...vals);
    const span = max - min || 1;
    c.clearRect(0, 0, w, h);
    c.beginPath();
    vals.forEach((v, i) => {
      const x = (i / Math.max(1, vals.length - 1)) * (w - 8) + 4;
      const y = h - 6 - ((v - min) / span) * (h - 12);
      if (i === 0) c.moveTo(x, y);
      else c.lineTo(x, y);
    });
    const lastX = w - 4;
    c.lineTo(lastX, h - 4);
    c.lineTo(4, h - 4);
    c.closePath();
    c.fillStyle = (color || css("--accent")) + "33";
    c.fill();
    c.beginPath();
    vals.forEach((v, i) => {
      const x = (i / Math.max(1, vals.length - 1)) * (w - 8) + 4;
      const y = h - 6 - ((v - min) / span) * (h - 12);
      if (i === 0) c.moveTo(x, y);
      else c.lineTo(x, y);
    });
    c.strokeStyle = color || css("--accent");
    c.lineWidth = 1.6;
    c.stroke();
  }
  function bars(canvas, items, color) {
    const box = ctxOf(canvas);
    if (!box) return;
    const { c, w, h } = box;
    c.clearRect(0, 0, w, h);
    const data = items || [];
    const max = Math.max(1, ...data.map((d) => Number(d.n || d.v || d.packets || 0)));
    const bw = Math.max(2, (w - 20) / Math.max(1, data.length) - 4);
    data.forEach((d, i) => {
      const n = Number(d.n || d.v || d.packets || 0);
      const bh = (n / max) * (h - 18);
      const x = 10 + i * (bw + 4);
      const y = h - 14 - bh;
      c.fillStyle = color || css("--accent2");
      c.fillRect(x, y, bw, bh);
    });
  }
  function pie(canvas, items) {
    const box = ctxOf(canvas);
    if (!box) return;
    const { c, w, h } = box;
    c.clearRect(0, 0, w, h);
    const palette = ["#3dd6c6", "#5b8def", "#ffd166", "#ff8c42", "#ff4d6d", "#7ae582", "#c9a0ff", "#64b5f6"];
    const data = (items || []).slice(0, 8);
    const total = data.reduce((s, d) => s + Number(d.packets || d.n || d.bytes || 0), 0) || 1;
    let a = -Math.PI / 2;
    const cx = w * 0.38, cy = h / 2, r = Math.min(w, h) * 0.36;
    data.forEach((d, i) => {
      const v = Number(d.packets || d.n || d.bytes || 0) / total;
      const a2 = a + v * Math.PI * 2;
      c.beginPath();
      c.moveTo(cx, cy);
      c.arc(cx, cy, r, a, a2);
      c.closePath();
      c.fillStyle = palette[i % palette.length];
      c.fill();
      a = a2;
      const label = d.name || d.app || d.bucket || "?";
      c.fillStyle = "#d7e0ea";
      c.font = "11px sans-serif";
      c.fillText(`${label} ${Math.round(v * 100)}%`, w * 0.62, 16 + i * 14);
    });
  }
  g.Charts = { line, area, bars, pie };
})(window);
