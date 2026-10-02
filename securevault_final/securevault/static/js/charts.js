// ════════════════════════════════════════════════════════════════════════════
//  SecureVault — Self-contained SVG charts  (charts.js)
//  No CDN, no dependency → CSP-clean and fully offline. All charts render into
//  a target element by id and adapt to the current theme via CSS variables.
// ════════════════════════════════════════════════════════════════════════════

const Charts = (() => {
  const NS = 'http://www.w3.org/2000/svg';
  const css = v => getComputedStyle(document.body).getPropertyValue(v).trim() || '#888';

  function el(tag, attrs = {}, parent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function clear(id) { const c = document.getElementById(id); if (c) c.innerHTML = ''; return c; }

  // ── Donut chart (alert severity distribution) ────────────────────────────
  function donut(id, segments, centerLabel = '', centerSub = '') {
    const host = clear(id);
    if (!host) return;
    const total = segments.reduce((s, x) => s + x.value, 0);
    const size = 180, r = 70, cx = size / 2, cy = size / 2, stroke = 22;
    const svg = el('svg', { viewBox: `0 0 ${size} ${size}`, width: '100%', height: '180' }, host);

    el('circle', { cx, cy, r, fill: 'none', stroke: css('--border'), 'stroke-width': stroke }, svg);

    const circ = 2 * Math.PI * r;
    let offset = 0;
    if (total > 0) {
      segments.forEach(seg => {
        if (seg.value <= 0) return;
        const frac = seg.value / total;
        const c = el('circle', {
          cx, cy, r, fill: 'none', stroke: seg.color, 'stroke-width': stroke,
          'stroke-dasharray': `${frac * circ} ${circ}`,
          'stroke-dashoffset': -offset * circ,
          transform: `rotate(-90 ${cx} ${cy})`, 'stroke-linecap': 'butt',
        }, svg);
        c.style.transition = 'stroke-dasharray .6s ease';
        offset += frac;
      });
    }
    const t1 = el('text', { x: cx, y: cy - 2, 'text-anchor': 'middle', 'font-size': 30, 'font-weight': 800, fill: css('--text') }, svg);
    t1.textContent = centerLabel;
    const t2 = el('text', { x: cx, y: cy + 18, 'text-anchor': 'middle', 'font-size': 11, fill: css('--text-dim') }, svg);
    t2.textContent = centerSub;

    // legend
    const leg = document.createElement('div');
    leg.className = 'chart-legend';
    segments.forEach(seg => {
      const li = document.createElement('div'); li.className = 'li';
      const sw = document.createElement('span'); sw.className = 'sw'; sw.style.background = seg.color;
      li.appendChild(sw);
      li.appendChild(document.createTextNode(`${seg.label} · ${seg.value}`));
      leg.appendChild(li);
    });
    host.appendChild(leg);
  }

  // ── Vertical bar chart (events over time) ────────────────────────────────
  function bars(id, data, color) {
    const host = clear(id);
    if (!host) return;
    color = color || css('--primary');
    const W = 100 * data.length + 20, H = 180, pad = 26, bw = 60;
    const max = Math.max(1, ...data.map(d => d.value));
    const svg = el('svg', { viewBox: `0 0 ${Math.max(320, W)} ${H}`, width: '100%', height: '180', preserveAspectRatio: 'none' }, host);
    const innerH = H - pad * 2;
    const step = (Math.max(320, W) - 30) / data.length;

    // gridlines
    for (let g = 0; g <= 3; g++) {
      const y = pad + innerH * (g / 3);
      el('line', { x1: 15, y1: y, x2: Math.max(320, W) - 5, y2: y, stroke: css('--border'), 'stroke-width': 1, opacity: .5 }, svg);
    }
    data.forEach((d, i) => {
      const h = (d.value / max) * innerH;
      const x = 20 + i * step;
      const rect = el('rect', { x, y: pad + innerH - h, width: Math.min(bw, step - 18), height: h, rx: 5, fill: color, opacity: .85 }, svg);
      rect.style.transition = 'height .5s ease';
      const v = el('text', { x: x + Math.min(bw, step - 18) / 2, y: pad + innerH - h - 6, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 700, fill: css('--text') }, svg);
      v.textContent = d.value || '';
      const lab = el('text', { x: x + Math.min(bw, step - 18) / 2, y: H - 8, 'text-anchor': 'middle', 'font-size': 10.5, fill: css('--text-dim') }, svg);
      lab.textContent = d.label;
    });
  }

  // ── Sparkline / area (timeline) ──────────────────────────────────────────
  function area(id, values, color) {
    const host = clear(id);
    if (!host) return;
    color = color || css('--accent');
    const W = 600, H = 140, pad = 10;
    const max = Math.max(1, ...values);
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, width: '100%', height: '140', preserveAspectRatio: 'none' }, host);
    if (!values.length) return;
    const step = (W - pad * 2) / Math.max(1, values.length - 1);
    const pts = values.map((v, i) => [pad + i * step, H - pad - (v / max) * (H - pad * 2)]);
    const line = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
    const fill = `${line} L${pts[pts.length - 1][0]},${H - pad} L${pts[0][0]},${H - pad} Z`;

    const grad = el('linearGradient', { id: id + '-g', x1: 0, y1: 0, x2: 0, y2: 1 }, svg);
    el('stop', { offset: '0%', 'stop-color': color, 'stop-opacity': .35 }, grad);
    el('stop', { offset: '100%', 'stop-color': color, 'stop-opacity': 0 }, grad);
    el('path', { d: fill, fill: `url(#${id}-g)` }, svg);
    el('path', { d: line, fill: 'none', stroke: color, 'stroke-width': 2.5, 'stroke-linejoin': 'round' }, svg);
    pts.forEach(p => el('circle', { cx: p[0], cy: p[1], r: 2.5, fill: color }, svg));
  }

  // ── Risk gauge ring (0-100) ──────────────────────────────────────────────
  function gauge(id, value) {
    const host = clear(id);
    if (!host) return;
    const size = 116, r = 48, cx = size / 2, cy = size / 2, stroke = 11;
    const svg = el('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size }, host);
    el('circle', { cx, cy, r, fill: 'none', stroke: css('--border'), 'stroke-width': stroke }, svg);
    const color = value < 30 ? css('--ok') : value < 60 ? css('--warn') : css('--danger');
    const circ = 2 * Math.PI * r;
    const c = el('circle', {
      cx, cy, r, fill: 'none', stroke: color, 'stroke-width': stroke, 'stroke-linecap': 'round',
      'stroke-dasharray': `${(value / 100) * circ} ${circ}`, transform: `rotate(-90 ${cx} ${cy})`,
    }, svg);
    c.style.transition = 'stroke-dasharray .7s ease';
    const t = el('text', { x: cx, y: cy + 7, 'text-anchor': 'middle', 'font-size': 26, 'font-weight': 800, fill: css('--text') }, svg);
    t.textContent = value;
  }

  return { donut, bars, area, gauge };
})();

window.Charts = Charts;
