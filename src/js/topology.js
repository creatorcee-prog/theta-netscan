/**
 * Dynamic topology rendering from relationship records.
 * No fixed illustrative lines — only evidence-based edges.
 */

import { CONFIDENCE } from './models.js';

const CATEGORY_COLORS = {
  'Router': '#58a6ff',
  'Firewall': '#f85149',
  'Managed Switch': '#a371f7',
  'Unmanaged Switch': '#8b949e',
  'Access Point': '#2dd4bf',
  'Wireless Controller': '#2dd4bf',
  'Modem': '#d29922',
  'Server': '#3fb950',
  'NAS': '#3fb950',
  'Desktop': '#e3b341',
  'Laptop': '#e3b341',
  'Smartphone': '#d29922',
  'Tablet': '#d29922',
  'Printer': '#8b949e',
  'Camera': '#f85149',
  'IoT Device': '#6e7681',
  'Network Appliance': '#58a6ff',
  'Unknown Device': '#6e7681'
};

const CATEGORY_ICONS = {
  'Router': 'R',
  'Firewall': 'F',
  'Managed Switch': 'S',
  'Unmanaged Switch': 's',
  'Access Point': 'A',
  'Server': 'Srv',
  'NAS': 'NAS',
  'Desktop': 'PC',
  'Laptop': 'Lap',
  'Smartphone': 'Ph',
  'Printer': 'Pr',
  'Unknown Device': '?'
};

function confidenceClass(conf) {
  switch (conf) {
    case CONFIDENCE.VERIFIED: return 'edge-verified';
    case CONFIDENCE.OBSERVED: return 'edge-observed';
    case CONFIDENCE.INFERRED: return 'edge-inferred';
    default: return 'edge-unknown';
  }
}

export class TopologyRenderer {
  constructor(container, options = {}) {
    this.container = container;
    this.devices = [];
    this.relationships = [];
    this.filters = {
      categories: new Set(),
      showOffline: true,
      confidence: new Set([CONFIDENCE.VERIFIED, CONFIDENCE.OBSERVED, CONFIDENCE.INFERRED, CONFIDENCE.UNKNOWN])
    };
    this.scale = 1;
    this.offsetX = 0;
    this.offsetY = 0;
    this.dragging = null;
    this.panning = false;
    this.lastPan = null;
    this.selectedId = null;
    this.onSelect = options.onSelect || (() => {});
    this.onPositionChange = options.onPositionChange || (() => {});

    this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.svg.classList.add('map-canvas');
    this.svg.setAttribute('width', '100%');
    this.svg.setAttribute('height', '100%');
    this.container.appendChild(this.svg);

    this.gEdges = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    this.gNodes = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    this.svg.appendChild(this.gEdges);
    this.svg.appendChild(this.gNodes);

    this._bindEvents();
    this._emptyEl = null;
  }

  setData(devices, relationships) {
    this.devices = devices || [];
    this.relationships = relationships || [];
    this._layoutIfNeeded();
    this.render();
  }

  _layoutIfNeeded() {
    const unpositioned = this.devices.filter(d => d.mapX == null || d.mapY == null);
    if (unpositioned.length === 0) return;

    const w = this.container.clientWidth || 360;
    const h = this.container.clientHeight || 400;
    const cx = w / 2;
    const cy = h / 2;

    const routers = unpositioned.filter(d =>
      d.category === 'Router' || d.category === 'Firewall' || d.category === 'Modem'
    );
    const others = unpositioned.filter(d => !routers.includes(d));

    routers.forEach((d, i) => {
      d.mapX = cx + (i - (routers.length - 1) / 2) * 80;
      d.mapY = cy - 60;
    });

    const radius = Math.min(w, h) * 0.32;
    others.forEach((d, i) => {
      const angle = (i / Math.max(others.length, 1)) * Math.PI * 2 - Math.PI / 2;
      d.mapX = cx + Math.cos(angle) * radius;
      d.mapY = cy + Math.sin(angle) * radius + 40;
    });
  }

  render() {
    const visible = this._visibleDevices();
    const visibleIds = new Set(visible.map(d => d.id));
    const edges = this.relationships.filter(r =>
      visibleIds.has(r.sourceDeviceId) &&
      visibleIds.has(r.destDeviceId) &&
      this.filters.confidence.has(r.confidence)
    );

    while (this.gEdges.firstChild) this.gEdges.removeChild(this.gEdges.firstChild);
    while (this.gNodes.firstChild) this.gNodes.removeChild(this.gNodes.firstChild);

    if (visible.length === 0) {
      this._showEmpty(true);
      return;
    }
    this._showEmpty(false);

    const pos = {};
    visible.forEach(d => { pos[d.id] = { x: d.mapX, y: d.mapY }; });

    for (const rel of edges) {
      const a = pos[rel.sourceDeviceId];
      const b = pos[rel.destDeviceId];
      if (!a || !b) continue;
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', a.x);
      line.setAttribute('y1', a.y);
      line.setAttribute('x2', b.x);
      line.setAttribute('y2', b.y);
      line.setAttribute('class', confidenceClass(rel.confidence));
      line.dataset.relId = rel.id;
      this.gEdges.appendChild(line);
    }

    for (const d of visible) {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.classList.add('node-group');
      g.dataset.id = d.id;
      g.setAttribute('transform', `translate(${d.mapX},${d.mapY})`);

      const color = CATEGORY_COLORS[d.category] || CATEGORY_COLORS['Unknown Device'];
      const r = 18;

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', r);
      circle.setAttribute('fill', color);
      circle.setAttribute('fill-opacity', d.status === 'offline' ? 0.35 : 0.85);
      circle.setAttribute('stroke', this.selectedId === d.id ? '#39c5cf' : '#0d1117');
      circle.setAttribute('stroke-width', this.selectedId === d.id ? 3 : 1.5);
      circle.classList.add('node-circle');
      g.appendChild(circle);

      const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      icon.setAttribute('text-anchor', 'middle');
      icon.setAttribute('dominant-baseline', 'central');
      icon.setAttribute('fill', '#0d1117');
      icon.setAttribute('font-size', '11');
      icon.setAttribute('font-weight', '700');
      icon.setAttribute('font-family', 'ui-monospace, monospace');
      icon.textContent = CATEGORY_ICONS[d.category] || (d.category || '?')[0];
      g.appendChild(icon);

      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('y', r + 14);
      label.setAttribute('text-anchor', 'middle');
      label.classList.add('node-label');
      label.textContent = (d.hostname || d.ipAddress || d.macAddress || 'Device').slice(0, 16);
      g.appendChild(label);

      if (d.ipAddress) {
        const sub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        sub.setAttribute('y', r + 26);
        sub.setAttribute('text-anchor', 'middle');
        sub.classList.add('node-sublabel');
        sub.textContent = d.ipAddress;
        g.appendChild(sub);
      }

      if (d.status === 'offline') {
        const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ring.setAttribute('r', r + 3);
        ring.setAttribute('fill', 'none');
        ring.setAttribute('stroke', '#6e7681');
        ring.setAttribute('stroke-width', 1);
        ring.setAttribute('stroke-dasharray', '3 2');
        g.appendChild(ring);
      }

      this.gNodes.appendChild(g);
    }

    this._applyTransform();
  }

  _visibleDevices() {
    return this.devices.filter(d => {
      if (!this.filters.showOffline && d.status === 'offline') return false;
      if (this.filters.categories.size > 0 && !this.filters.categories.has(d.category)) return false;
      return true;
    });
  }

  _showEmpty(show) {
    if (show) {
      if (!this._emptyEl) {
        this._emptyEl = document.createElement('div');
        this._emptyEl.className = 'map-empty';
        this._emptyEl.innerHTML = `
          <h3>No topology data</h3>
          <p>Add devices and create relationships, or import a session. Topology is generated only from recorded relationship evidence — no invented links.</p>
        `;
        this.container.appendChild(this._emptyEl);
      }
      this._emptyEl.style.display = 'flex';
    } else if (this._emptyEl) {
      this._emptyEl.style.display = 'none';
    }
  }

  _applyTransform() {
    const t = `translate(${this.offsetX},${this.offsetY}) scale(${this.scale})`;
    this.gEdges.setAttribute('transform', t);
    this.gNodes.setAttribute('transform', t);
  }

  _bindEvents() {
    this.svg.addEventListener('pointerdown', (e) => {
      const target = e.target.closest('.node-group');
      if (target) {
        const id = target.dataset.id;
        this.selectedId = id;
        this.dragging = {
          id,
          startX: e.clientX,
          startY: e.clientY,
          origX: this.devices.find(d => d.id === id)?.mapX ?? 0,
          origY: this.devices.find(d => d.id === id)?.mapY ?? 0
        };
        this.svg.setPointerCapture(e.pointerId);
        this.render();
        this.onSelect(id);
        e.preventDefault();
        return;
      }
      this.panning = true;
      this.lastPan = { x: e.clientX, y: e.clientY };
      this.svg.setPointerCapture(e.pointerId);
      e.preventDefault();
    });

    this.svg.addEventListener('pointermove', (e) => {
      if (this.dragging) {
        const dx = (e.clientX - this.dragging.startX) / this.scale;
        const dy = (e.clientY - this.dragging.startY) / this.scale;
        const dev = this.devices.find(d => d.id === this.dragging.id);
        if (dev) {
          dev.mapX = this.dragging.origX + dx;
          dev.mapY = this.dragging.origY + dy;
          this.render();
        }
        e.preventDefault();
        return;
      }
      if (this.panning && this.lastPan) {
        this.offsetX += e.clientX - this.lastPan.x;
        this.offsetY += e.clientY - this.lastPan.y;
        this.lastPan = { x: e.clientX, y: e.clientY };
        this._applyTransform();
        e.preventDefault();
      }
    });

    this.svg.addEventListener('pointerup', (e) => {
      if (this.dragging) {
        const dev = this.devices.find(d => d.id === this.dragging.id);
        if (dev) this.onPositionChange(dev.id, dev.mapX, dev.mapY);
        this.dragging = null;
      }
      this.panning = false;
      this.lastPan = null;
    });

    this.svg.addEventListener('pointercancel', () => {
      this.dragging = null;
      this.panning = false;
      this.lastPan = null;
    });

    let lastDist = null;
    this.svg.addEventListener('touchstart', (e) => {
      if (e.touches.length === 2) {
        lastDist = Math.hypot(
          e.touches[0].clientX - e.touches[1].clientX,
          e.touches[0].clientY - e.touches[1].clientY
        );
      }
    }, { passive: true });

    this.svg.addEventListener('touchmove', (e) => {
      if (e.touches.length === 2 && lastDist != null) {
        const dist = Math.hypot(
          e.touches[0].clientX - e.touches[1].clientX,
          e.touches[0].clientY - e.touches[1].clientY
        );
        const factor = dist / lastDist;
        this.scale = Math.max(0.3, Math.min(3, this.scale * factor));
        lastDist = dist;
        this._applyTransform();
      }
    }, { passive: true });
  }

  zoomIn() {
    this.scale = Math.min(3, this.scale * 1.25);
    this._applyTransform();
  }
  zoomOut() {
    this.scale = Math.max(0.3, this.scale / 1.25);
    this._applyTransform();
  }
  resetView() {
    this.scale = 1;
    this.offsetX = 0;
    this.offsetY = 0;
    this._applyTransform();
  }

  setFilter(key, value) {
    this.filters[key] = value;
    this.render();
  }

  select(id) {
    this.selectedId = id;
    this.render();
  }
}
