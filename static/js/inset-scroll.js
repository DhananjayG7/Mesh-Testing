(() => {
  class InsetScroll {
    constructor(area, opts = {}) {
      this.area = area;
      this.opts = Object.assign({
        insetRight: toNumber(area.dataset.insetRight, 36),
        width: toNumber(area.dataset.width, 22),
        minThumb: toNumber(area.dataset.minThumb, 48),
        header: area.dataset.header || '.header',  // selector for header (optional)
        offsetTop: toNumber(area.dataset.offsetTop, 0), // extra pixels under header
        trackBg: area.dataset.trackBg || null,
        thumbBg: area.dataset.thumbBg || null,
        lockBody: area.dataset.lockBody === 'true' // if true, will add .is-lock-body to <body>
      }, opts);

      this.track = document.createElement('div');
      this.track.className = 'is-track';
      this.thumb = document.createElement('div');
      this.thumb.className = 'is-thumb';
      this.track.appendChild(this.thumb);
      document.body.appendChild(this.track);

      // Apply per-instance CSS variables
      this.track.style.setProperty('--is-inset-right', this.opts.insetRight + 'px');
      this.track.style.setProperty('--is-width', this.opts.width + 'px');
      this.track.style.setProperty('--is-min-thumb', this.opts.minThumb + 'px');
      if (this.opts.trackBg) this.track.style.setProperty('--is-track-bg', this.opts.trackBg);
      if (this.opts.thumbBg) this.track.style.setProperty('--is-thumb-bg', this.opts.thumbBg);

      if (this.opts.lockBody) document.body.classList.add('is-lock-body');

      this.dragging = false;
      this.startY = 0;
      this.startScrollTop = 0;

      this.headerEl = findHeader(this.opts.header);

      // events
      this._onAreaScroll = this.refreshThumb.bind(this);
      this._onResize = this.layout.bind(this);

      this.area.addEventListener('scroll', this._onAreaScroll, { passive: true });
      window.addEventListener('resize', this._onResize);

      this.thumb.addEventListener('pointerdown', this.onThumbDown.bind(this));
      this.thumb.addEventListener('pointerup', this.onThumbUp.bind(this));
      this.thumb.addEventListener('pointercancel', this.onThumbUp.bind(this));
      this.thumb.addEventListener('lostpointercapture', () => (this.dragging = false));
      this.thumb.addEventListener('pointermove', this.onThumbMove.bind(this));

      this.track.addEventListener('pointerdown', (e) => {
        if (e.target !== this.track) return;
        const trackRect = this.track.getBoundingClientRect();
        const clickY = e.clientY - trackRect.top;
        const thumbH = this.thumb.offsetHeight;
        const trackH = this.track.clientHeight;
        const maxTop = Math.max(1, trackH - thumbH);
        const maxScroll = Math.max(1, this.area.scrollHeight - this.area.clientHeight);
        const targetTop = clamp(clickY - thumbH / 2, 0, maxTop);
        const targetScroll = (targetTop / maxTop) * maxScroll;
        this.area.scrollTop = targetScroll;
      });

      // observe size changes (fonts/images load, etc.)
      this.ro = new ResizeObserver(() => this.layout());
      this.ro.observe(this.area);
      if (this.headerEl) this.ro.observe(this.headerEl);

      // initial layout
      this.layout();
      window.addEventListener('load', () => this.layout());
      setTimeout(() => this.layout(), 300);
    }

    layout() {
      // position track below header
      const headerBottom = this.headerEl ? Math.ceil(this.headerEl.getBoundingClientRect().bottom) : 0;
      const top = headerBottom + this.opts.offsetTop;
      const height = window.innerHeight - top;
      this.track.style.top = top + 'px';
      this.track.style.height = height + 'px';

      // pin the scroll area’s height to remaining viewport space if it’s the body child
      if (this.area === document.body || this.area === document.documentElement) {
        // not recommended; better to use a dedicated container
      } else {
        this.area.style.height = height + 'px';
      }

      this.toggleTrack();
      this.refreshThumb();
    }

    toggleTrack() {
      if (this.area.scrollHeight > this.area.clientHeight + 1) {
        this.track.style.display = 'block';
      } else {
        this.track.style.display = 'none';
      }
    }

    refreshThumb() {
      const trackH = this.track.clientHeight;
      const maxScroll = Math.max(0, this.area.scrollHeight - this.area.clientHeight);
      const ratio = this.area.clientHeight / (this.area.scrollHeight || 1);
      const minThumb = this.opts.minThumb;
      const thumbH = clamp(Math.round(trackH * ratio), minThumb, trackH);
      this.thumb.style.height = thumbH + 'px';

      const maxTop = trackH - thumbH;
      const scrollTop = this.area.scrollTop;
      const thumbTop = maxScroll ? (scrollTop / maxScroll) * maxTop : 0;
      this.thumb.style.transform = 'translateY(' + thumbTop + 'px)';
    }

    onThumbDown(e) {
      this.dragging = true;
      this.thumb.setPointerCapture(e.pointerId);
      this.startY = e.clientY;
      this.startScrollTop = this.area.scrollTop;
      e.preventDefault();
    }

    onThumbMove(e) {
      if (!this.dragging) return;
      const trackH = this.track.clientHeight;
      const thumbH = this.thumb.offsetHeight;
      const maxTop = Math.max(1, trackH - thumbH);
      const maxScroll = Math.max(1, this.area.scrollHeight - this.area.clientHeight);
      const deltaY = e.clientY - this.startY;
      const scrollPerPixel = maxScroll / maxTop;
      this.area.scrollTop = clamp(this.startScrollTop + deltaY * scrollPerPixel, 0, maxScroll);
    }

    onThumbUp(e) {
      if (!this.dragging) return;
      this.dragging = false;
      try { this.thumb.releasePointerCapture(e.pointerId); } catch (_) {}
    }

    destroy() {
      this.area.removeEventListener('scroll', this._onAreaScroll);
      window.removeEventListener('resize', this._onResize);
      this.ro.disconnect();
      this.track.remove();
    }
  }

  // Helpers
  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }
  function toNumber(x, fallback) {
    const n = Number(x);
    return Number.isFinite(n) ? n : fallback;
  }
  function findHeader(sel) {
    if (!sel) return null;
    try {
      const el = document.querySelector(sel);
      return el || null;
    } catch { return null; }
  }

  // Auto-init: any element with class "inset-scroll-area"
  function initInsetScroll() {
    const instances = [];
    document.querySelectorAll('.inset-scroll-area').forEach((area) => {
      instances.push(new InsetScroll(area));
    });
    // Expose for debugging or later teardown
    window.__InsetScrollInstances = instances;
  }

  // Public API if you want to call manually elsewhere
  window.InsetScrollInit = initInsetScroll;

  document.addEventListener('DOMContentLoaded', initInsetScroll);
})();
