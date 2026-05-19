// selfdef minimal-web client — sovereignty-clean (vanilla JS, no framework)
// per MS043 R10173 (SSE 2s refresh) + R10212 (no mutations from web)

(function () {
  'use strict';

  // ---- per-panel SSE wiring ----
  const panels = document.querySelectorAll('.panel-body[data-sse]');
  panels.forEach((p) => {
    const path = p.dataset.sse;
    startStream(p, path);
  });

  function startStream(target, ssePath) {
    let es;
    try {
      es = new EventSource(ssePath);
      es.addEventListener('snapshot', (ev) => {
        try {
          const data = JSON.parse(ev.data);
          render(target, data);
        } catch (e) {
          // malformed payload — keep last good render
        }
      });
      es.addEventListener('error', () => {
        try { es.close(); } catch (e) {}
        // R10173: fallback to polling every 2s if SSE drops
        setTimeout(() => poll(target, ssePath), 2000);
      });
    } catch (e) {
      // EventSource unavailable; fall back to polling
      setTimeout(() => poll(target, ssePath), 2000);
    }
  }

  function poll(target, ssePath) {
    const snapshotPath = ssePath.replace('/sse/', '/api/d-7575/');
    fetch(snapshotPath)
      .then((r) => r.json())
      .then((data) => {
        render(target, data);
        setTimeout(() => poll(target, ssePath), 2000);
      })
      .catch(() => {
        setTimeout(() => poll(target, ssePath), 2000);
      });
  }

  function render(target, data) {
    // Minimal renderer — list rows with id pill + state.
    if (!data || !Array.isArray(data.rows)) {
      target.textContent = JSON.stringify(data, null, 2);
      return;
    }
    target.innerHTML = '';
    for (const r of data.rows) {
      const row = document.createElement('div');
      row.className = 'row';
      const id = document.createElement('span');
      id.className = 'id';
      id.textContent = r.id || '';
      const body = document.createElement('span');
      body.textContent = r.text || '';
      row.appendChild(id);
      row.appendChild(body);
      if (r.state) {
        const pill = document.createElement('span');
        pill.className = 'pill ' + (r.state === 'ok' ? 'ok' : (r.state === 'bad' ? 'bad' : 'warn'));
        pill.textContent = r.state;
        row.appendChild(pill);
      }
      target.appendChild(row);
    }
  }

  // ---- keyboard navigation per MS043 R10263-R10266 + F05159 ----
  const PANEL_ORDER = ['rules', 'grants', 'quarantine', 'authority'];
  let focusIdx = -1;

  function focusPanel(idx) {
    const kind = PANEL_ORDER[idx];
    const panel = document.getElementById('panel-' + kind);
    if (!panel) return;
    panel.tabIndex = 0;
    panel.focus();
    focusIdx = idx;
  }

  window.addEventListener('keydown', (e) => {
    // Tab cycles panels
    if (e.key === 'Tab' && !e.metaKey && !e.ctrlKey) {
      e.preventDefault();
      focusPanel((focusIdx + (e.shiftKey ? -1 : 1) + PANEL_ORDER.length) % PANEL_ORDER.length);
      return;
    }
    // ? shows help
    if (e.key === '?') {
      showToast('Tab/Shift-Tab cycle · Esc blur · clipboard CLI per R10212');
      return;
    }
    // Esc exits focus
    if (e.key === 'Escape') {
      if (document.activeElement && document.activeElement.blur) {
        document.activeElement.blur();
      }
      focusIdx = -1;
      return;
    }
  });

  // ---- web→CLI clipboard helper (R10212: web NEVER mutates) ----
  window.selfdefCopyCli = function (cmd) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(cmd).then(() => {
        showToast('copied to clipboard: ' + cmd.slice(0, 60) + (cmd.length > 60 ? '…' : ''));
      });
    } else {
      // fallback: select-and-copy via execCommand
      const ta = document.createElement('textarea');
      ta.value = cmd;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
      } catch (e) { /* nop */ }
      document.body.removeChild(ta);
      showToast('copied (fallback)');
    }
  };

  function showToast(msg) {
    let t = document.querySelector('.toast');
    if (!t) {
      t = document.createElement('div');
      t.className = 'toast';
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(showToast._h);
    showToast._h = setTimeout(() => t.classList.remove('show'), 1800);
  }

  // ---- auth state surfaced to header ----
  fetch('/api/auth/state')
    .then((r) => r.json())
    .then((s) => {
      const el = document.getElementById('auth-state');
      if (el && s.has_operator_key) {
        el.textContent = 'unlocked (operator MS003)';
        el.classList.add('unlocked');
      }
    })
    .catch(() => { /* read-only is the default */ });
})();
