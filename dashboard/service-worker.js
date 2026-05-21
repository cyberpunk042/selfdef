// Minimal offline shell so the dashboard works on a phone with a flaky
// link. We cache the static shell aggressively but never the API
// responses themselves — operators need the freshest data they can get.

// Bump on every shell change so the activate hook can purge stale
// versions. v3 (2026-05-20): index.html gained modules-section;
// app.js gained refreshModules() + setInterval; consumes /v1/modules.
// v2 (2026-05-20): manifest gained scope/categories/512x512 icon;
// index.html gained scheduler panel; app.js gained the four-watchdog
// refresh handlers; dashboard.css gained the .fa-backpressure
// aggregate state.
// v26 (2026-05-21): MS043 UX — operator-named view presets in
// #tab-nav (Default / Security / Performance / Inference / Compact).
// Each preset snaps {hiddenPanels, activeTab, refreshRate} to an
// operator-meaningful configuration in one click. localStorage
// selfdef.activePreset persists the choice. Tractable interim
// toward the "20 dashboards" verbatim requirement.
// v25 (2026-05-21): MS043 UX — refresh-rate selector (Fast/Normal/
// Slow/Paused) in #tab-nav. localStorage selfdef.refreshRate
// persists the choice; gatedInterval() is now a self-rescheduling
// setTimeout chain so rate flips apply on the NEXT cycle of every
// panel without clearing handles. Hidden panels (operator-hidden
// OR tab-hidden) also skip their probe.
// v24 (2026-05-21): MS043 UX — operator-facing per-panel visibility
// menu in #tab-nav. localStorage selfdef.hiddenPanels persists the
// hidden set. .operator-hidden CSS class hides sections. View ▾
// button toggles the menu; checkboxes per panel; "Show all panels"
// reset row.
// v23 (2026-05-21): MS011 Z-8 path-conflict surface — app.js modules
// panel now fetches /v1/modules/install-plan in parallel and renders
// a yellow conflict badge + meta line when two planned modules
// declare the same path in [install_paths].
const SHELL = "selfdef-shell-v26";
const SHELL_ASSETS = [
  "./",
  "./index.html",
  "./app.js",
  "./dashboard.css",
  "./manifest.json",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(SHELL).then((c) => c.addAll(SHELL_ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== SHELL).map((k) => caches.delete(k))),
    ),
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  // Never intercept non-GET requests — caches.match won't return a
  // sensible response for a POST anyway, and we definitely don't want
  // to swallow a control verb (rules/reload, panic, actions/run).
  if (e.request.method !== "GET") {
    return;
  }
  // Read API calls and the SSE stream must always hit the network —
  // never serve a cached event list to an operator chasing an alert.
  if (
    url.pathname.startsWith("/events") ||
    url.pathname.startsWith("/findings") ||
    url.pathname.startsWith("/status") ||
    url.pathname.startsWith("/actions")
  ) {
    return;
  }
  e.respondWith(
    caches.match(e.request).then((cached) => cached || fetch(e.request)),
  );
});
