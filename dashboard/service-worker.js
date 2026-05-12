// Minimal offline shell so the dashboard works on a phone with a flaky
// link. We cache the static shell aggressively but never the API
// responses themselves — operators need the freshest data they can get.

const SHELL = "selfdef-shell-v1";
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
  // API calls and the SSE stream must always hit the network — never
  // serve a cached event list to an operator chasing an alert.
  if (
    url.pathname.startsWith("/events") ||
    url.pathname.startsWith("/findings") ||
    url.pathname.startsWith("/status")
  ) {
    return;
  }
  e.respondWith(
    caches.match(e.request).then((cached) => cached || fetch(e.request)),
  );
});
