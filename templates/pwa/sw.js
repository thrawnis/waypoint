/*
 * Waypoint service worker. Served from /sw.js (not /static/) so its scope is
 * the whole site. Pages and API calls always come from the network — they're
 * per-user and must never be served stale — with a cached offline page as the
 * fallback when there's no connection. Static files have content-hashed names,
 * so they're safe to serve cache-first.
 */
const VERSION = '{{ version|escapejs }}';
const CACHE = 'waypoint-' + VERSION;
const OFFLINE_URL = '{% url "offline" %}';
const PRECACHE = [OFFLINE_URL, '{{ icon_url|escapejs }}'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => caches.match(OFFLINE_URL)));
    return;
  }

  if (url.pathname.startsWith('{{ static_prefix|escapejs }}')) {
    event.respondWith(
      caches.match(req).then((hit) => hit || fetch(req).then((resp) => {
        if (resp.ok) {
          const copy = resp.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return resp;
      }))
    );
  }
});
