const CACHE_NAME = 'kaytagi-cache-v1';
const CACHE_URLS = ['/', '/index.html', '/icon.svg', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(CACHE_URLS).catch(() => {})));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Network-first strategy: always try network, fallback to cache
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  if (!e.request.url.startsWith('http')) return;
  // Don't cache Supabase API calls
  if (e.request.url.includes('supabase.co')) return;
  e.respondWith(
    fetch(e.request)
      .then(res => {
        const clone = res.clone();
        caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});

// Push notification handler
self.addEventListener('push', e => {
  if (!e.data) return;
  let data = {};
  try { data = e.data.json(); } catch { data = { title: '🔔 Кайтаги', body: e.data.text() }; }
  e.waitUntil(
    self.registration.showNotification(data.title || '🔔 Кайтаги', {
      body: data.body || 'Новый заказ!',
      icon: '/icon.svg',
      badge: '/icon.svg',
      vibrate: [200, 100, 200, 100, 200],
      tag: data.tag || 'kaytagi-notif',
      requireInteraction: true,
      data: { url: data.url || '/' }
    })
  );
});

// Notification click — focus or open the app
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = e.notification.data?.url || '/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(all => {
      for (const c of all) {
        if ('focus' in c) { c.focus(); return; }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
