self.addEventListener("install", (event) => {
    event.waitUntil(
      caches.open("maxgamers-cache-v1").then((cache) => {
        return cache.addAll([
          "/",
          "/manifest.json",
          "/uploads/icon-192.jpg",
          "/uploads/icon-512.jpg"
        ]);
      })
    );
  });
  
  self.addEventListener("fetch", (event) => {
    event.respondWith(
      caches.match(event.request).then((response) => {
        return response || fetch(event.request);
      })
    );
  });
  