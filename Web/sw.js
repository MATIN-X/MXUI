// ============================================================================
// MXUI VPN Panel - Service Worker
// Version: 1.0.0
// ============================================================================

const CACHE_NAME = 'mxui-panel-v1';
const STATIC_CACHE = 'mxui-static-v1';
const DYNAMIC_CACHE = 'mxui-dynamic-v1';
const API_CACHE = 'mxui-api-v1';

// Static assets to cache on install
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/login.html',
    '/dashboard.html',
    '/subscription.html',
    '/app.js',
    '/api.js',
    '/ui.js',
    '/utils.js',
    '/styles.css',
    '/manifest.json',
    '/lang_fa.json',
    '/lang_en.json',
    '/lang_ru.json',
    '/lang_zh.json',
    '/assets/favicon.png',
    '/assets/icon-192.png',
    '/assets/icon-512.png'
];

// API endpoints to cache
const API_ENDPOINTS = [
    '/api/stats',
    '/api/admin/profile'
];

// Cache expiration times (in seconds)
const CACHE_EXPIRATION = {
    static: 7 * 24 * 60 * 60,    // 7 days
    dynamic: 24 * 60 * 60,       // 1 day
    api: 5 * 60                   // 5 minutes
};

// ============================================================================
// INSTALL EVENT
// ============================================================================

self.addEventListener('install', (event) => {
    console.log('[SW] Installing service worker...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then((cache) => {
                console.log('[SW] Caching static assets');
                return cache.addAll(STATIC_ASSETS.map(url => {
                    return new Request(url, { cache: 'reload' });
                })).catch(err => {
                    console.warn('[SW] Some static assets failed to cache:', err);
                });
            })
            .then(() => {
                console.log('[SW] Service worker installed');
                return self.skipWaiting();
            })
    );
});

// ============================================================================
// ACTIVATE EVENT
// ============================================================================

self.addEventListener('activate', (event) => {
    console.log('[SW] Activating service worker...');
    
    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames
                        .filter((name) => {
                            return name.startsWith('mxui-') && 
                                   name !== STATIC_CACHE && 
                                   name !== DYNAMIC_CACHE &&
                                   name !== API_CACHE;
                        })
                        .map((name) => {
                            console.log('[SW] Deleting old cache:', name);
                            return caches.delete(name);
                        })
                );
            })
            .then(() => {
                console.log('[SW] Service worker activated');
                return self.clients.claim();
            })
    );
});

// ============================================================================
// FETCH EVENT
// ============================================================================

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // Skip non-GET requests
    if (event.request.method !== 'GET') {
        return;
    }
    
    // Skip chrome-extension and other protocols
    if (!url.protocol.startsWith('http')) {
        return;
    }
    
    // Handle API requests
    if (url.pathname.startsWith('/api/')) {
        event.respondWith(handleApiRequest(event.request));
        return;
    }
    
    // Handle static assets
    if (isStaticAsset(url.pathname)) {
        event.respondWith(handleStaticRequest(event.request));
        return;
    }
    
    // Handle dynamic requests
    event.respondWith(handleDynamicRequest(event.request));
});

// ============================================================================
// REQUEST HANDLERS
// ============================================================================

// Handle static assets (cache-first strategy)
async function handleStaticRequest(request) {
    const cached = await caches.match(request);
    
    if (cached) {
        // Return cached and update in background
        fetchAndCache(request, STATIC_CACHE);
        return cached;
    }
    
    return fetchAndCache(request, STATIC_CACHE);
}

// Handle API requests (network-first strategy with fallback)
async function handleApiRequest(request) {
    try {
        const response = await fetchWithTimeout(request, 5000);
        
        if (response.ok) {
            const cache = await caches.open(API_CACHE);
            cache.put(request, response.clone());
        }
        
        return response;
    } catch (error) {
        console.log('[SW] API request failed, trying cache:', request.url);
        
        const cached = await caches.match(request);
        if (cached) {
            return cached;
        }
        
        // Return offline response
        return new Response(
            JSON.stringify({ 
                error: 'offline',
                message: 'Ø´Ù…Ø§ Ø¢ÙÙ„Ø§ÛŒÙ† Ù‡Ø³ØªÛŒØ¯'
            }),
            { 
                status: 503,
                headers: { 'Content-Type': 'application/json' }
            }
        );
    }
}

// Handle dynamic requests (stale-while-revalidate strategy)
async function handleDynamicRequest(request) {
    const cached = await caches.match(request);
    
    const fetchPromise = fetch(request)
        .then((response) => {
            if (response.ok) {
                const cache = caches.open(DYNAMIC_CACHE);
                cache.then(c => c.put(request, response.clone()));
            }
            return response;
        })
        .catch(() => {
            // Return offline page for navigation requests
            if (request.mode === 'navigate') {
                return caches.match('/offline.html');
            }
            return null;
        });
    
    return cached || fetchPromise;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function isStaticAsset(pathname) {
    const staticExtensions = [
        '.html', '.css', '.js', '.json',
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot'
    ];
    
    return staticExtensions.some(ext => pathname.endsWith(ext)) ||
           STATIC_ASSETS.includes(pathname);
}

async function fetchAndCache(request, cacheName) {
    try {
        const response = await fetch(request);
        
        if (response.ok) {
            const cache = await caches.open(cacheName);
            cache.put(request, response.clone());
        }
        
        return response;
    } catch (error) {
        const cached = await caches.match(request);
        if (cached) {
            return cached;
        }
        throw error;
    }
}

function fetchWithTimeout(request, timeout) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error('Request timeout'));
        }, timeout);
        
        fetch(request)
            .then((response) => {
                clearTimeout(timer);
                resolve(response);
            })
            .catch((error) => {
                clearTimeout(timer);
                reject(error);
            });
    });
}

// ============================================================================
// PUSH NOTIFICATIONS
// ============================================================================

self.addEventListener('push', (event) => {
    console.log('[SW] Push notification received');
    
    let data = {
        title: 'MXUI Panel',
        body: 'Ø§Ø¹Ù„Ø§Ù† Ø¬Ø¯ÛŒØ¯',
        icon: '/assets/icon-192.png',
        badge: '/assets/badge-72.png',
        tag: 'mxui-notification',
        data: {}
    };
    
    if (event.data) {
        try {
            data = { ...data, ...event.data.json() };
        } catch (e) {
            data.body = event.data.text();
        }
    }
    
    const options = {
        body: data.body,
        icon: data.icon,
        badge: data.badge,
        tag: data.tag,
        data: data.data,
        vibrate: [200, 100, 200],
        actions: data.actions || [
            { action: 'open', title: 'Ù…Ø´Ø§Ù‡Ø¯Ù‡' },
            { action: 'close', title: 'Ø¨Ø³ØªÙ†' }
        ],
        requireInteraction: data.requireInteraction || false
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

// Handle notification click
self.addEventListener('notificationclick', (event) => {
    console.log('[SW] Notification clicked:', event.action);
    
    event.notification.close();
    
    if (event.action === 'close') {
        return;
    }
    
    const urlToOpen = event.notification.data?.url || '/dashboard.html';
    
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then((clientList) => {
                // Check if there's already a window open
                for (const client of clientList) {
                    if (client.url.includes(urlToOpen) && 'focus' in client) {
                        return client.focus();
                    }
                }
                // Open new window
                if (clients.openWindow) {
                    return clients.openWindow(urlToOpen);
                }
            })
    );
});

// ============================================================================
// BACKGROUND SYNC
// ============================================================================

self.addEventListener('sync', (event) => {
    console.log('[SW] Background sync:', event.tag);
    
    if (event.tag === 'sync-data') {
        event.waitUntil(syncData());
    }
    
    if (event.tag === 'sync-backup') {
        event.waitUntil(syncBackup());
    }
});

async function syncData() {
    try {
        // Get pending requests from IndexedDB
        const pendingRequests = await getPendingRequests();
        
        for (const request of pendingRequests) {
            try {
                const response = await fetch(request.url, {
                    method: request.method,
                    headers: request.headers,
                    body: request.body
                });
                
                if (response.ok) {
                    await removePendingRequest(request.id);
                }
            } catch (error) {
                console.error('[SW] Sync failed for request:', request.id);
            }
        }
    } catch (error) {
        console.error('[SW] Sync data failed:', error);
    }
}

async function syncBackup() {
    try {
        // Trigger backup creation
        const response = await fetch('/api/backup/auto', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            console.log('[SW] Auto backup completed');
        }
    } catch (error) {
        console.error('[SW] Auto backup failed:', error);
    }
}

// IndexedDB helpers for pending requests
function openDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('mxui-sw-db', 1);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains('pending-requests')) {
                db.createObjectStore('pending-requests', { keyPath: 'id', autoIncrement: true });
            }
        };
    });
}

async function getPendingRequests() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction('pending-requests', 'readonly');
        const store = transaction.objectStore('pending-requests');
        const request = store.getAll();
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);
    });
}

async function removePendingRequest(id) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction('pending-requests', 'readwrite');
        const store = transaction.objectStore('pending-requests');
        const request = store.delete(id);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}

// ============================================================================
// PERIODIC SYNC (if supported)
// ============================================================================

self.addEventListener('periodicsync', (event) => {
    console.log('[SW] Periodic sync:', event.tag);
    
    if (event.tag === 'check-updates') {
        event.waitUntil(checkForUpdates());
    }
    
    if (event.tag === 'refresh-stats') {
        event.waitUntil(refreshStats());
    }
});

async function checkForUpdates() {
    try {
        const response = await fetch('/api/version');
        const data = await response.json();
        
        // Notify clients if update available
        const clients = await self.clients.matchAll();
        clients.forEach(client => {
            client.postMessage({
                type: 'UPDATE_AVAILABLE',
                version: data.version
            });
        });
    } catch (error) {
        console.error('[SW] Check updates failed:', error);
    }
}

async function refreshStats() {
    try {
        const response = await fetch('/api/stats');
        
        if (response.ok) {
            const cache = await caches.open(API_CACHE);
            cache.put('/api/stats', response);
        }
    } catch (error) {
        console.error('[SW] Refresh stats failed:', error);
    }
}

// ============================================================================
// MESSAGE HANDLER
// ============================================================================

self.addEventListener('message', (event) => {
    console.log('[SW] Message received:', event.data);
    
    const { type, payload } = event.data;
    
    switch (type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;
            
        case 'CLEAR_CACHE':
            clearAllCaches().then(() => {
                event.ports[0].postMessage({ success: true });
            });
            break;
            
        case 'CACHE_URLS':
            cacheUrls(payload.urls).then(() => {
                event.ports[0].postMessage({ success: true });
            });
            break;
            
        case 'GET_CACHE_SIZE':
            getCacheSize().then((size) => {
                event.ports[0].postMessage({ size });
            });
            break;
    }
});

async function clearAllCaches() {
    const cacheNames = await caches.keys();
    await Promise.all(cacheNames.map(name => caches.delete(name)));
    console.log('[SW] All caches cleared');
}

async function cacheUrls(urls) {
    const cache = await caches.open(DYNAMIC_CACHE);
    await cache.addAll(urls);
    console.log('[SW] URLs cached:', urls.length);
}

async function getCacheSize() {
    if ('storage' in navigator && 'estimate' in navigator.storage) {
        const estimate = await navigator.storage.estimate();
        return estimate.usage;
    }
    return 0;
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

self.addEventListener('error', (event) => {
    console.error('[SW] Error:', event.error);
});

self.addEventListener('unhandledrejection', (event) => {
    console.error('[SW] Unhandled rejection:', event.reason);
});

console.log('[SW] Service worker loaded');
