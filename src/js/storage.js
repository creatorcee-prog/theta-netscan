/**
 * Local persistence via IndexedDB + localStorage fallback.
 * Sessions are isolated. Never mix client networks.
 */

const DB_NAME = 'NetScan';
const DB_VERSION = 1;
const STORE = 'sessions';

let dbPromise = null;

function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    if (!window.indexedDB) {
      resolve(null);
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => resolve(null);
    req.onsuccess = () => resolve(req.result);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'id' });
      }
    };
  });
  return dbPromise;
}

export async function listSessions() {
  const db = await openDB();
  if (!db) {
    try {
      const raw = localStorage.getItem('ns_sessions_index');
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }
  return new Promise((resolve) => {
    const tx = db.transaction(STORE, 'readonly');
    const store = tx.objectStore(STORE);
    const req = store.getAll();
    req.onsuccess = () => {
      const sessions = (req.result || []).map(s => ({
        id: s.id,
        siteName: s.siteName,
        clientName: s.clientName,
        updatedAt: s.updatedAt,
        deviceCount: (s.devices || []).length
      }));
      resolve(sessions.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || '')));
    };
    req.onerror = () => resolve([]);
  });
}

export async function loadSession(id) {
  const db = await openDB();
  if (!db) {
    try {
      const raw = localStorage.getItem('ns_session_' + id);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }
  return new Promise((resolve) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(id);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => resolve(null);
  });
}

export async function saveSession(session) {
  session.updatedAt = new Date().toISOString();
  const db = await openDB();
  if (!db) {
    try {
      localStorage.setItem('ns_session_' + session.id, JSON.stringify(session));
      let index = [];
      try { index = JSON.parse(localStorage.getItem('ns_sessions_index') || '[]'); } catch {}
      const entry = {
        id: session.id,
        siteName: session.siteName,
        clientName: session.clientName,
        updatedAt: session.updatedAt,
        deviceCount: (session.devices || []).length
      };
      const idx = index.findIndex(s => s.id === session.id);
      if (idx >= 0) index[idx] = entry; else index.push(entry);
      localStorage.setItem('ns_sessions_index', JSON.stringify(index));
      return true;
    } catch (e) {
      console.error('localStorage save failed', e);
      return false;
    }
  }
  return new Promise((resolve) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(session);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => resolve(false);
  });
}

export async function deleteSession(id) {
  const db = await openDB();
  if (!db) {
    localStorage.removeItem('ns_session_' + id);
    try {
      let index = JSON.parse(localStorage.getItem('ns_sessions_index') || '[]');
      index = index.filter(s => s.id !== id);
      localStorage.setItem('ns_sessions_index', JSON.stringify(index));
    } catch {}
    return true;
  }
  return new Promise((resolve) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(id);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => resolve(false);
  });
}

export function exportSessionJSON(session) {
  const blob = new Blob([JSON.stringify(session, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `netscan-${(session.siteName || 'session').replace(/\s+/g, '_')}-${session.id.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportDevicesCSV(session) {
  const headers = [
    'id', 'hostname', 'ipAddress', 'macAddress', 'manufacturer', 'model',
    'category', 'os', 'status', 'vlan', 'subnet', 'gateway',
    'discoverySource', 'confidence', 'firstDiscovered', 'lastObserved', 'notes', 'tags'
  ];
  const rows = [headers.join(',')];
  for (const d of (session.devices || [])) {
    rows.push(headers.map(h => {
      let v = d[h];
      if (Array.isArray(v)) v = v.join(';');
      if (v == null) v = '';
      v = String(v).replace(/"/g, '""');
      if (v.includes(',') || v.includes('"') || v.includes('\n')) v = `"${v}"`;
      return v;
    }).join(','));
  }
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `netscan-devices-${session.id.slice(0, 8)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
