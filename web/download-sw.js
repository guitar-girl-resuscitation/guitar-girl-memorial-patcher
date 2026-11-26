/* Browser service worker; runs on the player's device. */
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method === 'GET' && url.origin === self.location.origin &&
      /^\/api\/v1\/download\/[A-Za-z0-9._-]+$/.test(url.pathname) && !url.search) {
    event.respondWith(download(url, event.request.signal));
  }
});

async function readPart(path, signal) {
  for (let attempt = 0; ; attempt++) {
    let delay = 1000 * (attempt + 1);
    try {
      const response = await fetch(path, {signal, credentials:'omit', redirect:'error'});
      if (response.ok) return await response.arrayBuffer();
      if (response.status !== 429 && response.status < 500) throw new RangeError('Part unavailable');
      delay = Math.max(delay, Math.min(120000, (Number(response.headers.get('retry-after')) || 0) * 1000));
      await response.body?.cancel();
    } catch (error) {
      if (error instanceof RangeError || signal.aborted || attempt === 3) throw error;
    }
    if (attempt === 3) throw Error('Unable to download part');
    await new Promise(resolve => setTimeout(resolve, delay));
  }
}

async function download(url, signal) {
  url.search = 'ggfm-manifest=1';
  const response = await fetch(url, {cache:'no-store', redirect:'error', signal});
  // Also supports a draining generation which serves the original file here.
  if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) return response;
  const m = await response.json();
  if (m.schema !== 1 || !/^[0-9A-F]{64}$/.test(m.cache) ||
      !/^[0-9A-F]{64}$/.test(m.generation) || !/^[0-9a-f]{64}$/.test(m.key) ||
      !Number.isSafeInteger(m.size) || m.size <= 0 || !Number.isSafeInteger(m.versionCode) ||
      m.versionCode <= 0 || m.partSize !== 16 * 1024 * 1024) throw Error('Invalid download manifest');
  const key = await crypto.subtle.importKey('raw', Uint8Array.from(m.key.match(/../g), b => parseInt(b,16)),
      'AES-GCM', false, ['decrypt']);
  const abort = new AbortController();
  signal.addEventListener('abort', () => abort.abort(), {once:true});
  let index = 0;
  const body = new ReadableStream({
    async pull(controller) {
      const path = '/?ggfm-part=' + m.cache + '.' + m.generation + '.' + index;
      const iv = new Uint8Array(12);
      new DataView(iv.buffer).setUint32(8, index, false);
      const size = Math.min(m.partSize, m.size - index * m.partSize);
      const bytes = await readPart(path, abort.signal);
      if (bytes.byteLength !== size + 16) throw Error('Incomplete encrypted part');
      const plaintext = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, bytes);
      controller.enqueue(new Uint8Array(plaintext));
      if (++index * m.partSize >= m.size) controller.close();
    },
    cancel() { abort.abort(); }
  });
  return new Response(body, {headers:{
    'Content-Type':'application/octet-stream', 'Content-Length':String(m.size),
    'Content-Disposition':'attachment; filename=Guitar-Girl-Fan-Memorial-Build-' + m.versionCode + '.xapk',
    'Cache-Control':'private, no-store'
  }});
}
