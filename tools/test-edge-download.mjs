import assert from 'node:assert/strict';
import {webcrypto as crypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const size = 16 * 1024 * 1024;
const pieces = [new Uint8Array(size).fill(17), Uint8Array.of(2, 3, 5, 7)];
const key = await crypto.subtle.generateKey({name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
const manifest = {schema:1, cache:'A'.repeat(64), generation:'B'.repeat(64),
  key:Buffer.from(await crypto.subtle.exportKey('raw',key)).toString('hex'),
  size:size+4, partSize:size, versionCode:800041};
const tickets = new Set(['fresh','second','damaged']);
const edge = new Map();
let reads = 0;
async function fetch(url) {
  if (url instanceof URL) {
    if (!tickets.delete(url.pathname.split('/').pop())) return new Response(null,{status:404});
    return Response.json(manifest);
  }
  if (!edge.has(url)) {
    const i = Number(url.split('.').pop()), iv = new Uint8Array(12);
    new DataView(iv.buffer).setUint32(8,i);
    edge.set(url,new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,pieces[i])));
    reads++;
  }
  return new Response(edge.get(url));
}
const env = vm.createContext({self:{addEventListener(){}}, crypto, fetch, URL, Response, Uint8Array,
  DataView, ReadableStream, AbortController, setTimeout});
vm.runInContext(readFileSync(new URL('../web/download-sw.js',import.meta.url),'utf8'),env);
function redeem(t){return env.download(new URL('https://example.com/api/v1/download/'+t),new AbortController().signal);}
for (const t of ['fresh','second']) {
  const response = await redeem(t);
  assert.match(response.headers.get('content-disposition'),/800041\.xapk/);
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), Buffer.concat(pieces));
  assert.equal(reads,2);
}
assert.equal((await redeem('fresh')).status,404);
manifest.generation = 'C'.repeat(64);
manifest.versionCode++;
assert.match((await redeem('damaged')).headers.get('content-disposition'),/800042\.xapk/);
tickets.add('tampered');
edge.set('/?ggfm-part='+manifest.cache+'.'+manifest.generation+'.1',new Uint8Array(20));
await assert.rejects(async()=> (await redeem('tampered')).arrayBuffer());
console.log('Verified round trip, warm cache, redeemed ticket replay, version naming and tamper rejection');
