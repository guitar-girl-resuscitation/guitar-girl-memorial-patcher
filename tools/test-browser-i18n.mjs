import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const html=readFileSync(new URL('../web/index.html',import.meta.url),'utf8');
// XAPK can be ZIP, octet-stream, or unknown to Android's document provider.
// An accept filter can hide valid files before our content hash check runs.
const fileInput=html.match(/<input\b[^>]*\bid="source"[^>]*>/)[0];
assert.match(fileInput,/\btype="file"/);
assert.doesNotMatch(fileInput,/\baccept\s*=/i);
assert.match(html,/const ok=digest===health\.sourceSha256\.toUpperCase\(\)/);
assert.match(html,/if\(busy\|\|!file\|\|!health\|\|digest!==health\.sourceSha256\.toUpperCase\(\)\)return/);
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
function element(){return {textContent:'',value:'',disabled:false,children:[],dataset:{},setAttribute(k,v){this[k]=v},replaceChildren(...children){this.children=children}}}
async function page(browserLanguage, stored, blocked=false, prebuilt=true){
 const nodes=new Map();
 for(const id of ['source','status','progress','language','filename','upload','hash','versions'])nodes.set(id,element());
 nodes.get('upload').disabled=true;
 const labels=[...html.matchAll(/data-i18n="([^"]+)"/g)].map(m=>Object.assign(element(),{dataset:{i18n:m[1]}}));
 const document={documentElement:{},getElementById:id=>nodes.get(id),querySelectorAll:()=>labels,createElement:element,createTextNode:text=>({textContent:text})};
 const storage={value:stored,getItem(){if(blocked)throw Error('blocked');return this.value},setItem(k,v){if(blocked)throw Error('blocked');this.value=v}};
 const context=vm.createContext({document,navigator:{language:browserLanguage},localStorage:storage,
  fetch:async()=>({ok:true,json:async()=>({prebuiltEnabled:prebuilt,sourceVersion:'8.0.0',sourceSha256:'ABCD'})}),requestAnimationFrame:cb=>cb()});
 vm.runInContext(script,context);
 await vm.runInContext('ready',context);
 assert.equal(vm.runInContext('Object.keys(messages.zh).sort().join()===Object.keys(messages.en).sort().join()',context),true);
 return {context,nodes,document,storage,labels};
}
const en=await page('en-US',null);
assert.equal(en.document.documentElement.lang,'en');
assert.equal(en.nodes.get('upload').textContent,'Verify and download');
assert.equal(en.nodes.get('versions').children.length,3);
assert.equal(en.nodes.get('versions').children[0].children[1].textContent,'Not recorded');
vm.runInContext("health.components={server:{commit:'97d8c39dee247f30e9576612eff88022ba063c40',sourceUpdatedAt:'2026-09-06T09:26:51Z'}};renderVersions()",en.context);
assert.equal(en.nodes.get('versions').children[0].children[1].textContent,'97d8c39');
assert.equal(en.nodes.get('versions').children[0].children[2].textContent,'2026-09-06 09:26:51 UTC');
assert.match(en.nodes.get('status').textContent,/Supports Guitar Girl/);
vm.runInContext('download({downloadToken:"one-use-token"})',en.context);
assert.equal(en.nodes.get('status').className,'complete');
assert.equal(en.nodes.get('status').children.length,2);
const url=en.nodes.get('status').children[1].href;
en.nodes.get('language').value='zh';en.nodes.get('language').onchange();
assert.equal(en.storage.value,'zh');
assert.equal(en.document.documentElement.lang,'zh-Hans');
assert.equal(en.nodes.get('status').children[1].href,url);
assert.match(en.nodes.get('status').children[1].textContent,/下载/);
assert.match(html,/#status\.complete\{[^}]*flex-direction:column[^}]*gap:14px/);
assert.match(html,/button,a\.button\{display:inline-flex/);
vm.runInContext("show('hashing')",en.context);
assert.equal(en.nodes.get('status').className,'');
assert.equal(en.nodes.get('upload').disabled,true);
const zh=await page('zh-TW',null,true,false);
assert.equal(zh.document.documentElement.lang,'zh-Hans');
assert.match(zh.nodes.get('upload').textContent,/完整上传/);
zh.nodes.get('source').files=[{name:'too-large.xapk',size:769*1024*1024}];
await zh.nodes.get('source').onchange();
assert.match(zh.nodes.get('status').textContent,/768 MiB/);
assert.equal(zh.nodes.get('upload').disabled,true);
assert.equal((await page('es-ES',null)).document.documentElement.lang,'en');
assert.equal((await page('zh-CN','en')).document.documentElement.lang,'en');
assert.equal((await page('en','invalid')).document.documentElement.lang,'en');
console.log('browser i18n: language detection, storage fallback, key parity, modes, errors and download preservation OK');
