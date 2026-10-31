/* Extension API harness, not a real Chrome/Gemini prevention claim. */
'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'../browser-extension');
const id='akncbelkcijoipfcfnhpcaajcfagkijm';
const own={id,url:`chrome-extension://${id}/options.html`};
const page={id,url:'https://gemini.google.com/app',tab:{id:1,url:'https://gemini.google.com/app'}};
const key=n=>'sedra_k_'+String(n).repeat(16)+'.'+'x'.repeat(43);
const pause=()=>new Promise(resolve=>setTimeout(resolve,30));
function harness(){
  const session={},local={},requests=[];let handler,offline=false,trusted=false;
  const storage=values=>({async get(keys){const result={};for(const k of typeof keys==='string'?[keys]:keys)result[k]=values[k];return result;},async set(v){Object.assign(values,v);},async remove(k){delete values[k];},async setAccessLevel(v){trusted=v.accessLevel==='TRUSTED_CONTEXTS';}});
  const chrome={storage:{session:storage(session),local:storage(local)},runtime:{id,getURL:p=>`chrome-extension://${id}/${p}`,onMessage:{addListener(fn){handler=fn;}}},alarms:{create(){},onAlarm:{addListener(){}}}};
  const context=vm.createContext({chrome,crypto:webcrypto,URL,TextEncoder,Uint8Array,AbortSignal,btoa,
    fetch:async(url,options)=>{if(offline)throw Error('offline');const body=JSON.parse(options.body);requests.push({url,body,authorization:options.headers.Authorization});return {ok:true,async json(){return {decision:body.failure?'BLOCK':'ALLOW',request_id:body.request_id,alert_ids:[]};}};},
    importScripts(...names){for(const name of names)vm.runInContext(fs.readFileSync(path.join(root,name),'utf8'),context);}});
  vm.runInContext(fs.readFileSync(path.join(root,'worker.js'),'utf8'),context);
  function send(message,sender=page){return new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Worker did not reply')),3000);const keep=handler(message,sender,value=>{clearTimeout(timer);resolve(value);});if(!keep){clearTimeout(timer);resolve({ignored:true});}});}
  return {send,session,local,requests,setOffline(v){offline=v;},get trusted(){return trusted;}};
}
const payload=(n=1)=>({kind:'inspect',payload:{request_id:'br-worker-test-'+n,operation:'send',mode:'preview',text:'PRIVATE_CONTENT_SENTINEL',files:[],host:'attacker.example'}});

test('composer navigation and upload buttons are not default submit controls outside forms',()=>{
  const core=require('../browser-extension/core.js');
  for(const label of ['Upload & tools','Main menu','Dismiss','Temporary chat'])assert.equal(core.isSendControl({type:'submit',formBound:false,label}),false);
  assert.equal(core.isSendControl({type:'submit',formBound:true,label:'Continue'}),true);
  assert.equal(core.isSendControl({type:'button',formBound:false,label:'Send message'}),true);
  assert.equal(core.isSendControl({type:'button',formBound:false,testId:'send-button',label:''}),true);
  assert.equal(core.isSendControl({type:'button',formBound:false,label:'Upload file'}),false);
});
test('manifest and destination validation grant only explicit hosts',()=>{
  const core=require('../browser-extension/core.js'),manifest=JSON.parse(fs.readFileSync(path.join(root,'manifest.json')));
  assert.equal(core.destination('https://gemini.google.com/app'),'gemini.google.com');
  for(const url of ['https://gemini.google.com.evil.example','https://user:pass@gemini.google.com/app','http://gemini.google.com','http://127.0.0.1:8765/portal'])assert.equal(core.destination(url),null);
  assert.equal(core.destination('http://127.0.0.1:8765/browser-lab'),'sedra-browser-lab');
  const hash=require('node:crypto').createHash('sha256').update(Buffer.from(manifest.key,'base64')).digest('hex').slice(0,32);
  assert.equal([...hash].map(x=>String.fromCharCode(97+parseInt(x,16))).join(''),id);
  assert(!JSON.stringify(manifest).includes('<all_urls>'));assert(!manifest.externally_connectable);
});
test('worker protects key storage and derives the host from the browser sender',async()=>{
  const h=harness();assert.equal((await h.send({kind:'connect',key:key('a')},own)).connected,true);
  const value=await h.send(payload());assert.equal(value.decision,'ALLOW');assert(h.trusted);
  const last=h.requests.at(-1);assert.equal(last.body.host,'gemini.google.com');assert.equal(last.url,'http://127.0.0.1:8765/api/v1/browser/inspect');
  assert.equal(last.authorization,'Bearer '+key('a'));assert(!JSON.stringify(value).includes(key('a')));assert(!JSON.stringify(h.local).includes(key('a')));
  assert((await h.send({kind:'status'},page)).ignored);
  assert((await h.send(payload(),{...page,url:'https://evil.example'})).ignored);
  assert((await h.send(payload(),{...page,id:'other-extension'})).ignored);
});
test('missing connection fails closed without queuing unbound actor reports',async()=>{
  const h=harness();const value=await h.send(payload());assert.equal(value.decision,'BLOCK');assert.equal((h.local.queue||[]).length,0);
});
test('offline queue contains metadata only and is bounded',async()=>{
  const h=harness();await h.send({kind:'connect',key:key('b')},own);h.setOffline(true);
  for(let i=0;i<101;i++)assert.equal((await h.send(payload(i))).decision,'BLOCK');
  assert.equal(h.local.queue.length,100);assert.equal(h.local.lost,1);
  assert(!JSON.stringify(h.local).includes('PRIVATE_CONTENT_SENTINEL'));assert(!JSON.stringify(h.local).includes(key('b')));
  h.setOffline(false);await h.send(payload(200));await pause();assert.equal(h.local.queue.length,95);
});
test('queued reports never move to a different key identity after reconnect',async()=>{
  const h=harness();await h.send({kind:'connect',key:key('c')},own);h.setOffline(true);await h.send(payload());h.setOffline(false);
  await h.send({kind:'connect',key:key('d')},own);await pause();
  assert.equal(h.local.queue.length,0);assert.equal(h.local.lost,1);
  assert(!h.requests.some(r=>r.body.operation==='offline'&&r.authorization==='Bearer '+key('d')));
});
