'use strict';
importScripts('core.js');
const ENDPOINT='http://127.0.0.1:8765/api/v1/browser/inspect';
const ready=chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
let serial=Promise.resolve();
async function api(payload){
  await ready;const {key}=await chrome.storage.session.get('key');if(!key)throw Error('NOT_CONNECTED');
  const fingerprint=await SedraCore.digest(key);
  try{
  const response=await fetch(ENDPOINT,{method:'POST',credentials:'omit',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(5000),headers:{'Authorization':'Bearer '+key,'Content-Type':'application/json'},body:JSON.stringify(payload)});
  if(!response.ok)throw Error('POLICY_SERVICE_'+response.status);
  const value=await response.json();if(!['ALLOW','BLOCK'].includes(value.decision)||value.request_id!==payload.request_id)throw Error('INVALID_POLICY_RESPONSE');
  return value;
  }catch{const error=Error('POLICY_SERVICE_UNAVAILABLE');error.keyFingerprint=fingerprint;throw error;}
}
async function queueFailure(host,fingerprint){
  if(!fingerprint)return;
  const {queue=[],lost=0}=await chrome.storage.local.get(['queue','lost']);
  const event={host,request_id:'br-offline-'+crypto.randomUUID(),operation:'offline',mode:'preview',text:'',files:[],failure:'BACKEND_UNAVAILABLE'};
  const overflow=Math.max(0,queue.length+1-100);await chrome.storage.local.set({queue:[...queue,{key_fingerprint:fingerprint,event}].slice(-100),lost:lost+overflow});
}
async function flush(){
  const {queue=[],lost=0}=await chrome.storage.local.get(['queue','lost']);if(!queue.length)return;
  const {key}=await chrome.storage.session.get('key');if(!key)return;const fingerprint=await SedraCore.digest(key);let discarded=0;
  const remaining=[...queue];
  for(const entry of queue.slice(0,5)){try{if(entry.key_fingerprint===fingerprint)await api(entry.event);else discarded++;remaining.shift();await chrome.storage.local.set({queue:remaining,lost:lost+discarded});}catch{break;}}
}
chrome.alarms.create('sedra-offline-alerts',{periodInMinutes:1});
chrome.alarms.onAlarm.addListener(a=>{if(a.name==='sedra-offline-alerts')serial=serial.then(flush).catch(()=>{});});
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
  if(sender.id!==chrome.runtime.id)return false;
  const ownOptions=sender.url===chrome.runtime.getURL('options.html')&&!sender.tab?.url?.startsWith('http');
  if(message?.kind==='connect'&&ownOptions){
    (async()=>{await ready;if(typeof message.key!=='string'||!/^sedra_k_[a-f0-9]{16}\.[A-Za-z0-9_-]{40,}$/.test(message.key))throw Error('INVALID_KEY');await chrome.storage.session.set({key:message.key});
      const check=await api({request_id:'br-connect-'+crypto.randomUUID(),host:'sedra-browser-lab',operation:'draft',mode:'preview',text:'Connection check',files:[]});
      serial=serial.then(flush).catch(()=>{});reply({connected:check.decision==='ALLOW'});})().catch(async()=>{await chrome.storage.session.remove('key');reply({error:'Connection failed. Check the bound browser key, local service and browser localhost permission.'});});return true;
  }
  if(message?.kind==='status'&&ownOptions){(async()=>{await ready;const {key}=await chrome.storage.session.get('key');const {queue=[],lost=0}=await chrome.storage.local.get(['queue','lost']);reply({connected:Boolean(key),queued:queue.length,lost});})();return true;}
  if(message?.kind==='disconnect'&&ownOptions){chrome.storage.session.remove('key').then(()=>reply({connected:false}));return true;}
  const host=SedraCore.destination(sender.url||'');
  if(message?.kind!=='inspect'||!host||!sender.tab)return false;
  const p=message.payload;
  if(!p||typeof p.text!=='string'||!Array.isArray(p.files)||p.files.length>2||!['paste','draft','send','file','drop'].includes(p.operation)||!['preview','release'].includes(p.mode))return false;
  const payload={request_id:p.request_id,host,operation:p.operation,mode:p.mode,text:p.text,files:p.files,...(p.failure?{failure:p.failure}:{})};
  serial=serial.then(async()=>{
    try{const value=await api(payload);reply(value);await flush();}
    catch(error){await queueFailure(host,error.keyFingerprint);reply({decision:'BLOCK',reason_codes:['POLICY_SERVICE_UNAVAILABLE'],local_only:true,request_id:p.request_id});}
  }).catch(()=>reply({decision:'BLOCK',local_only:true,reason_codes:['LOCAL_INSPECTION_FAILED']}));
  return true;
});
