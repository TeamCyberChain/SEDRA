/* Explicit localhost DOM test transport. This is not an installed extension. */
'use strict';
const harnessSession=fetch('/api/state',{cache:'no-store'}).then(async r=>{if(!r.ok)throw Error('Analyst lab session required');const v=await r.json();if(v.session.role!=='analyst')throw Error('Analyst lab session required');return v.session.csrf_token;});
async function SedraHarnessTransport(message){
  if(location.origin!=='http://127.0.0.1:8765'||location.pathname!=='/browser-harness'||message?.kind!=='inspect')throw Error('Local test transport only');
  const csrf=await harnessSession,payload={...message.payload,host:'sedra-browser-lab'};
  const r=await fetch('/api/browser-lab/inspect',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(payload)});
  if(!r.ok)throw Error('Local policy check failed');return r.json();
}
