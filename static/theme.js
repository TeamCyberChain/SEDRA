/* Preference only; never store identity, tokens or submitted content. */
(()=>{'use strict';const root=document.documentElement;let preference;
try{preference=localStorage.getItem('sedra-theme');}catch{}
const media=matchMedia('(prefers-color-scheme: dark)');
function apply(value){root.dataset.theme=value==='dark'?'dark':'light';document.querySelectorAll('.theme-toggle').forEach(b=>{b.textContent=root.dataset.theme==='dark'?'Light mode':'Dark mode';b.setAttribute('aria-pressed',String(root.dataset.theme==='dark'));});}
apply(preference|| (media.matches?'dark':'light'));
addEventListener('storage',e=>{if(e.key==='sedra-theme'){preference=e.newValue;apply(preference||(media.matches?'dark':'light'));}});
media.addEventListener('change',e=>{if(!preference)apply(e.matches?'dark':'light');});
let csrf=null,queue=[],sending=false;
async function report(event,control){
 if(queue.length>=20)return;queue.push({event,control});if(sending)return;sending=true;
 try{while(queue.length){const body=queue.shift();try{
 if(!csrf){const r=await fetch('/api/audit/context');if(!r.ok)continue;csrf=(await r.json()).csrf_token;}
 const r=await fetch('/api/audit/ui',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});if(r.status===403)csrf=null;
 }catch{csrf=null;}}}finally{sending=false;}
}
document.addEventListener('DOMContentLoaded',()=>{
 window.SedraTheme={set(value){preference=value==='dark'?'dark':'light';try{localStorage.setItem('sedra-theme',preference);}catch{}apply(preference);report('theme_'+preference,'other');}};
 document.addEventListener('change',e=>{if(e.target.matches('select,input[type=checkbox],input[type=radio]'))report('selection',/identity/.test(e.target.id)?'identity':/filter|source|audit-event/.test(e.target.id)?'filter':'other');},true);
 document.addEventListener('submit',()=>report('control','submit'),true);
 report('page_open',location.pathname==='/portal'?'portal':'other');
 document.addEventListener('click',e=>{const node=e.target.closest('button,a');if(!node)return;
 const href=node.getAttribute('href')||'';const tab=node.dataset.tab||node.dataset.go||(href==='/portal'?'portal':href==='/integrations'?'integrations':/^\/#(overview|alerts|investigation|inventory|transfers|integrations|audit)$/.test(href)?href.slice(2):null);if(tab){report('navigation',tab==='lab'?'transfers':tab);return;}
 const id=node.id||'';let control=/refresh/.test(id)?'refresh':/revoke/.test(id)||node.dataset.revoke?'revoke':/send/.test(id)?'submit':/document/.test(id)?'document':/endpoint/.test(id)?'endpoint':node.hasAttribute('data-alert-action')?'review':/configure/.test(id)?'configure':'other';
 report('control',control);
 },true);
});
addEventListener('unhandledrejection',()=>report('client_error','other'));
addEventListener('error',()=>report('client_error','other'));
})();
