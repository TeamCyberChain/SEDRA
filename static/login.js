(()=>{
'use strict';const $=id=>document.getElementById(id);let csrf=null;
async function api(path,body){const r=await fetch(path,{method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});const data=await r.json();if(!r.ok)throw Error(data.error||'Sign-in failed');return data;}
async function showMfa(){const c=await api('/api/account/context');csrf=c.csrf_token;if(!c.mfa.pending){$('password-stage').hidden=false;$('mfa-stage').hidden=true;return;}$('password-stage').hidden=true;$('mfa-stage').hidden=false;
 if(!c.mfa.enrolled){const e=await api('/api/account/mfa/enroll',{});$('mfa-enrollment').hidden=false;$('mfa-qr').src=e.qr_data_url;$('mfa-secret').textContent=e.secret;}else{$('mfa-enrollment').hidden=true;$('mfa-secret').textContent='';$('mfa-qr').removeAttribute('src');}
}
$('account-login').onsubmit=async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;$('login-status').textContent='';try{const c=await api('/api/account/context');csrf=c.csrf_token;const f=new FormData(e.target);await api('/api/account/login',{username:f.get('username'),password:f.get('password')});e.target.reset();await showMfa();}catch(e){$('login-status').textContent=e.message;}finally{b.disabled=false;}};
$('mfa-login').onsubmit=async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;$('login-status').textContent='';try{const r=await api('/api/account/mfa/verify',{code:new FormData(e.target).get('code')});e.target.reset();$('mfa-secret').textContent='';$('mfa-qr').removeAttribute('src');if(r.recovery_codes.length){$('mfa-stage').hidden=true;$('recovery-stage').hidden=false;$('mfa-recovery-codes').textContent=r.recovery_codes.join('\n');}else location.assign('/');}catch(e){$('login-status').textContent=e.message;}finally{b.disabled=false;}};
$('restart-signin').onclick=async()=>{try{const c=await api('/api/account/context');csrf=c.csrf_token;await api('/api/logout',{});location.reload();}catch(e){$('login-status').textContent=e.message;}};
$('save-recovery').onclick=()=>{const a=document.createElement('a'),url=URL.createObjectURL(new Blob(['SEDRA single-use recovery codes\nStore separately from your password.\n'+$('mfa-recovery-codes').textContent],{type:'text/plain'}));a.href=url;a.download='SEDRA-recovery-codes.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
$('finish-signin').onclick=()=>{$('mfa-recovery-codes').textContent='';location.assign('/');};
showMfa().catch(e=>{$('login-status').textContent=e.message;});
})();
