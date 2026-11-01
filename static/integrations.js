'use strict';
(() => {
  const el=id=>document.getElementById(id);
  let sessionEpoch=null,running=false,submitting=false,secretTimer;
  function status(message){el('integration-status').textContent=message;}
  function clearSecret(){clearTimeout(secretTimer);el('issued-key').textContent='';el('issued-key').hidden=true;}
  function sync(){
    const epoch=state?.session?.csrf_token;
    if(epoch!==sessionEpoch){sessionEpoch=epoch;clearSecret();el('key-list').replaceChildren();}
    el('key-form').querySelectorAll('input,button').forEach(node=>node.disabled=!isAnalyst()||submitting);
    if(!isAnalyst())status('Analyst access is required to manage credentials.');
  }
  async function refresh(){
    if(running||!state)return;
    sync();if(!isAnalyst())return;
    running=true;const epoch=sessionEpoch;
    try{
      const result=await api('/api/integrations/keys');if(epoch!==sessionEpoch)return;
      document.querySelector('[data-sso-login]').hidden=!result.sso_enabled;
      status(result.accounts_enabled?'Account sign-in enforced. Manage users and roles in Settings.':result.sso_enabled?'Single sign-on enforced. Identity is supplied by the configured provider.':'Workspace identities enabled. Configure OIDC before deploying to an organization.');
      el('key-list').innerHTML=result.keys.length?result.keys.map(key=>`<article class="credential"><div><strong>${esc(key.name)}</strong><span class="credential-state ${key.revoked?'revoked':''}">${key.revoked?'Revoked':key.expires*1000<Date.now()?'Expired':'Active'}</span></div><p>${esc(key.scopes.join(' · '))}</p><small>${key.subjects.length?'Users: '+esc(key.subjects.join(', '))+' · ':''}Expires ${esc(dateTime(key.expires))}</small><button class="text-button" data-revoke="${esc(key.id)}" ${key.revoked?'disabled':''}>Revoke</button></article>`).join(''):'<div class="empty-state">No API credentials have been issued.</div>';
    }catch(error){status(error.message);}finally{running=false;}
  }
  el('key-form').addEventListener('submit',async event=>{
    event.preventDefault();if(!isAnalyst()||submitting)return;submitting=true;
    const button=event.submitter,epoch=sessionEpoch;button.disabled=true;clearSecret();
    try{
      const subjects=el('key-subjects').value.split(',').map(value=>value.trim().replace(/^user[ -]?(\d+)$/i,(_,n)=>'lab-'+n.padStart(3,'0'))).filter(Boolean);
      const result=await api('/api/integrations/keys',{name:el('key-name').value,ttl_hours:Number(el('key-ttl').value),scopes:[...el('key-form').querySelectorAll('[name=scope]:checked')].map(node=>node.value),subjects});
      if(epoch!==sessionEpoch)return;
      el('issued-key').textContent=result.token;el('issued-key').hidden=false;secretTimer=setTimeout(clearSecret,60000);await refresh();
    }catch(error){status(error.message);}finally{submitting=false;sync();}
  });
  el('key-list').addEventListener('click',async event=>{
    const button=event.target.closest('[data-revoke]');if(!button||!isAnalyst())return;
    button.disabled=true;
    try{await api('/api/integrations/keys',{action:'revoke',id:button.dataset.revoke});clearSecret();await refresh();}
    catch(error){status(error.message);button.disabled=false;}
  });
  el('refresh-integrations').onclick=refresh;
  el('sso-logout').onclick=async()=>{try{await api('/api/logout',{});clearSecret();location.assign('/');}catch(error){status(error.message);}};
  window.SedraIntegrations={refresh,sync};
})();
