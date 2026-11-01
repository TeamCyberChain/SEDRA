(()=>{
'use strict';
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const permissionNames={'accounts.read':'View the user directory','accounts.create':'Create standard accounts','accounts.update':'Enable, disable and change standard account roles','accounts.reset_password':'Reset standard account passwords','accounts.reset_mfa':'Manage standard account authenticators'};
let context=null,admin=null,section='profile',userTab='creation',usersExpanded=true,auditPage=null,auditRows=[],busy=false,opener=null,revision=0;
const d=document.createElement('dialog');
d.className='settings-dialog';d.setAttribute('aria-label','Settings');
d.innerHTML=`<header class="settings-head"><div><span class="settings-overline">WORKSPACE</span><h2>Settings</h2></div><button type="button" id="settings-close" aria-label="Close settings">×</button></header><div class="settings-layout"><nav class="settings-nav" aria-label="Settings sections"><button data-setting="profile">Profile & account</button><button data-setting="appearance">Appearance</button><button data-setting="audit">Audit Logs</button><button data-setting="manage" aria-expanded="false" hidden>Users <span aria-hidden="true">⌄</span></button><div class="settings-subnav" id="settings-users-nav" hidden><button data-manage="creation">User Creation</button><button data-manage="management">User Management</button><button data-manage="roles">Roles</button></div></nav><section class="settings-content" id="settings-content" aria-live="polite"></section></div><p class="settings-status" id="settings-status" role="status"></p>`;
const content=d.querySelector('#settings-content'),note=d.querySelector('#settings-status');
const has=p=>(context?.account.permissions||[]).includes(p);
const isAdmin=()=>context?.account.access_profile==='administrator';
function notify(s='',error=false){note.textContent=s;note.dataset.error=String(error);}
function wipePasswords(){for(const p of d.querySelectorAll('input[type=password]'))p.value='';}
async function refreshContext(){
 const r=await fetch('/api/account/context');const value=await r.json();if(!r.ok)throw Error('Account context unavailable');context=value;
 d.querySelector('[data-setting=manage]').hidden=!context.account.can_manage_users;
 d.querySelector('[data-setting=audit]').hidden=context.enabled&&!['administrator','analyst'].includes(context.account.access_profile);
}
async function api(url,body){
 const r=await fetch(url,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-CSRF-Token':context.csrf_token}:{},body:body?JSON.stringify(body):undefined});
 const v=await r.json();if(!r.ok)throw Error(v.error||'Operation failed');return v;
}
function heading(title,description){return `<div class="settings-page-heading"><span class="settings-overline">${section==='manage'?'USERS':'SETTINGS'}</span><h3 tabindex="-1">${title}</h3><p>${description}</p></div>`;}
function profile(){
 const a=context.account;
 content.innerHTML=heading('Profile & account','Your current workspace identity and access.')+(context.enabled?`<div class="settings-profile"><div class="settings-avatar">${esc((a.username||'?').slice(0,2).toUpperCase())}</div><div><h4>${esc(a.username||'Signed out')}</h4><p>${esc(a.account_role||'No role')}</p></div></div><dl class="settings-properties"><dt>Access profile</dt><dd>${esc(a.access_profile||'None')}</dd><dt>MFA</dt><dd>${context.mfa?.enrolled?'Authenticator enabled · '+context.mfa.recovery_codes_remaining+' recovery codes remaining':'Enrollment required'}</dd><dt>UEBA identity</dt><dd>${esc(a.subject_id||'Administrative account')}</dd></dl>${a.username?'<div class="settings-actions"><button data-mfa-own>Change my MFA</button><button id="settings-signout">Sign out</button></div><div id="settings-mfa-own-panel"></div>':'<a href="/login">Sign in</a>'}`:context.bootstrap_allowed?`<p>Create the first Administrator to enable account-based sign-in. This invalidates existing demonstration sessions.</p><form id="settings-bootstrap"><label>Administrator username<input name="username" autocomplete="username" pattern="[A-Za-z][A-Za-z0-9_.-]{2,63}" required></label><label>Password · at least 12 characters<input name="password" type="password" minlength="12" maxlength="256" autocomplete="new-password" required></label><label>Confirm password<input name="confirm" type="password" minlength="12" maxlength="256" autocomplete="new-password" required></label><button class="settings-primary">Create Administrator & enable sign-in</button></form>`:'<p>Account setup requires the local Administrator workspace.</p>');
}
async function audit(older=false,render=true){
 const ticket=revision;
 if(!older&&render){auditRows=[];auditPage=null;content.innerHTML=heading('Audit Logs','Persisted API, interface and application event metadata.')+`<div class="settings-row"><label>Source<select id="settings-audit-source"><option value="">All sources</option><option>API</option><option>HTTP</option><option>UI</option><option>APPLICATION</option></select></label><button id="settings-audit-refresh">Refresh logs</button><button id="settings-audit-export">Export loaded</button></div><table class="settings-audit-table"><tbody id="settings-audit-rows"></tbody></table><button id="settings-audit-older" disabled>Load older records</button>`;}
 const source=d.querySelector('#settings-audit-source').value;
 const v=await api('/api/audit?limit=50&source='+source+(older&&auditPage?.next_before?'&before='+auditPage.next_before:''));
 if(section!=='audit'||ticket!==revision||!d.open)return;
 auditPage=v;auditRows=older?auditRows.concat(v.items):v.items;
 d.querySelector('#settings-audit-rows').innerHTML=auditRows.map(r=>`<tr><td>${esc(new Date(r.at*1000).toLocaleString())}<br><small>${esc(r.source)} · ${esc(r.actor)}</small></td><td>${esc(r.event)}<br><code>${esc(r.metadata.route||r.metadata.control||r.metadata.id||'')} ${esc(r.metadata.status||'')}</code><details><summary>Metadata</summary><pre>${esc(JSON.stringify(r.metadata,null,2))}</pre></details></td></tr>`).join('');
 d.querySelector('#settings-audit-older').disabled=!v.next_before;notify(v.write_failures_since_start?'Audit storage degraded':auditRows.length+' records loaded');
}
const rolePrivileged=r=>r.base==='administrator'||r.permissions.length>0;
function options(value){return admin.roles.filter(r=>isAdmin()||!rolePrivileged(r)).map(r=>`<option value="${esc(r.id)}" ${r.id===value?'selected':''}>${esc(r.name)}</option>`).join('');}
function subjects(){return '<option value="">No subject · administrative accounts</option>'+admin.subjects.map(s=>`<option value="${esc(s)}">${esc(s)}</option>`).join('');}
function permissionsFields(selected=[]){return `<fieldset class="settings-permissions"><legend>Account administration permissions</legend>${Object.entries(permissionNames).map(([p,name])=>`<label><input type="checkbox" name="permissions" value="${p}" ${selected.includes(p)?'checked':''}>${name}</label>`).join('')}<p>Delegation is available on Analyst profiles. Directory access is required for all account actions. Only Administrators can modify privileged accounts or role definitions.</p></fieldset>`;}
function roleDescription(r){return r.base==='administrator'?'Full security review, integrations, audit and account administration.':r.base==='analyst'?'Security review, integrations, endpoint controls and audit.':'Governed AI and transfers; UEBA is limited to the bound identity. No security audit or account administration.';}
function creation(){
 if(!has('accounts.create'))return heading('User Creation','Your role can view users but cannot create accounts.')+'<p>Ask an Administrator for the Create accounts permission.</p>';
 return heading('User Creation','Add an account and assign its role and behavior identity.')+`<form id="settings-user-create"><div class="settings-form-grid"><label>Username<input name="username" autocomplete="off" pattern="[A-Za-z][A-Za-z0-9_.-]{2,63}" maxlength="64" required></label><label>Initial password<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="256" required></label><label>Role<select name="role_id">${options('user')}</select></label><label>UEBA identity<select name="subject">${subjects()}</select></label></div><p class="settings-help">Use 12–256 characters. User profiles require a UEBA identity; administrative profiles do not. MFA enrollment is mandatory on the account’s first sign-in.</p><button class="settings-primary">Create user</button></form>`;
}
function manageable(u){const r=admin.roles.find(r=>r.id===u.role_id);return isAdmin()||(!rolePrivileged(r)&&u.id!==context.account.account_id);}
function management(){return heading('User Management','Review existing accounts, access roles and account status.')+`<label class="settings-search">Find a user<input id="settings-user-search" type="search" placeholder="Search by username" autocomplete="off"></label><div id="settings-user-list">${admin.users.map(u=>{
 const change=has('accounts.update')&&manageable(u),reset=has('accounts.reset_password')&&manageable(u);
 return `<article class="settings-record" data-account="${esc(u.id)}" data-username="${esc(u.username)}"><div class="settings-record-head"><div><h4>${esc(u.username)}</h4><p>${esc(u.role_name)} · ${esc(u.subject||'Administrative account')} · MFA ${u.mfa_enrolled?'enabled · '+u.recovery_codes_remaining+' recovery codes remaining':'enrollment required'}</p></div><span class="settings-badge ${u.active?'':'disabled'}">${u.active?'Active':'Disabled'}</span></div>${change?`<div class="settings-form-grid"><label>Role<select data-user-role>${options(u.role_id)}</select></label><label>UEBA identity<select data-user-subject>${subjects()}</select></label></div>`:''}<div class="settings-actions">${change?`<button data-save-user="${esc(u.id)}" data-active="${u.active}">Save changes</button><button data-toggle-user="${esc(u.id)}" data-active="${u.active}">${u.active?'Disable account':'Enable account'}</button>`:''}${reset?`<button data-reset-user="${esc(u.id)}">Reset password</button>`:''}${!change&&!reset?'<small>Read-only access</small>':''}</div>${mfaControls(u)}<div data-reset-panel hidden></div></article>`;
 }).join('')}</div><p id="settings-user-empty" hidden>No matching accounts.</p>`;}

function mfaControls(u){
 if(u.id===context.account.account_id)return '<div class="settings-mfa-line"><span>Authenticator</span><button data-own-mfa>Change my MFA</button></div>';
 if(!has('accounts.reset_mfa')||!manageable(u))return '';
 return `<div class="settings-mfa-line"><span>Authenticator</span><div class="settings-actions">${u.mfa_enrolled?`<button data-mfa-user="${esc(u.id)}" data-mfa-action="replace">Change MFA</button><button class="settings-danger" data-mfa-user="${esc(u.id)}" data-mfa-action="remove">Remove MFA</button>`:`<button data-mfa-user="${esc(u.id)}" data-mfa-action="enroll">Add MFA</button>`}</div></div><div data-mfa-panel></div>`;
}
function ownMfa(){
 const panel=d.querySelector('#settings-mfa-own-panel');
 panel.innerHTML=`<form id="settings-mfa-replace-start" class="settings-security-form"><h4>Change your authenticator</h4><p>Your current authenticator stays active until the new one is verified. Other sessions and old recovery codes will then be revoked. Use a fresh, unused code.</p><label>Your current password<input name="password" type="password" autocomplete="current-password" required maxlength="256"></label><label>Current authenticator or recovery code<input name="code" type="password" autocomplete="one-time-code" required minlength="6" maxlength="64"></label><button class="settings-primary">Verify identity & set up replacement</button></form>`;
}
function showMfaManagement(b){
 const u=admin.users.find(u=>u.id===b.dataset.mfaUser);if(!u)return;
 const action=b.dataset.mfaAction,panel=b.closest('[data-account]').querySelector('[data-mfa-panel]');
 wipePasswords();panel.innerHTML=`<form class="settings-mfa-manage settings-security-form" data-user="${esc(u.id)}" data-version="${u.auth_version}" data-action="${esc(action)}"><h4>${action==='enroll'?'Add MFA':action==='remove'?'Remove authenticator':'Change authenticator'} · ${esc(u.username)}</h4><p>${action==='enroll'?'The account owner must sign in and scan their own setup QR. No seed is assigned or exposed to the operator.':'The registered authenticator and recovery codes will be retired. The account owner must enroll a new authenticator on their next sign-in.'} All account sessions will be revoked. MFA remains mandatory.</p><label>Reason<select name="reason"><option value="${action==='enroll'?'enrollment_requested':'device_replaced'}">${action==='enroll'?'Enrollment requested':'Device replaced'}</option><option value="device_lost">Device lost</option><option value="access_recovery">Verified access recovery</option></select></label><label>Your operator password · ${esc(context.account.username)}<input name="password" type="password" autocomplete="current-password" required maxlength="256"></label><label>Your fresh authenticator or recovery code<input name="code" type="password" autocomplete="one-time-code" required minlength="6" maxlength="64"></label><p class="settings-help">Use a code that has not already been used to sign in. The target’s password is not requested here.</p><button class="${action==='remove'?'settings-danger':'settings-primary'}">${action==='enroll'?'Require owner enrollment':action==='remove'?'Remove authenticator & revoke sessions':'Require new authenticator & revoke sessions'}</button></form>`;
}

function roles(){return heading('Roles','Access profiles define workspace capabilities; account permissions control delegated administration.')+(context.account.can_manage_roles?`<form id="settings-role-create"><div class="settings-form-grid"><label>Role name<input name="name" maxlength="50" pattern="[A-Za-z][A-Za-z0-9 _-]{1,49}" required></label><label>Access profile<select name="base"><option value="user">User</option><option value="analyst">Analyst</option><option value="administrator">Administrator</option></select></label></div>${permissionsFields()}<button class="settings-primary">Create role</button></form>`:'<p>Your role can inspect capabilities. Only Administrators can define or change roles.</p>')+admin.roles.map(r=>`<article class="settings-record"><div class="settings-record-head"><h4>${esc(r.name)}</h4><span class="settings-badge">${esc(r.base)}${r.builtin?' · Built-in':''}</span></div><p>${roleDescription(r)}</p><ul class="settings-capabilities">${r.base==='administrator'?'<li>All account actions and role administration</li>':r.permissions.length?r.permissions.map(p=>`<li>${esc(permissionNames[p]||p)}</li>`).join(''):'<li>No delegated account permissions</li>'}</ul>${context.account.can_manage_roles&&!r.builtin?`<details><summary>Edit role permissions</summary><form class="settings-role-edit" data-role="${esc(r.id)}"><label>Role name<input name="name" value="${esc(r.name)}" maxlength="50" required></label>${permissionsFields(r.permissions)}<button>Save role permissions</button></form></details>`:''}</article>`).join('');}
async function manage(tab=userTab){
 const ticket=revision;userTab=tab;
 d.querySelectorAll('[data-manage]').forEach(b=>b.setAttribute('aria-current',String(b.dataset.manage===tab)));
 const value=await api('/api/accounts');if(section!=='manage'||ticket!==revision||!d.open)return;admin=value;
 // Older server versions have no permission catalog; show a clear update error, not unsafe controls.
 if(admin.roles.some(r=>!Array.isArray(r.permissions)))throw Error('Server update required. Restart SEDRA to load account permissions.');
 content.innerHTML=tab==='roles'?roles():tab==='management'?management():creation();
 if(tab==='management')for(const u of admin.users){const select=content.querySelector(`[data-account="${u.id}"] [data-user-subject]`);if(select)select.value=u.subject||'';}
}
async function show(value){
 wipePasswords();revision++;if(value==='manage'&&section!=='manage')usersExpanded=true;section=value;notify();
 if(section==='manage'&&!context.account.can_manage_users)section='profile';
 if(section==='audit'&&context.enabled&&!['administrator','analyst'].includes(context.account.access_profile))section='profile';
 d.querySelectorAll('[data-setting]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.setting===section)));
 d.querySelector('[data-setting=manage]').setAttribute('aria-expanded',String(section==='manage'&&usersExpanded));
 d.querySelector('#settings-users-nav').hidden=section!=='manage'||!usersExpanded;
 if(section==='profile')profile();
 if(section==='appearance')content.innerHTML=heading('Appearance','A consistent color scheme across every SEDRA workspace.')+`<div class="settings-theme-options"><button data-theme-choice="light" aria-pressed="${document.documentElement.dataset.theme!=='dark'}"><span class="settings-theme-preview light"><i></i><i></i></span><b>Light</b><small>Clear, neutral surfaces</small></button><button data-theme-choice="dark" aria-pressed="${document.documentElement.dataset.theme==='dark'}"><span class="settings-theme-preview dark"><i></i><i></i></span><b>Dark</b><small>Graphite surfaces, teal accents</small></button></div>`;
 if(section==='audit')await audit();
 if(section==='manage')await manage();
 content.scrollTop=0;
}
function position(){
 if(!opener||!d.open)return;const r=opener.getBoundingClientRect();const wide=innerWidth>760&&r.right<innerWidth*.45;
 d.dataset.dock=wide?'sidebar':'mobile';
 if(wide){const left=Math.round(r.right+12),width=Math.min(920,innerWidth-left-16);d.style.left=left+'px';d.style.width=width+'px';d.style.bottom=Math.max(16,innerHeight-r.bottom)+'px';}
 else{d.style.left='12px';d.style.width='calc(100vw - 24px)';d.style.bottom='12px';}
}
async function open(value='profile',source){
 if(d.open&&source){close();return;}opener=source||document.querySelector('.settings-open');
 try{await refreshContext();if(!d.open)d.show();position();opener?.setAttribute('aria-expanded','true');await show(value);d.querySelector('#settings-close').focus();}catch(e){notify(e.message,true);}
}
function clear(){revision++;wipePasswords();content.replaceChildren();auditRows=[];admin=null;context=null;opener?.setAttribute('aria-expanded','false');}
function close(){if(busy){notify('Wait for the current account operation to finish.');return;}d.close();opener?.focus();}
d.addEventListener('close',clear);
document.addEventListener('keydown',e=>{if(d.open&&e.key==='Escape'){e.preventDefault();close();}});
document.addEventListener('pointerdown',e=>{if(d.open&&!busy&&!d.contains(e.target)&&!e.target.closest('.settings-open'))close();});
addEventListener('resize',position);addEventListener('sedra-sidebar-change',()=>{if(d.open){if(document.documentElement.dataset.nav==='collapsed')close();else position();}});
d.addEventListener('input',e=>{if(e.target.id==='settings-user-search'){const q=e.target.value.toLowerCase();let count=0;for(const row of content.querySelectorAll('[data-username]')){row.hidden=!row.dataset.username.includes(q);if(!row.hidden)count++;}d.querySelector('#settings-user-empty').hidden=count>0;}});
d.addEventListener('change',e=>{if(e.target.id==='settings-audit-source')void audit(false,false).catch(e=>notify(e.message,true));});
d.addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b||busy)return;
 try{
  if(b.id==='settings-close'){close();return;}
  if(b.dataset.setting){if(b.dataset.setting==='manage'&&section==='manage'){usersExpanded=!usersExpanded;d.querySelector('#settings-users-nav').hidden=!usersExpanded;b.setAttribute('aria-expanded',String(usersExpanded));return;}await show(b.dataset.setting);return;}
  if(b.dataset.manage){wipePasswords();revision++;notify();await manage(b.dataset.manage);return;}
  if(b.dataset.themeChoice){window.SedraTheme?.set(b.dataset.themeChoice);d.querySelectorAll('[data-theme-choice]').forEach(n=>n.setAttribute('aria-pressed',String(n===b)));notify('Appearance saved.');return;}
  if(b.hasAttribute('data-mfa-own')){ownMfa();return;}
  if(b.hasAttribute('data-own-mfa')){await show('profile');ownMfa();return;}
  if(b.dataset.mfaUser){showMfaManagement(b);return;}
  if(b.id==='settings-mfa-download'){const url=URL.createObjectURL(new Blob(['SEDRA single-use recovery codes. Store separately from your password.\n'+d.querySelector('#settings-new-recovery').textContent],{type:'text/plain'})),a=document.createElement('a');a.href=url;a.download='SEDRA-recovery-codes.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return;}
  if(b.id==='settings-mfa-finish'){profile();return;}
  if(b.id==='settings-signout'){await api('/api/logout',{});location.assign('/login');return;}
  if(b.id==='settings-audit-refresh'){await audit(false,false);return;}
  if(b.id==='settings-audit-older'){await audit(true);return;}
  if(b.id==='settings-audit-export'){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify({scope:auditPage?.scope,items:auditRows},null,2)],{type:'application/json'}));a.download='SEDRA-audit.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);return;}
  if(b.dataset.resetUser){const panel=b.closest('[data-account]').querySelector('[data-reset-panel]');wipePasswords();panel.hidden=!panel.hidden;panel.innerHTML=panel.hidden?'':`<form class="settings-password-reset" data-user="${esc(b.dataset.resetUser)}"><p>Resetting the password signs this account out of all current sessions. Independent integration keys remain unchanged.</p><label>New password<input name="password" type="password" minlength="12" maxlength="256" autocomplete="new-password" required></label><label>Confirm new password<input name="confirm" type="password" minlength="12" maxlength="256" autocomplete="new-password" required></label><button class="settings-primary">Reset password & sign out sessions</button></form>`;return;}
  if(b.dataset.saveUser||b.dataset.toggleUser){
   const row=b.closest('[data-account]');busy=true;
   await api('/api/accounts/users',{action:'update',id:row.dataset.account,role_id:row.querySelector('[data-user-role]').value,subject:row.querySelector('[data-user-subject]').value,active:b.dataset.toggleUser?b.dataset.active!=='1':b.dataset.active==='1'});
   await refreshContext();if(!context.account.can_manage_users){await show('profile');return;}await manage('management');notify('Account updated. Disabled sessions cannot be restored by re-enabling the account.');
  }
 }catch(e){notify(e.message,true);}finally{busy=false;}
});
d.addEventListener('submit',async e=>{
 e.preventDefault();if(busy)return;busy=true;const f=e.target,b=e.submitter||f.querySelector('button');b.disabled=true;
 try{
  const data=Object.fromEntries(new FormData(f));
  if(f.classList.contains('settings-mfa-manage')){
   await api('/api/accounts/mfa',{id:f.dataset.user,expected_version:Number(f.dataset.version),action:f.dataset.action,...data});
   wipePasswords();await manage('management');notify('Authenticator registration updated. Previous sessions are revoked; owner enrollment is required.');
  }
  if(f.id==='settings-mfa-replace-start'){
   const setup=await api('/api/account/mfa/replace/start',data);wipePasswords();
   d.querySelector('#settings-mfa-own-panel').innerHTML=`<section class="settings-security-form" data-sensitive="true"><h4>Set up your new authenticator</h4><p>Scan with your new device and confirm its six-digit code within five minutes. Closing this screen keeps your current authenticator active.</p><img class="settings-mfa-qr" src="${esc(setup.qr_data_url)}" alt="Private replacement authenticator setup QR" width="200" height="200"><code class="settings-mfa-key">${esc(setup.secret)}</code><form id="settings-mfa-replace-confirm"><label>New authenticator code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required maxlength="6"></label><button class="settings-primary">Confirm new authenticator</button></form></section>`;
  }
  if(f.id==='settings-mfa-replace-confirm'){
   const result=await api('/api/account/mfa/replace/confirm',data);wipePasswords();await refreshContext();profile();
   d.querySelector('#settings-mfa-own-panel').innerHTML=`<section class="settings-security-form" data-sensitive="true"><h4>New authenticator enabled</h4><p>Your old authenticator, recovery codes and other sessions are revoked. Save these new one-use recovery codes separately from your password; they will not be shown again.</p><pre id="settings-new-recovery">${esc(result.recovery_codes.join('\n'))}</pre><div class="settings-actions"><button id="settings-mfa-download">Download recovery codes</button><button id="settings-mfa-finish">Done</button></div></section>`;
   notify('Authenticator replaced successfully.');if(typeof loadState==='function')void loadState({silent:true});
  }
  if(f.id==='settings-bootstrap'){if(data.password!==data.confirm)throw Error('Passwords must match');await api('/api/account/bootstrap',{username:data.username,password:data.password,role_id:'administrator',subject:''});f.reset();location.assign('/login');}
  if(f.id==='settings-user-create'){await api('/api/accounts/users',data);f.reset();await manage('management');notify('User created.');}
  if(f.id==='settings-role-create'||f.classList.contains('settings-role-edit')){
   delete data.permissions;data.permissions=new FormData(f).getAll('permissions');
   if(f.dataset.role){data.action='update';data.id=f.dataset.role;}
   await api('/api/accounts/roles',data);await manage('roles');notify('Role saved. Permissions apply to existing sessions on their next request.');
  }
  if(f.classList.contains('settings-password-reset')){if(data.password!==data.confirm)throw Error('Passwords must match');await api('/api/accounts/password',{id:f.dataset.user,password:data.password});wipePasswords();await refreshContext();if(!context.account.username){await show('profile');notify('Password reset. Sign in with the new password.');}else{await manage('management');notify('Password reset. Previous sessions have been revoked.');}}
 }catch(e){notify(e.message,true);}finally{for(const p of f.querySelectorAll('input[type=password]'))p.value='';b.disabled=false;busy=false;}
});
document.body.append(d);
let buttons=[...document.querySelectorAll('.settings-open')];
if(!buttons.length){const b=document.createElement('button');b.className='settings-open settings-floating';b.textContent='Settings';document.body.append(b);buttons=[b];}
buttons.forEach(b=>{b.setAttribute('aria-haspopup','dialog');b.setAttribute('aria-expanded','false');b.onclick=()=>open('profile',b);});
window.SedraSettings={open};
setInterval(async()=>{if(!d.open||busy)return;try{const before=JSON.stringify(context?.account);await refreshContext();if(before!==JSON.stringify(context.account))await show(section);}catch{}},8000);
if(location.hash==='#audit'){if(typeof changeTab==='function')changeTab('overview',false);history.replaceState(null,'','/#overview');void open('audit');}
})();
