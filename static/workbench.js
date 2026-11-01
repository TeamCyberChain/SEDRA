'use strict';
const UEBA_SECTIONS={summary:'Summary',cases:'Cases',signals:'Detection logic',activity:'Activity & sources',endpoint:'Endpoint',models:'Models & baselines',coverage:'Coverage'};
function uebaPaneHTML(s,part){
 const t=document.createElement('template');t.innerHTML=uebaInvestigationHTML(s);
 const html=selector=>[...t.content.querySelectorAll(selector)].map(n=>n.outerHTML).join('');
 if(part==='signals'){
  for(const rule of t.content.querySelectorAll('.ueba-rules .ueba-rule')){
   const details=document.createElement('details'),summary=document.createElement('summary');
   details.className=rule.className;details.open=rule.classList.contains('active');
   summary.innerHTML=rule.firstElementChild.innerHTML;details.append(summary);
   for(const child of [...rule.children].slice(1))details.append(child);
   rule.replaceWith(details);
  }
  return html('.ueba-rules');
 }
 if(part==='endpoint')return html('.endpoint-panel')||'<div class="panel workspace-empty">No endpoint identity is mapped to this subject.</div>';
 if(part==='coverage')return html('.ueba-coverage');
 if(part==='activity'){
  const chart=t.content.querySelector('.ueba-charts')?.children[1];
  return (chart?.outerHTML||'')+html('.ueba-timeline');
 }
 const profile=t.content.querySelector('.ueba-profile');
 if(part==='models'){
  profile?.querySelectorAll('.ueba-summary-grid,.ueba-impact').forEach(n=>n.remove());
  if(profile?.querySelector('h2'))profile.querySelector('h2').textContent='Model eligibility and baseline support';
  const trend=t.content.querySelector('.ueba-charts')?.children[0];return (profile?.outerHTML||'')+(trend?.outerHTML||'')+html('.ueba-evaluation');
 }
 profile?.querySelectorAll('.ueba-baseline-grid,.ueba-freshness').forEach(n=>n.remove());
 const rules=[...(s.live_context?.rules||[]),...(s.endpoint_context?.rules||[])].filter(r=>r.active);
 return (profile?.outerHTML||'')+`<section class="panel workspace-brief"><h2>What needs attention</h2>${rules.length?rules.map(r=>`<div class="brief-row"><span>${esc(r.title)}</span><b>${r.score}/100</b></div>`).join(''):'<p>No active live rule. Source coverage and baseline support must still be reviewed.</p>'}<p class="scope-note">${esc(s.model_context?.note||'')} Current rules are triage signals; they do not establish employee intent.</p></section>`;
}

(()=>{
 let epoch=null,data=null,activeReport=null,list=[],tab='executive',days=7,template='executive',subject='',busy=false,fetching=false,last=0,queued=null;
 const $=id=>document.getElementById(id),safe=esc;
 const named={executive:'Executive overview',protection:'Data protection',behavior:'Behavior & review',coverage:'Source coverage'};
 function n(v){return Number(v||0).toLocaleString('en');}
 function card(label,value,note){return `<article class="dashboard-card"><span>${safe(label)}</span><strong>${safe(value)}</strong><p>${safe(note)}</p></article>`;}
 function bars(rows,key,label){const max=Math.max(1,...rows.map(r=>r[key]));return rows.length?rows.map(r=>`<div class="dashboard-bar"><div><span>${safe(label(r))}</span><b>${n(r[key])}</b></div><i style="--bar:${100*r[key]/max}%"></i></div>`).join(''):'<p class="scope-note">No recorded activity in this view.</p>';}
 function trail(){return '<p class="workspace-definition">Operational records only. Blocked attempts are not confirmed breaches or measured financial losses. Historical model benchmarks are excluded.</p>';}
 function renderDash(){
  const root=$('dashboards-content');if(!data){root.innerHTML='<div class="panel workspace-empty">Loading recorded operations…</div>';return;}
  $('dashboard-period').value=String(data.window.days);
  const m=data.metrics,c=data.cases;
  let body='';
  if(tab==='executive')body=`<div class="dashboard-kpis">${card('Transfer attempts',n(m.attempts),'Recorded in the selected period')}${card('Stopped by policy',n(m.blocked),'Attempts, not confirmed breaches')}${card('Confirmed deliveries',n(m.confirmed),'Matching result observed by the gateway')}${card('Unconfirmed deliveries',n(m.unconfirmed),'Needs reconciliation; do not retry blindly')}${card('Active identities',n(m.active_identities),'Identities with recorded attempts')}${card('High-priority identities',n(m.high_priority_identities),'Current observed rules; analyst review required')}</div><div class="dashboard-grid"><section class="panel workspace-brief"><h2>Recorded activity by day</h2>${bars(data.trend,'attempts',r=>r.day)}<p class="scope-note">AZT (UTC+04). Only days with records are shown; this does not establish continuous collection.</p></section><section class="panel workspace-brief"><h2>Leadership actions</h2>${data.recommended_actions.map((a,i)=>`<div class="leader-action"><b>${i+1}</b><p>${safe(a)}</p></div>`).join('')}<div class="brief-row"><span>Current unreviewed cases</span><b>${n(c.open)}</b></div><p class="scope-note">Case status is independent of the request date filter and signal expiry.</p></section></div>`;
  if(tab==='protection')body=`<div class="dashboard-kpis">${card('Policy blocks',n(m.blocked),'Recorded gateway decisions')}${card('Registered sources',n(m.registered_sources),'Shared synthetic registered corpus')}${card('Document accesses',n(m.document_accesses),'This application endpoint only')}${card('Other delivery states',n(m.other_states),'Reservations, expiry or other retained states')}</div><div class="dashboard-grid"><section class="panel workspace-brief"><h2>Sensitive-pattern detections</h2>${bars(data.detectors,'count',r=>r.name.replace(/_/g,' '))}<p class="scope-note">One request may contain several detector types. Values are masked.</p></section><section class="panel workspace-brief"><h2>Destinations</h2>${bars(data.routes,'attempts',r=>r.route)}<h3>Classification snapshots</h3>${bars(data.classifications,'count',r=>r.name)}</section></div>`;
  if(tab==='behavior')body=`<div class="dashboard-kpis">${card('High live priority',n(m.high_priority_identities),'Observed live rules only')}${card('Awaiting review',n(c.open),'Current retained case status')}${card('In review',n(c.in_review),'Acknowledged by an analyst')}${card('Resolved',n(c.resolved),'Disposition recorded; source evidence retained')}</div><section class="panel workspace-brief"><h2>Current review priorities</h2>${data.high_priority.length?data.high_priority.map(s=>`<div class="brief-row"><button class="text-button" data-investigate="${safe(s.subject_id)}">${safe(s.subject_id)}</button><span>${safe(s.active_rules.join(' · '))}</span><b>${n(s.live_priority)}/100</b></div>`).join(''):'<p>No identity currently has a qualifying high-priority live rule.</p>'}<p class="scope-note">Current state can differ from peak captured evidence. Scores are not maliciousness probabilities.</p></section>`;
  if(tab==='coverage')body=`<div class="coverage-cards">${data.coverage.map(c=>`<section class="panel workspace-brief"><span class="workspace-overline">${safe(c.name)}</span><h2>${safe(c.state)}</h2><p>${safe(c.note)}</p></section>`).join('')}</div><section class="panel workspace-brief"><h2>How to read these dashboards</h2>${data.definitions.map(d=>`<p>${safe(d)}</p>`).join('')}</section>`;
  root.innerHTML=`${trail()}<div class="workspace-tabs">${Object.entries(named).map(([k,v])=>`<button data-dashboard="${k}" aria-selected="${tab===k}">${v}</button>`).join('')}</div>${body}<p class="scope-note">Snapshot ${safe(dateTime(data.generated_at))}. Detail rows ${n(data.data_quality.detail_rows)} / ${n(m.attempts)}${data.data_quality.detail_truncated?' · breakdowns are bounded; totals remain complete':''}.</p>`;
 }
 function reportPreview(r){const m=r.snapshot.metrics;return `<section class="panel workspace-brief report-preview"><span class="workspace-overline">SAVED SNAPSHOT</span><h2>${safe(r.title)}</h2><p>${safe(r.snapshot.scope.label)} · ${r.snapshot.window.days} day(s) · ${safe(dateTime(r.snapshot.generated_at))}</p><div class="dashboard-kpis">${card('Attempts',n(m.attempts),'Selected period')}${card('Blocked',n(m.blocked),'Policy decisions')}${card('Unconfirmed',n(m.unconfirmed),'Reconciliation required')}</div><div class="workspace-downloads"><a class="button primary" href="/api/reports?id=${r.id}&format=pdf" target="_blank" rel="noopener">Open PDF</a><a class="button secondary" href="/api/reports?id=${r.id}&format=csv" download="SEDRA-${r.id}.csv">Download CSV</a><a class="button secondary" href="/api/reports?id=${r.id}&format=json" download="SEDRA-${r.id}.json">Download JSON</a></div><p class="scope-note report-digest">Snapshot SHA-256 ${safe(r.sha256)}</p><p class="scope-note">Generated reports retain their original figures. Refreshing dashboards does not rewrite saved reports.</p></section>`;}
 function renderReports(){
  const analyst=isAnalyst();if(!analyst)template='activity';
  $('reports-content').innerHTML=`<section class="panel workspace-brief"><h2>Create a report</h2><p>Save an evidence-based snapshot and export it for review.</p><form id="report-form" class="workspace-report-form"><label>Report template<select id="report-template">${(analyst?['executive','security','activity']:['activity']).map(k=>`<option value="${k}" ${k===template?'selected':''}>${({executive:'Executive security brief',security:'Security operations report',activity:'Activity and delivery report'})[k]}</option>`).join('')}</select></label><label>Period<select id="report-days">${[1,7,30].map(d=>`<option value="${d}" ${d===days?'selected':''}>${d===1?'Last 24 hours':'Last '+d+' days'}</option>`).join('')}</select></label><label>Identity scope<select id="report-subject">${analyst?'<option value="">All authorized identities</option>':''}${analysisSubjects().map(s=>`<option value="${safe(s.subject_id)}" ${(subject||state.session.subject_id)===s.subject_id?'selected':''}>${safe(s.subject_id)}</option>`).join('')}</select></label><button class="button primary" ${busy?'disabled':''}>${busy?'Generating report…':'Generate report'}</button></form><p id="report-status" role="status"></p></section>${activeReport?reportPreview(activeReport):''}<section class="panel workspace-brief"><div class="report-list-heading"><h2>Saved reports</h2><button id="refresh-reports" class="button secondary">Refresh list</button></div>${list.length?`<div class="table-scroll"><table><thead><tr><th>Created</th><th>Template / scope</th><th>Open</th></tr></thead><tbody>${list.map(r=>`<tr><td>${safe(dateTime(r.created))}</td><td>${safe(r.template)}<small>${safe(r.subject||'All authorized identities')}</small></td><td><button class="text-button" data-report="${r.id}">View report</button></td></tr>`).join('')}</tbody></table></div>`:'<p>No report snapshots in your current authorized scope.</p>'}<p class="scope-note">Latest 100 authorized snapshots. Reports persist across activity reset. Raw prompts, credentials and Windows packets are excluded.</p></section>`;
 }
 async function open(which,force=false){
  if(!state)return;if(fetching){queued={which,force};return;}if(which==='dashboards'&&!isAnalyst())return;
  fetching=true;const token=epoch;
  try{
   if(which==='dashboards'){if(force||!data||data.window.days!==days||Date.now()-last>30000){const requestedDays=days;const result=await api('/api/dashboards?days='+requestedDays);if(epoch!==token||requestedDays!==days)return;data=result;last=Date.now();}renderDash();}
   else{const result=await api('/api/reports');if(epoch!==token)return;list=result.items;renderReports();}
  }catch(e){const root=$(which+'-content');if(root&&token===epoch)root.innerHTML='<div class="panel workspace-empty">'+safe(e.message)+'</div>';}
  finally{fetching=false;if(queued){const next=queued;queued=null;void open(next.which,next.force);}}
 }
 function sync(){
  const next=state?state.session.csrf_token+'|'+state.session.role+'|'+state.session.subject_id:null;
  const nav=document.querySelector('[data-tab="dashboards"]');if(nav)nav.hidden=!state||!isAnalyst();
  if(epoch===next)return;epoch=next;data=null;list=[];activeReport=null;last=0;template=isAnalyst()?'executive':'activity';subject='';
  for(const id of ['dashboards-content','reports-content'])$(id)?.replaceChildren();
  if(state&&['dashboards','reports'].includes(selectedTab))void open(selectedTab,true);
 }
 document.addEventListener('click',async e=>{
  const u=e.target.closest('[data-ueba-section]');if(u){selectedUebaSection=u.dataset.uebaSection;changeTab('ueba/'+selectedUebaSection);return;}
  const b=e.target.closest('button');if(!b)return;
  if(b.dataset.dashboard){tab=b.dataset.dashboard;renderDash();return;}
  if(b.id==='refresh-dashboards'){void open('dashboards',true);return;}
  if(b.id==='refresh-reports'){void open('reports',true);return;}
  if(b.dataset.report){try{const token=epoch;const r=await api('/api/reports?id='+b.dataset.report);if(token!==epoch)return;activeReport=r;renderReports();}catch(e){showError(e.message);}}
 });
 document.addEventListener('change',e=>{
  if(e.target.id==='dashboard-period'){days=Number(e.target.value);void open('dashboards',true);}
  if(e.target.id==='report-days')days=Number(e.target.value);
  if(e.target.id==='report-template')template=e.target.value;
  if(e.target.id==='report-subject')subject=e.target.value;
 });
 document.addEventListener('submit',async e=>{
  if(e.target.id!=='report-form')return;e.preventDefault();if(busy)return;busy=true;const token=epoch;
  const b=e.submitter;b.disabled=true;b.textContent='Generating report…';
  try{const r=await api('/api/reports',{template,days,subject_id:subject||state.session.subject_id||''});if(token!==epoch)return;activeReport=r;const v=await api('/api/reports');if(token!==epoch)return;list=v.items;renderReports();$('report-status').textContent='Report generated and saved.';}
  catch(e){if(token===epoch&&$('report-status'))$('report-status').textContent=e.message;}
  finally{busy=false;if(token===epoch){b.disabled=false;const current=$('report-form')?.querySelector('button');if(current){current.disabled=false;current.textContent='Generate report';}}}
 });
 setInterval(()=>{if(!document.hidden&&selectedTab==='dashboards'&&state)void open('dashboards');},30000);
 window.SedraWorkspace={sync,open};
})();
