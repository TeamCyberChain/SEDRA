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
 if(part==='endpoint')return (typeof agentPanelHTML==='function'?agentPanelHTML(s):'')+(html('.endpoint-panel')||'<div class="panel workspace-empty">No local endpoint identity is mapped to this subject.</div>');
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
  if(boardId)body=customBoard();
  root.innerHTML=`${trail()}${boardLibrary()}<div class="workspace-tabs">${Object.entries(named).map(([k,v])=>`<button data-dashboard="${k}" aria-selected="${!boardId&&tab===k}">${v}</button>`).join('')}</div>${body}<p class="scope-note">Snapshot ${safe(dateTime(data.generated_at))}. Detail rows ${n(data.data_quality.detail_rows)} / ${n(m.attempts)}${data.data_quality.detail_truncated?' · breakdowns are bounded; totals remain complete':''}.</p>`;
 }
 let boardId=null,boardDraft=null,boardDirty=false,boardEdit=false,boardBusy=false,boardDialog=null;
 const copy=v=>JSON.parse(JSON.stringify(v));
 const widgetLabels={kpi:'Metric card',trend:'Daily activity',detectors:'Sensitive-pattern detections',routes:'Destinations',classifications:'Classification snapshots',cases:'Case review status',coverage:'Source coverage',actions:'Recommended actions'};
 const metricLabels={attempts:'Transfer attempts',blocked:'Stopped by policy',confirmed:'Confirmed deliveries',unconfirmed:'Unconfirmed deliveries',active_identities:'Active identities',high_priority_identities:'High live priority',document_accesses:'Application document accesses',registered_sources:'Registered sources'};
 function metricNote(key){return ({high_priority_identities:'Current observed live rules; analyst review required',registered_sources:'Registered synthetic corpus; not endpoint discovery',document_accesses:'Application endpoint only',unconfirmed:'Reconciliation required; do not automatically resend'})[key]||'Recorded gateway activity in the selected period';}
 function makeWidget(type,metric){return {id:crypto.randomUUID().replaceAll('-','').slice(0,12),type,title:type==='kpi'?metricLabels[metric]:widgetLabels[type],width:['trend','coverage','actions'].includes(type)?'full':'half',...(type==='kpi'?{metric}: {})};}
 function starter(kind){if(kind==='blank')return [];if(kind==='protection')return [makeWidget('kpi','blocked'),makeWidget('kpi','unconfirmed'),makeWidget('detectors'),makeWidget('routes'),makeWidget('classifications')];return [makeWidget('kpi','attempts'),makeWidget('kpi','blocked'),makeWidget('kpi','confirmed'),makeWidget('kpi','unconfirmed'),makeWidget('trend'),makeWidget('actions')];}
 function boardLibrary(){const ready=Array.isArray(data.saved_dashboards);return `<div class="board-library"><label>Saved dashboards<select id="saved-dashboard-select" ${!ready?'disabled':''}><option value="">Choose a saved dashboard</option>${(data.saved_dashboards||[]).map(b=>`<option value="${b.id}" ${b.id===boardId?'selected':''}>${safe(b.name)}</option>`).join('')}</select></label><div><button class="button secondary" id="archived-dashboards" ${!ready?'disabled':''}>Archived</button><button class="button primary" id="new-dashboard" ${!ready?'disabled':''}>＋ New dashboard</button></div></div>`;}
 function widgetBody(w){
  if(w.type==='kpi')return `<div class="board-metric"><strong>${n(data.metrics[w.metric])}</strong><p>${safe(metricNote(w.metric))}</p></div>`;
  if(w.type==='trend')return bars(data.trend,'attempts',r=>r.day)+'<p class="scope-note">AZT (UTC+04). Only dates with recorded attempts are shown.</p>';
  if(w.type==='detectors')return bars(data.detectors,'count',r=>r.name.replaceAll('_',' '))+'<p class="scope-note">One request may contain several types. Bounded detail rows, not detection efficacy.</p>';
  if(w.type==='routes')return bars(data.routes,'attempts',r=>r.route);
  if(w.type==='classifications')return bars(data.classifications,'count',r=>r.name);
  if(w.type==='cases')return ['open','in_review','resolved'].map(k=>`<div class="brief-row"><span>${safe(k.replaceAll('_',' '))}</span><b>${n(data.cases[k])}</b></div>`).join('')+'<p class="scope-note">Current retained review status; independent of the request period.</p>';
  if(w.type==='coverage')return data.coverage.map(c=>`<div class="board-source"><strong>${safe(c.name)}</strong><span>${safe(c.state)}</span><p>${safe(c.note)}</p></div>`).join('');
  return data.recommended_actions.map((a,i)=>`<div class="leader-action"><b>${i+1}</b><p>${safe(a)}</p></div>`).join('');
 }
 function customBoard(){
  const saved=(data.saved_dashboards||[]).find(b=>b.id===boardId);if(!saved){boardId=null;boardDraft=null;return '<section class="panel workspace-brief"><p>This dashboard is no longer available. Select a preset or another saved dashboard.</p></section>';}
  if(!boardDraft||(!boardDirty&&boardDraft.revision!==saved.revision))boardDraft=copy(saved);
  const b=boardDraft,changed=boardDirty&&b.revision!==saved.revision;
  return `<section class="panel board-heading"><div><span class="workspace-overline">YOUR DASHBOARD · REVISION ${b.revision}</span><h2>${safe(b.name)}</h2>${b.description?`<p>${safe(b.description)}</p>`:''}<small>${boardDirty?'Unsaved changes':'Saved to your account'}${changed?' · A newer saved revision exists':''}</small></div><div class="board-actions">${boardEdit?`<button class="button secondary" id="board-details">Details</button><button class="button secondary" id="add-widget">＋ Add widget</button><button class="button secondary" id="discard-board">Discard draft</button><button class="button primary" id="save-board" ${boardBusy||!boardDirty?'disabled':''}>Save dashboard</button>`:`<button class="button secondary" id="archive-board">Archive</button><button class="button primary" id="edit-board">Edit layout</button>`}</div></section>${changed?'<p class="board-warning">Reload the saved version before editing, or retain this draft to compare. Saving a stale revision is rejected.</p>':''}<div class="board-grid">${b.widgets.map((w,i)=>`<section class="panel board-widget ${w.width==='full'?'board-wide':''}" data-widget="${w.id}"><div class="board-widget-heading"><h2>${safe(w.title)}</h2>${boardEdit?`<div class="widget-controls"><button data-widget-up="${w.id}" aria-label="Move ${safe(w.title)} earlier" ${i===0?'disabled':''}>↑</button><button data-widget-down="${w.id}" aria-label="Move ${safe(w.title)} later" ${i===b.widgets.length-1?'disabled':''}>↓</button><button data-widget-edit="${w.id}" aria-label="Edit ${safe(w.title)}">Edit</button><button data-widget-remove="${w.id}" aria-label="Remove ${safe(w.title)}">×</button></div>`:''}</div>${widgetBody(w)}</section>`).join('')}</div>${!b.widgets.length?`<section class="panel board-empty"><h2>Build your view</h2><p>Add recorded metrics, activity, sensitive-pattern detections and source coverage.</p><button class="button primary" id="empty-add-widget">＋ Add widget</button></section>`:''}`;
 }
 function ensureBoardDialog(){if(boardDialog)return boardDialog;boardDialog=document.createElement('dialog');boardDialog.className='board-dialog';boardDialog.setAttribute('aria-label','Dashboard editor');document.body.append(boardDialog);return boardDialog;}
 function closeBoardDialog(){if(boardDialog?.open)boardDialog.close();boardDialog?.replaceChildren();}
 function modal(title,body){const d=ensureBoardDialog();d.innerHTML=`<div class="board-dialog-head"><h2>${safe(title)}</h2><button type="button" data-board-cancel aria-label="Close dashboard editor">×</button></div>${body}<p id="board-dialog-status" role="alert"></p>`;if(!d.open)d.showModal();}
 function newBoardDialog(){modal('Create dashboard',`<form id="create-board-form"><label>Dashboard name<input name="name" required maxlength="60" placeholder="e.g. Leadership review"></label><label>Description<input name="description" maxlength="240" placeholder="Optional purpose of this dashboard"></label><div class="board-form-row"><label>Period<select name="days">${[1,7,30].map(d=>`<option value="${d}" ${d===days?'selected':''}>${d===1?'Last 24 hours':'Last '+d+' days'}</option>`).join('')}</select></label><label>Start with<select name="starter"><option value="executive">Executive starter</option><option value="protection">Data protection starter</option><option value="blank">Blank canvas</option></select></label></div><p class="scope-note">Saved to your account. Widgets use observed data; no custom scripts or external data are embedded.</p><div class="board-actions"><button type="button" data-board-cancel>Cancel</button><button class="button primary">Create dashboard</button></div></form>`);}
 function editDetails(){modal('Dashboard details',`<form id="board-details-form"><label>Name<input name="name" maxlength="60" required value="${safe(boardDraft.name)}"></label><label>Description<input name="description" maxlength="240" value="${safe(boardDraft.description)}"></label><button class="button primary">Apply to draft</button></form>`);}
 function widgetDialog(id=null){if(!boardDraft)return;boardEdit=true;const w=boardDraft.widgets.find(w=>w.id===id);modal(w?'Edit widget':'Add widget',`<form id="widget-form" data-widget-id="${w?.id||''}"><label>Widget type<select name="type" id="widget-type">${Object.entries(widgetLabels).map(([k,v])=>`<option value="${k}" ${k===(w?.type||'kpi')?'selected':''}>${v}</option>`).join('')}</select></label><label id="widget-metric-label" ${w&&w.type!=='kpi'?'hidden':''}>Metric<select name="metric" id="widget-metric">${Object.entries(metricLabels).map(([k,v])=>`<option value="${k}" ${k===(w?.metric||'attempts')?'selected':''}>${v}</option>`).join('')}</select></label><label>Widget title<input name="title" id="widget-title" maxlength="70" required value="${safe(w?.title||'Transfer attempts')}"></label><label>Width<select name="width"><option value="half" ${w?.width!=='full'?'selected':''}>Half width</option><option value="full" ${w?.width==='full'?'selected':''}>Full width</option></select></label><p class="scope-note">New widgets are added to the draft. Save the dashboard to keep the layout.</p><button class="button primary">${w?'Apply widget changes':'Add to dashboard'}</button></form>`);}
 async function selectBoard(id){const saved=data?.saved_dashboards?.find(b=>b.id===id);if(!saved)return;boardId=id;boardDraft=copy(saved);boardDirty=false;boardEdit=false;days=saved.days;await open('dashboards',true);}
 async function archiveDialog(){modal('Archive dashboard',`<p>Remove ${safe(boardDraft.name)} from the active list. You can restore it from Archived.</p><button class="button secondary" id="confirm-archive-board">Archive dashboard</button><button type="button" data-board-cancel>Cancel</button>`);}
 async function showArchived(){const token=epoch;const r=await api('/api/dashboards/saved?archived=1');if(token!==epoch)return;modal('Archived dashboards',r.items.length?r.items.map(b=>`<div class="brief-row"><span>${safe(b.name)}</span><button data-restore-board="${b.id}" data-revision="${b.revision}">Restore</button></div>`).join(''):'<p>No archived dashboards.</p>');}
 async function boardClick(button){
  if(button.hasAttribute('data-board-cancel')){closeBoardDialog();return true;}
  if(boardBusy)return Boolean(button.closest('.board-dialog')||button.closest('.board-heading'));
  const id=button.id;
  if(id==='new-dashboard'){if(boardDirty&&!confirm('Discard unsaved dashboard changes?'))return true;newBoardDialog();return true;}
  if(id==='edit-board'){boardEdit=true;renderDash();return true;}
  if(id==='board-details'){editDetails();return true;}
  if(id==='add-widget'||id==='empty-add-widget'){widgetDialog();return true;}
  if(id==='discard-board'){const b=data.saved_dashboards.find(b=>b.id===boardId);boardDraft=copy(b);boardDirty=false;boardEdit=false;days=b.days;await open('dashboards',true);return true;}
  if(id==='archived-dashboards'){await showArchived();return true;}
  if(id==='archive-board'){await archiveDialog();return true;}
  if(button.dataset.widgetEdit){widgetDialog(button.dataset.widgetEdit);return true;}
  if(button.dataset.widgetRemove||button.dataset.widgetUp||button.dataset.widgetDown){
   const uid=button.dataset.widgetRemove||button.dataset.widgetUp||button.dataset.widgetDown,i=boardDraft.widgets.findIndex(w=>w.id===uid);if(i<0)return true;
   if(button.dataset.widgetRemove)boardDraft.widgets.splice(i,1);else{const j=i+(button.dataset.widgetUp?-1:1);if(j>=0&&j<boardDraft.widgets.length)[boardDraft.widgets[i],boardDraft.widgets[j]]=[boardDraft.widgets[j],boardDraft.widgets[i]];}
   boardDirty=true;renderDash();return true;
  }
  if(id==='save-board'||id==='confirm-archive-board'||button.dataset.restoreBoard){
   boardBusy=true;const token=epoch;button.disabled=true;
   try{
    const body=id==='save-board'?{action:'update',id:boardDraft.id,expected_revision:boardDraft.revision,name:boardDraft.name,description:boardDraft.description,days,widgets:boardDraft.widgets}:id==='confirm-archive-board'?{action:'archive',id:boardDraft.id,expected_revision:boardDraft.revision}:{action:'restore',id:button.dataset.restoreBoard,expected_revision:Number(button.dataset.revision)};
    const result=await api('/api/dashboards/saved',body);if(token!==epoch)return true;
    closeBoardDialog();if(body.action==='archive'){boardId=null;boardDraft=null;}else{boardId=result.id;boardDraft=copy(result);days=result.days;}boardDirty=false;boardEdit=false;await open('dashboards',true);notify('Dashboard '+(body.action==='update'?'saved':body.action==='archive'?'archived':'restored')+'.');
   }finally{boardBusy=false;button.disabled=false;if(token===epoch&&data&&selectedTab==='dashboards')renderDash();}return true;
  }
  return false;
 }
 async function boardSubmit(e){
  if(!['create-board-form','widget-form','board-details-form'].includes(e.target.id))return false;e.preventDefault();if(boardBusy)return true;
  const f=e.target,v=Object.fromEntries(new FormData(f)),button=e.submitter;button.disabled=true;boardBusy=true;const token=epoch;
  try{
   if(f.id==='create-board-form'){const b=await api('/api/dashboards/saved',{action:'create',name:v.name,description:v.description,days:Number(v.days),widgets:starter(v.starter)});if(token!==epoch)return true;boardId=b.id;boardDraft=copy(b);boardDirty=false;boardEdit=true;days=b.days;closeBoardDialog();await open('dashboards',true);}
   if(f.id==='widget-form'){if(boardDraft.widgets.length>=16&&!f.dataset.widgetId)throw Error('A dashboard supports up to 16 widgets');const w={id:f.dataset.widgetId||crypto.randomUUID().replaceAll('-','').slice(0,12),type:v.type,title:v.title,width:v.width,...(v.type==='kpi'?{metric:v.metric}:{})};const i=boardDraft.widgets.findIndex(x=>x.id===w.id);if(i<0)boardDraft.widgets.push(w);else boardDraft.widgets[i]=w;boardDirty=true;closeBoardDialog();renderDash();}
   if(f.id==='board-details-form'){boardDraft.name=v.name;boardDraft.description=v.description;boardDirty=true;closeBoardDialog();renderDash();}
  }catch(err){const status=$('board-dialog-status');if(status&&token===epoch)status.textContent=err.message;else if(token===epoch)showError(err.message);}finally{boardBusy=false;button.disabled=false;if(token===epoch&&data&&selectedTab==='dashboards')renderDash();}return true;
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
  if(epoch===next)return;closeBoardDialog();boardId=null;boardDraft=null;boardDirty=false;boardEdit=false;epoch=next;data=null;list=[];activeReport=null;last=0;template=isAnalyst()?'executive':'activity';subject='';
  for(const id of ['dashboards-content','reports-content'])$(id)?.replaceChildren();
  if(state&&['dashboards','reports'].includes(selectedTab))void open(selectedTab,true);
 }
 document.addEventListener('click',async e=>{
  const u=e.target.closest('[data-ueba-section]');if(u){selectedUebaSection=u.dataset.uebaSection;changeTab('ueba/'+selectedUebaSection);return;}
  const b=e.target.closest('button');if(!b)return;
  try{if(await boardClick(b))return;}catch(err){const status=$('board-dialog-status');if(status&&boardDialog?.open)status.textContent=err.message;else showError(err.message);return;}
  if(b.dataset.dashboard){if(boardDirty&&!confirm('Discard unsaved dashboard changes?'))return;boardId=null;boardDraft=null;boardDirty=false;boardEdit=false;tab=b.dataset.dashboard;renderDash();return;}
  if(b.id==='refresh-dashboards'){void open('dashboards',true);return;}
  if(b.id==='refresh-reports'){void open('reports',true);return;}
  if(b.dataset.report){try{const token=epoch;const r=await api('/api/reports?id='+b.dataset.report);if(token!==epoch)return;activeReport=r;renderReports();}catch(e){showError(e.message);}}
 });
 document.addEventListener('change',e=>{
  if(e.target.id==='saved-dashboard-select'){if(e.target.value){if(boardDirty&&!confirm('Discard unsaved dashboard changes?')){e.target.value=boardId;return;}void selectBoard(e.target.value);}return;}
  if(e.target.id==='widget-type'){const type=e.target.value;$('widget-metric-label').hidden=type!=='kpi';$('widget-title').value=type==='kpi'?metricLabels[$('widget-metric').value]:widgetLabels[type];return;}
  if(e.target.id==='widget-metric'){$('widget-title').value=metricLabels[e.target.value];return;}
  if(e.target.id==='dashboard-period'){days=Number(e.target.value);if(boardId&&boardDraft){boardDraft.days=days;boardDirty=true;}void open('dashboards',true);}
  if(e.target.id==='report-days')days=Number(e.target.value);
  if(e.target.id==='report-template')template=e.target.value;
  if(e.target.id==='report-subject')subject=e.target.value;
 });
 document.addEventListener('submit',async e=>{
  if(['create-board-form','widget-form','board-details-form','report-form'].includes(e.target.id))e.preventDefault();
  if(await boardSubmit(e))return;
  if(e.target.id!=='report-form')return;e.preventDefault();if(busy)return;busy=true;const token=epoch;
  const b=e.submitter;b.disabled=true;b.textContent='Generating report…';
  try{const r=await api('/api/reports',{template,days,subject_id:subject||state.session.subject_id||''});if(token!==epoch)return;activeReport=r;const v=await api('/api/reports');if(token!==epoch)return;list=v.items;renderReports();$('report-status').textContent='Report generated and saved.';}
  catch(e){if(token===epoch&&$('report-status'))$('report-status').textContent=e.message;}
  finally{busy=false;if(token===epoch){b.disabled=false;const current=$('report-form')?.querySelector('button');if(current){current.disabled=false;current.textContent='Generate report';}}}
 });
 setInterval(()=>{if(!document.hidden&&selectedTab==='dashboards'&&state)void open('dashboards');},30000);
 window.SedraWorkspace={sync,open};
})();
