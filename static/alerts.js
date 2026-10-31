"use strict";
let alertFeed=null, alertRows=new Map(), alertEpoch=null, alertWatermark=null;
let detailInitialLoad=null;
let alertDetail=null, alertPollBusy=false, alertActionBusy=false, alertDispositionDraft='';

function alertPriority(value){return `<span class="alert-priority ${esc(value)}">${esc(titleCase(value))}</span>`;}
function alertStatus(value){return `<span class="alert-workflow ${esc(value.toLowerCase())}">${esc(titleCase(value))}</span>`;}
function alertError(message=''){$('alert-operation-error').textContent=message;$('alert-operation-error').hidden=!message;}

function syncAlertSession(){
  const epoch=state?.session?.csrf_token+'|'+state?.session?.role;
  if(epoch!==alertEpoch){
    alertEpoch=epoch;alertFeed=null;alertRows.clear();alertWatermark=null;alertDetail=null;alertDispositionDraft='';
    $('alert-notification').hidden=true;alertError();
    $('alerts-live-status').textContent=isAnalyst()?'Waiting for alert feed':'Analyst access required';
    if(isAnalyst()&&state.alerts?.available)acceptAlertFeed(state.alerts,false);
  }
  renderAlerts();
  if(alertPageId && isAnalyst() && detailInitialLoad!==epoch){detailInitialLoad=epoch;void openAlert(alertPageId);}
}

function acceptAlertFeed(feed,announce=true){
  if(!feed.available)return;
  if(alertFeed && feed.generation!==alertFeed.generation){alertRows.clear();alertDetail=null;alertWatermark=0;$('alert-notification').hidden=true;}
  const fresh=alertWatermark===null?[]:feed.items.filter(a=>a.seq>alertWatermark&&!a.imported_from_ledger);
  alertWatermark=Math.max(alertWatermark||0,feed.watermark);
  alertFeed=feed;
  for(const item of feed.items)alertRows.set(item.alert_id,item);
  if(announce&&fresh.length){
    const first=fresh[0];
    $('alert-notification-title').textContent=fresh.length===1?`${titleCase(first.severity)} · ${first.title}`:`${fresh.length} new security alerts`;
    $('alert-notification-description').textContent=`${first.subject_id} · ${first.outcome} · ${first.display_id}`;
    $('alert-notification').hidden=false;
  }
  renderAlerts();
}

async function pollAlerts(){
  if(!state||!isAnalyst()||alertPollBusy||alertActionBusy||document.hidden)return;
  const epoch=alertEpoch;alertPollBusy=true;
  try{
    const feed=await api('/api/alerts');
    if(epoch!==alertEpoch||!isAnalyst())return;
    acceptAlertFeed(feed,true);
    $('alerts-live-status').textContent='Live · 2s polling';
    const current=alertDetail?.alert, latest=current?alertRows.get(current.alert_id):null;
    if(current && latest && (current.revision!==latest.revision||current.state!==latest.state)){
      if($('alert-inspector').contains(document.activeElement)){
        $('alert-detail-freshness').textContent='This alert changed. Refresh details before applying an action.';
      }else await openAlert(current.alert_id,false);
    }
  }catch(error){
    $('alerts-live-status').textContent='Alert feed unavailable · last snapshot retained';
    if(error.status===403){
      alertRows.clear();alertFeed=null;alertDetail=null;$('alert-notification').hidden=true;renderAlerts();
      if(!loading)await loadState({silent:true});
    }
  }finally{alertPollBusy=false;}
}

function visibleAlerts(){
  const status=$('alert-status-filter').value,priority=$('alert-severity-filter').value;
  const query=$('alert-search').value.trim().toLowerCase().replace(/\buser[ -]?(\d+)\b/g,(_,n)=>'lab-'+n.padStart(3,'0')),unread=$('alert-unread-filter').checked;
  return [...alertRows.values()].sort((a,b)=>b.seq-a.seq).filter(a=>
    (status==='all'||(status==='active'?a.status!=='RESOLVED':a.status===status))&&
    (priority==='all'||a.severity===priority)&&(!unread||!a.read_at)&&
    (!query||JSON.stringify([a.display_id,a.title,a.subject_id,a.request_id,a.detector_types,a.reason_codes,a.destination]).toLowerCase().includes(query)));
}

function renderAlerts(){
  if(!state)return;
  const analyst=isAnalyst(),counts=alertFeed?.counts;
  $('alerts-access-note').hidden=analyst;$('alerts-authorized-content').hidden=!analyst;
  $('alert-bell').hidden=!analyst;
  $('alerts-nav-count').hidden=!analyst||!counts?.active;
  $('alerts-nav-count').textContent=counts?.active||'';
  $('alerts-nav-count').title='Active alerts';
  $('alert-unread-count').hidden=!analyst||!counts?.unread;
  $('alert-unread-count').textContent=counts?.unread||'';
  $('alert-bell').setAttribute('aria-label',`Open security alerts${counts?`, ${counts.unread} unread`:''}`);
  if(!analyst){$('alert-inspector').hidden=true;$('alerts-live-status').textContent='Analyst access required';return;}
  if(!counts){$('alerts-live-status').textContent='Waiting for alert feed';return;}
  $('alert-metrics').innerHTML=[['Open',counts.open,'Awaiting analyst review'],['In review',counts.in_review,'Acknowledged by Analyst'],['Unread',counts.unread,'Persisted across reloads'],['Critical active',counts.critical_active,'Impact-based review priority']].map(([label,n,note])=>`<article class="metric-card"><div class="metric-label">${esc(label)}</div><div class="metric-number">${n}</div><div class="metric-footnote">${esc(note)}</div></article>`).join('');
  const items=visibleAlerts();
  $('alert-queue-count').textContent=`${items.length} matching · ${counts.total} recorded · ${counts.resolved} resolved`;
  $('alert-rows').innerHTML=items.length?items.map(a=>`<tr class="${!a.read_at?'alert-unread':''} ${alertDetail?.alert.alert_id===a.alert_id?'selected':''}"><td><a class="asset-link" href="/alert?id=${encodeURIComponent(a.alert_id)}" target="_blank" rel="noopener">${esc(a.title)}</a><span class="table-subline">${esc(a.display_id)} · ${esc(dateTime(a.occurred_at))}${a.imported_from_ledger?' · imported event':''}</span></td><td>${alertPriority(a.severity)}</td><td><strong>${esc(a.subject_id)}</strong><span class="table-subline">${esc(a.destination)}</span></td><td><span class="alert-outcome">${esc(a.outcome)}</span><div class="tag-row">${a.detector_types.slice(0,2).map(t=>`<span class="data-tag detector">${esc(titleCase(t))}</span>`).join('')}</div></td><td>${alertStatus(a.status)}</td><td><a class="text-button" href="/alert?id=${encodeURIComponent(a.alert_id)}" target="_blank" rel="noopener" aria-label="Investigate ${esc(a.display_id)} in a new tab">Investigate ↗</a></td></tr>`).join(''):'<tr><td colspan="6" class="empty-state">No alerts match these filters.</td></tr>';
  $('alerts-loaded-note').textContent=`${alertRows.size} / ${counts.total} records loaded. Older records are available below.`;
  $('load-older-alerts').hidden=alertRows.size>=counts.total;
  $('alert-inspector').hidden=!alertDetail;
}

async function openAlert(alertId,markRead=true){
  if(!isAnalyst()||alertActionBusy)return;
  const epoch=alertEpoch;alertError();
  try{
    let detail=await api('/api/alerts?id='+encodeURIComponent(alertId));
    if(epoch!==alertEpoch||!isAnalyst())return;
    if(markRead&&!detail.alert.read_at){
      try{
        await api('/api/alerts/action',{alert_id:alertId,action_id:crypto.randomUUID(),action:'READ',expected_revision:detail.alert.revision});
        detail=await api('/api/alerts?id='+encodeURIComponent(alertId));
      }catch(error){
        if(error.status!==409)throw error;
        detail=await api('/api/alerts?id='+encodeURIComponent(alertId));
      }
    }
    if(epoch!==alertEpoch||!isAnalyst())return;
    if(alertDetail?.alert.alert_id!==alertId)alertDispositionDraft='';
    alertDetail=detail;alertRows.set(alertId,detail.alert);renderAlerts();renderAlertDetail();
    if(alertPageId){document.title=detail.alert.display_id+' · SEDRA';$('alerts-live-status').textContent=detail.alert.display_id;}
    await pollAlerts();
  }catch(error){alertError(error.message);}
}

function browserEvidenceHTML(context){
  if(!context)return '';
  const rows=[['Browser destination',context.host],['Guarded operation',context.operation],['Check mode',context.mode],['Evidence source',context.origin],['Enforcement evidence',context.enforcement],['Inspection failure',context.inspection_failure||'None']];
  return `<div class="ueba-freshness"><strong>Browser Guard evidence</strong><dl class="event-details">${rows.map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>${(context.files||[]).map(file=>`<p>Attachment ${esc(file.suffix)} · ${esc(file.bytes)} bytes · ${esc(file.inspection)}<br>SHA-256 ${esc(file.sha256)}</p>`).join('')}<p>Prompt and file content are masked. A browser report is not independent external delivery proof.</p></div>`;
}

function renderAlertDetail(){
  if(!alertDetail||!isAnalyst())return;
  const a=alertDetail.alert,request=alertDetail.request,closed=a.status==='RESOLVED';
  $('alert-inspector').hidden=false;
  $('alert-inspector').innerHTML=`<div class="panel-heading"><div><div class="eyebrow">${esc(a.display_id)} / INVESTIGATION</div><h2>${esc(a.title)}</h2><p>${esc(a.subject_id)} · ${esc(dateTime(a.occurred_at))} · revision ${a.revision}</p></div><a href="/#alerts" class="text-button">Back to alerts ↗</a></div><div class="alert-inspector-body"><div class="alert-detail-grid"><div><div class="tag-row">${alertPriority(a.severity)}${alertStatus(a.status)}<span class="data-tag">${esc(a.category)}</span></div><div class="alert-impact"><strong>${esc(a.outcome)}</strong><p>${esc(a.severity_basis)}</p></div><dl class="event-details">${[['Subject',a.subject_id],['Route',a.destination],['Policy decision',a.decision],['Delivery state',a.state],['Behavior priority',a.behavior_score],['Assignment',a.assigned_to||'Unassigned'],['Disposition',titleCase(a.disposition)],['Original payload SHA-256',a.body_sha256],['Original UTF-8 bytes',a.body_bytes]].map(([k,v])=>`<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>${request.behavior_context?.policy_context ? `<div class="ueba-freshness"><strong>Frozen UEBA context at admission</strong><p>Effective ${esc(request.behavior_context.behavior_score)} · daily applied ${esc(request.behavior_context.policy_context.daily_component)} · live ${esc(request.behavior_context.policy_context.live_component)} · model ${esc(request.behavior_context.model_context?.status)}.</p><p>Active live rules: ${esc(request.behavior_context.live_context?.active_rule_ids?.join(" · ") || "None")}.</p></div>` : ""}${browserEvidenceHTML(a.browser_context)}${securityTagsHTML(a.security_tags)}<div class="tag-row">${a.reason_codes.map(r=>`<span class="data-tag">${esc(r)}</span>`).join('')}</div>${a.imported_from_ledger?'<p class="scope-note">Imported from the retained local gateway ledger; the event time above is historical.</p>':''}</div><div><h3 class="mini-heading">Analyst workflow</h3><p class="scope-note">${esc(a.workflow_note)}</p><div class="alert-actions"><button class="button primary" data-alert-action="ACKNOWLEDGE" ${a.status!=='OPEN'?'disabled':''}>Acknowledge & investigate</button><label for="alert-disposition">Resolution</label><select id="alert-disposition" ${closed?'disabled':''}><option value="">Choose a disposition</option><option value="CONFIRMED_POLICY_EVENT">Confirmed policy event</option><option value="FALSE_POSITIVE">False positive · analyst assessment</option><option value="EXPECTED_TEST">Expected synthetic test</option></select><button class="button secondary" data-alert-action="RESOLVE" ${closed||!alertDispositionDraft?'disabled':''}>Resolve alert</button><button class="button secondary" data-alert-action="REOPEN" ${!closed?'disabled':''}>Reopen alert</button></div><p id="alert-detail-freshness" class="scope-note">${a.kind==='DELIVERY_UNKNOWN'?'Reconciliation updates delivery evidence; analyst resolution remains separate.':'Prevented request. Review does not unblock or retry the payload.'}</p><button id="refresh-alert-detail" class="text-button">Refresh details</button><div class="alert-shortcuts"><button class="text-button" id="alert-investigate-subject">Investigate subject ↗</button><button class="text-button" id="alert-inspect-request">Inspect gateway request ↗</button></div><h3 class="mini-heading">Review history</h3><ol class="alert-history"><li><b>Gateway event recorded</b><span>${esc(dateTime(a.occurred_at))}</span></li>${alertDetail.history.map(h=>`<li><b>${esc(titleCase(h.action))} · ${esc(h.actor)}</b><span>${esc(titleCase(h.old_status||'OPEN'))} → ${esc(titleCase(h.new_status))} · ${esc(dateTime(h.at))}</span>${h.action==='RESOLVE'?`<small>${esc(titleCase(h.disposition))}</small>`:''}</li>`).join('')}</ol></div></div><details class="evidence-json"><summary>Inspect complete masked alert and gateway evidence</summary><pre>${esc(JSON.stringify(alertDetail,null,2))}</pre></details></div>`;
  $('alert-disposition').value=closed?a.disposition:alertDispositionDraft;
}

async function applyAlertAction(action){
  if(alertActionBusy||mutating||!alertDetail||!isAnalyst())return;
  const a=alertDetail.alert,epoch=alertEpoch;
  const body={alert_id:a.alert_id,action_id:crypto.randomUUID(),action,expected_revision:a.revision};
  if(action==='RESOLVE'){if(!alertDispositionDraft)return;body.disposition=alertDispositionDraft;}
  alertActionBusy=true;setBusy(true);alertError();
  $('alert-inspector').querySelectorAll('button,select').forEach(el=>el.disabled=true);
  try{
    await api('/api/alerts/action',body);
    const detail=await api('/api/alerts?id='+encodeURIComponent(a.alert_id));
    if(epoch!==alertEpoch||!isAnalyst())return;
    alertDetail=detail;alertRows.set(a.alert_id,detail.alert);
    if(action==='REOPEN')alertDispositionDraft='';
    renderAlerts();renderAlertDetail();notify(`Alert ${titleCase(detail.alert.status)}. Gateway decision remains ${detail.alert.decision}.`);
  }catch(error){
    alertError(error.message+' Refresh details to verify the current state before another action.');renderAlertDetail();
  }finally{alertActionBusy=false;setBusy(false);await pollAlerts();}
}

for(const id of ['alert-search','alert-status-filter','alert-severity-filter','alert-unread-filter'])$(id).addEventListener(id==='alert-search'?'input':'change',renderAlerts);
document.addEventListener('click',async event=>{
  const open=event.target.closest('[data-alert-open]');if(open){window.open('/alert?id='+encodeURIComponent(open.dataset.alertOpen),'_blank','noopener');return;}
  const action=event.target.closest('[data-alert-action]');if(action){await applyAlertAction(action.dataset.alertAction);return;}
  if(event.target.closest('#close-alert-inspector')){alertDetail=null;renderAlerts();}
  if(event.target.closest('#refresh-alert-detail')&&alertDetail)await openAlert(alertDetail.alert.alert_id,false);
  if(event.target.closest('#alert-investigate-subject')&&alertDetail){if(alertPageId){location.assign('/?subject='+encodeURIComponent(alertDetail.alert.subject_id)+'#investigation');return;}analysisSource='lab';selectedSubject=alertDetail.alert.subject_id;renderSubjectOptions();changeTab('investigation');}
  if(event.target.closest('#alert-inspect-request')&&alertDetail){if(alertPageId){location.assign('/?request='+encodeURIComponent(alertDetail.request.request_id)+'#transfers');return;}activeRequest=alertDetail.request;changeTab('lab');}
});
document.addEventListener('change',event=>{
  if(event.target.id==='alert-disposition'){
    alertDispositionDraft=event.target.value;
    const button=$('alert-inspector').querySelector('[data-alert-action="RESOLVE"]');
    if(button)button.disabled=!alertDispositionDraft||alertDetail?.alert.status==='RESOLVED';
  }
});
$('dismiss-alert-notification').onclick=()=>{$('alert-notification').hidden=true;};
$('review-alert-notification').onclick=()=>{$('alert-notification').hidden=true;$('alert-status-filter').value='active';changeTab('alerts');};
$('load-older-alerts').onclick=async()=>{
  if(!isAnalyst()||!alertRows.size)return;
  const epoch=alertEpoch,before=Math.min(...[...alertRows.values()].map(a=>a.seq));
  try{const feed=await api('/api/alerts?before='+before);if(epoch===alertEpoch&&isAnalyst())acceptAlertFeed(feed,false);}
  catch(error){alertError(error.message);}
};
$('export-alerts').onclick=()=>{
  if(!isAnalyst())return;
  const blob=new Blob([JSON.stringify({profile:'sedra-gateway-alerts-v1',scope:alertFeed?.scope,exported_at:new Date().toISOString(),counts:alertFeed?.counts,items:visibleAlerts()},null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='SEDRA-alert-results.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
if(state)syncAlertSession();
setInterval(pollAlerts,2000);
