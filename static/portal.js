"use strict";
const $ = id => document.getElementById(id);
let session, connection, pending, detectorExamples={}, busy=false;
async function api(path,body){
  const response=await fetch(path,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',
    headers:{'Content-Type':'application/json','X-CSRF-Token':session?.csrf_token||''},body:body===undefined?undefined:JSON.stringify(body)});
  const data=await response.json();
  if(!response.ok)throw new Error(data.error||'The request could not be completed.');
  return data;
}
function error(message=''){ $('error').textContent=message;$('error').hidden=!message; }
function controls(value){busy=value;document.querySelectorAll('button,input,select').forEach(el=>el.disabled=value);renderConnection();}
function renderConnection(){
  if(!connection||!session)return;
  const analyst=session.role==='analyst';
  document.querySelectorAll('.portal-nav a[href="/#alerts"],.portal-nav a[href="/integrations"]').forEach(n=>{n.hidden=!analyst;});
  const local=connection.provider_id==='local';
  $('connection-status').textContent=connection.configured?`${local?'Local AI ready':'OpenAI configured'} · ${connection.model}`:`${local?'Local AI':'OpenAI'} not connected`;
  $('flow-label').textContent=`Employee → SEDRA → ${local?'Local Qwen':'OpenAI'} → answer`;
  $('route-note').textContent=local?'Model inference stays on this computer. No cloud provider or API credits are used.':'Only allowed text is sent to api.openai.com. Use fictional examples for the demonstration.';
  $('connection-panel').hidden=!analyst;
  $('send').disabled=busy||analyst||!connection.configured;
  $('send').textContent=busy?'Checking policy / waiting for provider…':pending?.unresolved?'Check existing request status':'Inspect & send to AI';
  $('new-request').hidden=!pending?.unresolved;$('uncertain-note').hidden=!pending?.unresolved;
  $('identity').value=analyst?'analyst':session.subject_id;
  $('identity').disabled=busy||Boolean(session?.principal);
}
async function refresh(){
  const data=await api('/api/portal/status');session=data.session;connection=data.connection;detectorExamples=data.data_types?.examples||{};error();
  $('provider').value=connection.provider_id||'openai';cloudFields();
  const subject=data.subjects.find(s=>s.subject_id===session.subject_id);
  $('context').textContent=subject?`Current policy context: ${subject.behavior_score}/100 · daily model applied: ${subject.model_context?.applied_score ?? subject.completed_day_score} (${subject.model_context?.status || "dated"}) · live UEBA: ${subject.live_context.score} / ${subject.live_context.active_rule_ids?.length || 0} active rules. Restricted content always blocks.`:session?.principal?'Sign in with a User account to send a governed request.':'Select an employee identity to send a governed request.';
  renderConnection();
}
function stat(label,value,blocked=false){const el=document.createElement('div');el.className='stat'+(blocked?' blocked':'');const title=document.createElement('span');title.textContent=label;const text=document.createElement('strong');text.textContent=String(value);el.append(title,text);return el;}
function renderAnswer(text){
  // Format the model's text with DOM nodes only; generated HTML is never interpreted.
  const fragments=[];
  for(const line of text.split('\n')){
    if(!line.trim())continue;
    const paragraph=document.createElement('p');
    for(const piece of line.split(/(\*\*[^*\n]+\*\*|`[^`\n]+`)/g)){
      if(piece.startsWith('**')&&piece.endsWith('**')){const strong=document.createElement('strong');strong.textContent=piece.slice(2,-2);paragraph.append(strong);}
      else if(piece.startsWith('`')&&piece.endsWith('`')){const code=document.createElement('code');code.textContent=piece.slice(1,-1);paragraph.append(code);}
      else paragraph.append(document.createTextNode(piece));
    }
    fragments.push(paragraph);
  }
  $('answer').replaceChildren(...fragments);
}
function showResult(data){
  const request=data.request, ai=data.ai, blocked=request.decision==='BLOCK';
  $('classification-panel').hidden=false;
  const tags=request.security_tags;
  const values=[tags?.sensitivity||'historical / unavailable',...(tags?.detector_tags||[]),...(tags?.business_tags||[])];
  $('classification-tags').replaceChildren(...values.map((value,i)=>{const el=document.createElement('span');el.className=i===0?'sensitivity '+(tags?.sensitivity||'unclassified'):'data-tag';el.textContent=i===0?value.charAt(0).toUpperCase()+value.slice(1):value.replace(/_/g,' ');return el;}));
  $('classification-details').replaceChildren(stat('INPUT SIZE',request.body_bytes+' UTF-8 bytes'),stat('REGISTERED SOURCES',(tags?.document_ids||[]).join(' · ')||'No eligible protected match'),stat('UNICODE INSPECTION',(request.normalization_flags?.mixed_script_tokens||0)+' mixed-script tokens'),stat('LABEL BASIS',tags?.basis||'Before governed-label profile'));
  $('classification-note').textContent=tags&&tags.sensitivity!=='unclassified'?'Derived from matched registered labels and supported structured detectors. Raw detector values are masked in evidence.':tags?.scope_note||'This historical request predates governed-label snapshots.';
  $('structured-findings').replaceChildren(...(request.structured_findings||[]).map(finding=>{
    const block=document.createElement('article');block.className='finding-card';
    const title=document.createElement('h3');title.textContent=finding.type.replace(/_/g,' ');
    const checks=document.createElement('p');checks.textContent='Checks: '+(finding.validation_checks||['legacy rule']).join(' · ');
    const representation=document.createElement('p');representation.textContent='Representation: '+(finding.representations||[finding.representation]).join(' · ');
    const normalization=document.createElement('p');normalization.textContent='Unicode normalization: '+((finding.normalization_steps||[]).join(' · ')||'none');
    const hash=document.createElement('code');hash.textContent='Canonical value SHA-256: '+finding.value_sha256;
    block.append(title,checks,representation,normalization,hash);return block;
  }));
  if(request.alert_ids?.length){const notice=document.createElement('p');notice.className='security-alert-recorded';notice.textContent='Security alert recorded · '+request.alert_ids.join(' · ')+' · review in Alerts with Analyst access.';$('structured-findings').append(notice);}
  renderAnswer(ai?.answer||'');
  $('answer-status').className=blocked?'blocked':'';
  const local=request.destination==='local_ai';
  $('answer-status').textContent=blocked?`SEDRA blocked this message. ${local?'The local model':'OpenAI'} was not contacted.`:ai?`Real ${ai.provider} response received${ai.status==='incomplete'?' · output limit reached':''}.`:data.error||`Delivery: ${request.state}. This request is not automatically resent.`;
  $('answer-meta').textContent=ai?`${ai.model} · ${ai.response_id} · ${ai.usage?.total_tokens??'Unknown'} tokens · ${local?'CPU inference on this computer; no cloud request':'provider response observed by this gateway'}; no independent receiver receipt.`:'';
  $('evidence-summary').replaceChildren(stat('SEDRA POLICY',request.decision,blocked),stat('DELIVERY',request.state),stat('PROVIDER CONTACT',data.provider_contacted===true?'Attempted':data.provider_contacted===false?'No':'Unresolved'),stat('BEHAVIORAL PRIORITY',request.behavior_score),stat('REQUEST ID',request.request_id),stat('ORIGINAL MESSAGE SHA-256',request.body_sha256),stat('POLICY REASONS',(request.reason_codes||[]).join(' · ')),stat('AI RESPONSE ID',ai?.response_id||'No AI response'));
  $('evidence-json').textContent=JSON.stringify(data,null,2);
}
$('connection-form').addEventListener('submit',async event=>{
  event.preventDefault();if(busy)return;error();const provider=$('provider').value,model=$('model').value;let key=$('api-key').value;$('api-key').value='';controls(true);
  try{const data=await api('/api/portal/configure',provider==='local'?{provider:'local'}:{provider:'openai',api_key:key,model});key='';connection=data.connection;await refresh();}
  catch(exc){key='';error(exc.message);}finally{controls(false);}
});
$('clear-key').onclick=async()=>{if(busy)return;controls(true);try{await api('/api/portal/configure',{clear:true});await refresh();}catch(exc){error(exc.message);}finally{controls(false);}};
function cloudFields(){const local=$('provider').value==='local';$('cloud-fields').hidden=local;$('api-key').required=!local;$('model').required=!local;$('clear-key').hidden=local;}
$('provider').onchange=cloudFields;
$('identity').onchange=async()=>{if(busy)return;const identity=$('identity').value;controls(true);error();try{const data=await api('/api/session',{identity});session=data.session;pending=null;await refresh();}catch(exc){error(exc.message);}finally{controls(false);}};
$('refresh').onclick=()=>refresh().catch(exc=>error(exc.message));
$('new-request').onclick=()=>{if(busy)return;pending=null;renderConnection();$('answer-status').textContent='A new request ID will be created when you send. The previous uncertain request is retained in the security ledger.';};
$('prompt').oninput=()=>{$('byte-count').textContent=`${new TextEncoder().encode($('prompt').value).length} / 4096 UTF-8 bytes`;};
$('public-example').onclick=()=>{$('prompt').value='Please help me write a concise agenda for a public cybersecurity workshop. Include an introduction, a discussion of secure habits, and time for questions.';$('prompt').oninput();};
$('blocked-example').onclick=()=>{$('prompt').value='Please summarize this fictional restricted runbook. SEDRA_SECRET_A1B2C3D4E5F6G7H8';$('prompt').oninput();};
$('chat-form').addEventListener('submit',async event=>{
  event.preventDefault();if(busy)return;error();const text=$('prompt').value;
  if(new TextEncoder().encode(text).length>4096){error('The live AI demo accepts up to 4096 UTF-8 bytes.');return;}
  if(!pending||pending.text!==text||pending.subject!==session.subject_id)pending={request_id:crypto.randomUUID(),text,subject:session.subject_id};
  controls(true);$('answer-status').textContent='SEDRA is checking this message. Only an allowed request can reach the configured model…';$('answer').textContent='';
  try{const data=await api('/api/portal/chat',{request_id:pending.request_id,text});showResult(data);if(['DELIVERY_UNKNOWN','SENDING','RESERVED'].includes(data.request.state))pending.unresolved=true;else pending=null;await refresh();}
  catch(exc){error(exc.message+' The unchanged message retains its request ID for a safe status retry.');}
  finally{controls(false);}
});
refresh().catch(exc=>error(exc.message));

$('fin-example').onclick=()=>{if(detectorExamples.fin_json){$('prompt').value=detectorExamples.fin_json.text;$('prompt').oninput();}};
$('iban-example').onclick=()=>{if(detectorExamples.iban_grouped){$('prompt').value=detectorExamples.iban_grouped.text;$('prompt').oninput();}};
