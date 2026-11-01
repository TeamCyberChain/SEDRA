/* SEDRA local demo UI. No dependencies, external requests, or fabricated metrics. */
"use strict";

let selectedAsset = null;
let labelDraftDirty = false;

function sensitivityBadge(value) {
  const level = ['restricted','confidential','public','unclassified'].includes(value) ? value : 'unclassified';
  return `<span class="sensitivity ${level}"><i aria-hidden="true"></i>${esc(titleCase(level))}</span>`;
}

function securityTagsHTML(tags) {
  if (!tags) return '<p class="scope-note">Historical request: governed label snapshot unavailable.</p>';
  return `<section class="request-classification"><h3 class="mini-heading">Content classification</h3><div class="tag-row">${sensitivityBadge(tags.sensitivity)}${array(tags.detector_tags).map(t=>`<span class="data-tag detector">${esc(titleCase(t))}</span>`).join('')}${array(tags.business_tags).map(t=>`<span class="data-tag">${esc(t)}</span>`).join('')}</div><p class="scope-note">${esc(tags.basis)} · frozen at admission. ${tags.sensitivity==='unclassified'?'No eligible protected match is not proof that data is public.':''}</p></section>`;
}

function renderDataTypes(){
  const catalog=state?.data_types;
  if(!catalog)return;
  $('detector-summary').textContent=`${catalog.rules.length} controls · ${catalog.iban_registry.country_count} IBAN formats`;
  $('detector-profile').innerHTML=`<span class="data-tag">${esc(catalog.profile)}</span><p class="scope-note">SWIFT registry ${esc(catalog.iban_registry.release)} · ${esc(catalog.iban_registry.date)}. Deterministic checks; no AI confidence score or external account lookup. JSON depth limit: ${catalog.limits.max_json_depth}; Base64: one bounded decode.</p>`;
  $('detector-rows').innerHTML=catalog.rules.map(rule=>`<tr><td><strong>${esc(rule.name)}</strong><span class="table-subline">${esc(rule.category)}</span></td><td><span class="sensitivity restricted">${esc(rule.action)}</span></td><td>${esc(rule.checks)}</td><td class="rule-scope">${esc(rule.scope)}</td></tr>`).join('');
  const previous=$('datatype-example').value;
  $('datatype-example').innerHTML=Object.entries(catalog.examples).map(([key,example])=>`<option value="${esc(key)}">${esc(example.label)}</option>`).join('');
  if(catalog.examples[previous])$('datatype-example').value=previous;
}

function renderInventory() {
  if (!state) return;
  const docs = array(state.documents), query = $('inventory-search').value.toLowerCase(), filter = $('inventory-filter').value;
  const selected = docs.filter(d=> (filter==='all'||d.metadata?.sensitivity===filter) && JSON.stringify([d.id,d.title,d.metadata?.owner,d.metadata?.business_tags]).toLowerCase().includes(query));
  const count = level => docs.filter(d=>d.metadata?.sensitivity===level).length;
  $('inventory-counts').innerHTML = [['Registered assets',docs.length,'Fixed synthetic corpus'],['Restricted',count('restricted'),'Hard policy on recognized matches'],['Confidential',count('confidential'),'Cumulative exposure controls'],['Detected data types',new Set(docs.flatMap(d=>d.metadata?.detector_tags||[])).size,'Structured rules · no raw values']].map(([label,value,note])=>`<article class="metric-card"><div class="metric-label">${esc(label)}</div><div class="metric-number">${value}</div><div class="metric-footnote">${esc(note)}</div></article>`).join('');
  $('inventory-total').textContent = `${selected.length} / ${docs.length} assets`;
  $('inventory-rows').innerHTML = selected.length ? selected.map(d=>{const m=d.metadata||{};return `<tr class="${selectedAsset===d.id?'selected':''}"><td><button class="asset-link" data-asset="${esc(d.id)}">${esc(d.title)}</button><span class="table-subline">${esc(d.id)} · v${esc(d.version)} · ${esc(d.language.toUpperCase())}</span></td><td>${sensitivityBadge(m.sensitivity)}</td><td>${esc(m.owner)}</td><td><div class="tag-row">${array(m.business_tags).map(t=>`<span class="data-tag">${esc(t)}</span>`).join('')}</div></td><td>${array(m.detector_tags).length?array(m.detector_tags).map(t=>`<span class="data-tag detector">${esc(titleCase(t))}</span>`).join(''):'<span class="subtle">No structured finding</span>'}</td><td><button class="text-button" data-asset="${esc(d.id)}" aria-label="Inspect metadata for ${esc(d.title)}">Inspect ↗</button><span class="table-subline">Revision ${m.revision??0}</span></td></tr>`;}).join('') : '<tr><td colspan="6" class="empty-state">No assets match these filters.</td></tr>';
  const history=array(state.label_history);
  $('label-history').innerHTML = !isAnalyst()?'<p class="scope-note padded">Label governance history is available to the local Analyst role.</p>':history.length?`<div class="table-scroll"><table class="asset-table"><thead><tr><th>Asset</th><th>Change</th><th>Revision / actor</th><th>Time</th></tr></thead><tbody>${history.slice(0,20).map(h=>`<tr><td>${esc(h.doc_id)}</td><td>${esc(h.before.sensitivity)} → ${esc(h.after.sensitivity)}<span class="table-subline">${esc(h.after.change_reason)} · metadata updated</span></td><td>r${h.revision} · ${esc(h.actor)}</td><td>${esc(dateTime(h.at))}</td></tr>`).join('')}</tbody></table></div>`:'<p class="scope-note padded">No analyst label changes have been recorded.</p>';
  if (!labelDraftDirty && !$('asset-inspector').contains(document.activeElement)) renderAssetInspector();
}

function renderAssetInspector() {
  const doc=array(state.documents).find(d=>d.id===selectedAsset), target=$('asset-inspector');
  target.hidden=!doc;
  if(!doc)return;
  const m=doc.metadata, editable=isAnalyst(), choices=doc.classification==='controlled_excerpt'?['confidential','restricted']:[m.registered_sensitivity_floor];
  target.innerHTML=`<div class="panel-heading"><div><div class="eyebrow">ASSET METADATA</div><h2>${esc(doc.title)}</h2><p>${esc(doc.id)} · source v${esc(doc.version)} · label revision ${m.revision}</p></div><button class="text-button" id="close-asset">Close inspector ×</button></div><div class="asset-inspector-grid"><div class="metadata-fields"><h3 class="mini-heading">Source & discovery</h3>${[['Sensitivity floor',m.registered_sensitivity_floor],['Label authority',m.label_source],['Source system',m.source_system],['Media type',m.media_type],['UTF-8 bytes',m.utf8_bytes],['Handling',m.handling],['Last changed',m.updated_at?dateTime(m.updated_at):'Initial registration'],['Changed by',m.updated_by]].map(([k,v])=>`<div class="detail-row"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')}<div class="source-hash"><span>SHA-256 / ORIGINAL CONTENT</span><code>${esc(m.source_sha256)}</code></div><p class="scope-note">${esc(m.discovery_scope)}. Detector tags show types only; no detected values are exposed.</p></div><form id="label-form" data-doc-id="${esc(doc.id)}" data-revision="${m.revision}"><h3 class="mini-heading">Governed labels</h3><label for="label-sensitivity">Sensitivity</label><select id="label-sensitivity" ${editable?'':'disabled'}>${choices.map(v=>`<option ${m.sensitivity===v?'selected':''} value="${v}">${titleCase(v)}</option>`).join('')}</select><label for="label-owner">Data owner</label><select id="label-owner" ${editable?'':'disabled'}>${state.label_schema.owners.map(v=>`<option ${m.owner===v?'selected':''}>${esc(v)}</option>`).join('')}</select><fieldset ${editable?'':'disabled'}><legend>Business tags</legend><div class="tag-options">${state.label_schema.business_tags.map(v=>`<label><input type="checkbox" name="business-tag" value="${esc(v)}" ${m.business_tags.includes(v)?'checked':''}>${esc(v)}</label>`).join('')}</div></fieldset><label for="label-reason">Change reason</label><select id="label-reason" ${editable?'':'disabled'}><option value="DATA_OWNER_REVIEW">Data owner review</option><option value="POLICY_REVIEW">Policy review</option><option value="DEMO_VALIDATION">Demo validation</option></select><p id="label-save-note" class="scope-note" role="status"></p><button class="button primary" type="submit" ${editable?'':'disabled'}>Save governed labels</button><p class="scope-note">${editable?'Restricted blocks recognized protected matches on new admissions. Existing request snapshots remain unchanged. Registered sensitivity floors cannot be weakened.':'Select Analyst to manage labels. Employee access is read-only.'}</p></form></div>`;
}

const icons = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  investigate: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5M8 11h5M10.5 8.5v5"/>',
  boundary: '<path d="M13 3v18M4 8h6M4 16h6M17 12h5m-3-3 3 3-3 3"/><circle cx="3" cy="8" r="1"/><circle cx="3" cy="16" r="1"/>',
  arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
  refresh: '<path d="M3 12a9 9 0 0 1 15.36-6.36L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15.36 6.36L3 16"/><path d="M8 16H3v5"/>',
  reset: '<path d="M3 4v6h6M3 10a9 9 0 1 1 1 8M12 7v5l3 2"/>',
  flask: '<path d="M9 3h6m-5 0v6L4 19a1.4 1.4 0 0 0 1.3 2h13.4a1.4 1.4 0 0 0 1.3-2L14 9V3M7 15h10M10 18h.01M14 17h.01"/>',
  shield: '<path d="m12 3 8 4v6c0 4-4 7-8 9-4-2-8-5-8-9V7l8-4Z"/><path d="m8 12 3 3 5-6"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
  document: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-6-6Z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>',
  send: '<path d="m3 3 19 9-19 9 4-9-4-9Zm4 9h15"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  block: '<circle cx="12" cy="12" r="9"/><path d="m6 6 12 12"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
  activity: '<path d="M2 12h5l3-8 4 16 3-8h5"/>',
  bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>'
};
const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] || icons.info}</svg>`;
const number = value => typeof value === "number" && Number.isFinite(value);
const display = value => value === null || value === undefined ? "—" : typeof value === "object" ? JSON.stringify(value) : String(value);
const score = value => number(value) ? new Intl.NumberFormat("en", {maximumFractionDigits:1}).format(value) : "—";
const titleCase = value => String(value ?? "").replace(/[_-]+/g, " ").replace(/\b\w/g, char => char.toUpperCase());
const array = value => Array.isArray(value) ? value : value ? [value] : [];
const shortId = value => String(value ?? "—").length > 18 ? `${String(value).slice(0,8)}…${String(value).slice(-6)}` : String(value ?? "—");
const percent = value => number(value) ? `${(value * 100).toFixed(1)}%` : "—";
const ratioWidth = value => number(value) ? Math.min(100, Math.max(0, value * 100)) : 0;
const dateTime = value => {
  if (!value) return "Time not supplied";
  const parsed = new Date(typeof value === "number" && value < 1e12 ? value * 1000 : value);
  if (!Number.isFinite(parsed.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-GB", {day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit",second:"2-digit",timeZone:"Asia/Baku"}).format(parsed) + " AZT";
};

let state = null;
const alertPageId = location.pathname === '/alert' ? new URLSearchParams(location.search).get('id') : null;
if(alertPageId){document.body.classList.add('alert-page');document.querySelector('#view-alerts h1').textContent='Alert investigation';}
let selectedTab = "overview";
let selectedSubject = new URLSearchParams(location.search).get('subject');
let analysisSource = "lab";
let selectedDocument = null;
let openedDocument = null;
let activeRequest = null;
let initialRequestId = new URLSearchParams(location.search).get('request');
let pendingTransfer = null;
let loading = false;
let mutating = false;
let toastTimer = null;
let lastLoaded = null;
let refreshWaiters = [];

function waitForRefresh() {
  return loading ? new Promise(resolve => refreshWaiters.push(resolve)) : Promise.resolve();
}

function installIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach(node => { node.innerHTML = icon(node.dataset.icon); });
}

function notify(message) {
  $("toast").textContent = message;
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $("toast").hidden = true; }, 5000);
}

function showError(message) {
  $("error-banner").textContent = message || "";
  $("error-banner").hidden = !message;
}

async function api(path, body) {
  const options = {credentials:"same-origin",headers:{"Accept":"application/json"},cache:"no-store"};
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = state?.session?.csrf_token || "";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let result;
  try { result = await response.json(); } catch (_) { throw new Error(`The server returned an unreadable response (${response.status}).`); }
  if (!response.ok) {
    const detail = result.error?.message ?? result.error ?? result.message ?? `Request failed (${response.status})`;
    const error=new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    error.status=response.status;throw error;
  }
  return result;
}

function isAnalyst() {
  return state?.session?.role === "analyst" || state?.session?.subject_id === "analyst";
}

function canTransfer() {
  return Boolean(state?.session?.subject_id) && !isAnalyst();
}

function currentBenchmark() {
  return analysisSource === 'cert-v2' ? state?.benchmark_v2 : state?.benchmark;
}

function benchmarkMeasured() {
  return isAnalyst() && ["measured","measured_development"].includes(currentBenchmark()?.status);
}

function usingBenchmark() {
  return analysisSource !== "lab" && benchmarkMeasured();
}

function analysisSubjects() {
  return array(usingBenchmark() ? currentBenchmark()?.subjects : state?.subjects);
}

function analysisEvaluation() {
  return (usingBenchmark() ? currentBenchmark()?.evaluation : state?.evaluation) || {};
}

function analysisTimestamp(value, compact = false) {
  if (!usingBenchmark()) return value ? dateTime(value) : "Completed user-day";
  if (!value) return "Completed benchmark user-day";
  const literal = String(value).replace("T", " ");
  return compact ? `${literal.slice(0,10)} · dataset local` : `${literal} · dataset-local time`;
}

function ensureAnalysisSelection() {
  if (analysisSource !== "lab" && !benchmarkMeasured()) analysisSource = "lab";
  const subjects = analysisSubjects();
  if (!subjects.some(subject => subject.subject_id === selectedSubject)) selectedSubject = subjects[0]?.subject_id || null;
}

function renderSourceContext() {
  ensureAnalysisSelection();
  const benchmark = currentBenchmark() || {};
  const status = benchmark.status || "unavailable";
  const cert = usingBenchmark() && selectedTab !== "lab";
  $("provenance-badge").innerHTML = `${icon("document")}${esc(cert ? `${benchmark.dataset || "CERT r4.2"} · published synthetic benchmark` : "Sample workspace · recorded activity")}`;
  $("provenance-badge").classList.toggle("benchmark-provenance",cert);
  const research = state?.benchmark_v2 || {};
  const downloaded = research.expected_source_bytes ? Math.min(100,100*(research.source_download_bytes || 0)/research.expected_source_bytes) : 0;
  const researchLabel = research.status === "measured_development" ? "development result" : research.progress?.status === "failed" ? "research needs attention" : research.progress?.stage === "downloading_official_archive" ? `source intake ${downloaded.toFixed(1)}% / not evaluated` : titleCase(research.progress?.stage || "awaiting verified run");
  $("benchmark-status-note").textContent = isAnalyst() ? `CERT v1: failed gate · v2: ${researchLabel}` : "Historical benchmark · Analyst role";
  $("benchmark-status-note").title = display(benchmark.measurement_status || benchmark.message || "");
  $("data-source-controls").hidden = !isAnalyst();
  const option = $("data-source-select").querySelector('option[value="cert"]');
  option.disabled = state?.benchmark?.status !== "measured";
  const v2option = $("data-source-select").querySelector('option[value="cert-v2"]');
  if (v2option) {
    v2option.disabled = state?.benchmark_v2?.status !== "measured_development";
    v2option.textContent = v2option.disabled ? "CERT v2 · awaiting verified run" : "CERT v2 · multichannel development";
  }
  option.textContent = "CERT v1 · file-only / failed gate";
  $("data-source-select").value = usingBenchmark() ? analysisSource : "lab";
  $("data-source-select").disabled = mutating;
  $("data-source-context").textContent = usingBenchmark()
    ? "Historical public synthetic research data. V1 uses active copy days. V2 uses four-channel calendar days and remains development evidence. These are separate from live identities."
    : "Generated behavioral context with actual local document-access and transfer activity.";
  $("investigation-source-description").textContent = usingBenchmark()
    ? "Inspect historical benchmark signals, their completed-day context, and available source evidence."
    : "Connect behavioral signals to their source context and transfer history.";
}

function setBusy(value, buttonId) {
  mutating = value;
  $("live-burst").disabled = value || !canTransfer();
  $("run-mosaic").disabled = value || state?.session?.subject_id !== "lab-001";
  $("load-judge-example").disabled = value;
  if (buttonId) $(buttonId).disabled = value;
  $("identity-select").disabled = value || Boolean(state?.session?.principal);
  $("reset-demo").disabled = value || !isAnalyst();
  $("send-transfer").disabled = value || !canTransfer() || !$("transfer-text").value.trim();
  $("open-document").disabled = value || !selectedDocument;
  $("fill-protected").disabled = value || !selectedDocument;
  $("document-select").disabled = value;
  $("data-source-select").disabled = value;
  document.querySelectorAll(".fragment-button").forEach(button => { button.disabled = value; });
  document.querySelectorAll('[data-ueba-scenario]').forEach(button=>{
    button.disabled=value||!canTransfer()||button.dataset.uebaScenario!==state?.session?.subject_id;
  });
  document.querySelectorAll('[data-endpoint-action]').forEach(button=>{button.disabled=value||!isAnalyst();});
}

async function loadState({silent = false} = {}) {
  if (loading) return waitForRefresh();
  loading = true;
  $("refresh-state").disabled = true;
  try {
    const previousRole = state?.session?.role;
    state = await api("/api/state");
    if(previousRole && previousRole!==state.session.role)labelDraftDirty=false;
    document.body.classList.remove("session-required");
    $("session-signin").hidden=true;
    lastLoaded = new Date();
    ensureAnalysisSelection();
    if (!selectedDocument || !array(state.documents).some(d => d.id === selectedDocument)) {
      selectedDocument = array(state.documents)[0]?.id || null;
      openedDocument = null;
    }
    if(initialRequestId){activeRequest=array(state.requests).find(r=>r.request_id===initialRequestId)||null;initialRequestId=null;}
    else if (activeRequest?.request_id) activeRequest = array(state.requests).find(r => r.request_id === activeRequest.request_id) || null;
    $("connection-status").classList.remove("offline");
    $("connection-status").innerHTML = '<span class="status-dot"></span>Gateway connected';
    showError("");
    render();
  } catch (error) {
    if(error.status===401){state=null;if(window.SedraAudit)window.SedraAudit.sync();document.body.classList.add("session-required");$("session-signin").hidden=false;$("identity-select").disabled=true;if(window.SedraIntegrations)window.SedraIntegrations.sync();}
    $("connection-status").classList.add("offline");
    $("connection-status").innerHTML = '<span class="status-dot"></span>Connection unavailable';
    if (!silent || !state) showError(error.message);
  } finally {
    loading = false;
    $("refresh-state").disabled = false;
    const waiters = refreshWaiters;
    refreshWaiters = [];
    waiters.forEach(resolve => resolve());
  }
}

function changeTab(tab, updateHash = true) {
  if(state&&!isAnalyst()&&['alerts','integrations','audit'].includes(tab))tab='overview';
  if(tab==='audit'){window.SedraSettings?.open('audit');tab='overview';}
  if(tab==="transfers")tab="lab";
  if (!["overview","alerts","investigation","inventory","lab","integrations","audit"].includes(tab)) tab = "overview";
  if(alertPageId && updateHash){location.assign('/#'+(tab==='lab'?'transfers':tab));return;}
  selectedTab = tab;
  if (updateHash) window.scrollTo({top:0,behavior:"instant"});
  document.querySelectorAll(".view").forEach(view => { view.hidden = view.id !== `view-${tab}`; });
  document.querySelectorAll("[data-tab]").forEach(button => {
    const active = button.dataset.tab === tab;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  $("breadcrumb-current").textContent = {overview:"Overview",investigation:"UEBA",lab:"Transfer Control",inventory:"Data Inventory",alerts:alertPageId?"Alert investigation":"Alerts",integrations:"Identity & integrations",audit:"Audit Logs"}[tab];
  if (updateHash) history.replaceState(null, "", `/#${tab==="lab"?"transfers":tab}`);
  if (state) {
    renderSourceContext();
    if (tab === "investigation") renderInvestigation();
    if (tab === "lab") renderLab();
    if (tab === "inventory") renderInventory();
    if (tab === "alerts" && typeof renderAlerts === "function") renderAlerts();
    if(tab==='audit' && window.SedraAudit){window.SedraAudit.sync();window.SedraAudit.load();}
    if(tab==='integrations' && window.SedraIntegrations)window.SedraIntegrations.refresh();
  }
}

function syncNavigationAccess() {
  const analyst=isAnalyst();
  document.querySelectorAll('[data-tab="alerts"],[data-tab="integrations"]').forEach(n=>{n.hidden=!analyst;});
  const evaluationPanel=$('evaluation-content')?.closest('.panel');if(evaluationPanel)evaluationPanel.hidden=!analyst;
  if(!analyst&&['alerts','integrations','audit'].includes(selectedTab)){
    document.body.classList.remove('alert-page');changeTab('overview',false);
  }
}

function render() {
  syncNavigationAccess();
  const identity = isAnalyst() ? "analyst" : state.session?.subject_id || "analyst";
  $("identity-select").closest(".identity-control").hidden=Boolean(state.session?.principal);
  $("identity-select").value = identity;
  $("identity-select").disabled = Boolean(state.session?.principal);
  document.querySelector('label[for="identity-select"]').textContent=state.session?.principal?"SSO identity":"Active identity";
  $("snapshot-time").textContent = `Refreshed ${dateTime(lastLoaded.toISOString())}`;
  renderSourceContext();
  renderOverview();
  $('governance-summary').innerHTML=['restricted','confidential','public'].map(level=>`<div class="governance-row">${sensitivityBadge(level)}<strong>${array(state.documents).filter(d=>d.metadata?.sensitivity===level).length}</strong></div>`).join('')+'<p class="scope-note">Registered synthetic text only. Analyst changes are revisioned; admitted requests retain their original labels.</p>';
  renderSubjectOptions();
  renderDocumentOptions();
  renderInvestigation(true);
  renderLab();
  renderInventory();
  renderDataTypes();
  if(typeof syncAlertSession === "function") syncAlertSession();
  if(window.SedraAudit)window.SedraAudit.sync();
  if(window.SedraIntegrations){window.SedraIntegrations.sync();if(selectedTab==='integrations')window.SedraIntegrations.refresh();}
  $("send-transfer").disabled = mutating || !canTransfer() || !$("transfer-text").value.trim();
  $("reset-demo").disabled = mutating || !isAnalyst();
  $("reset-demo").title = isAnalyst() ? "Clear the local demo ledger, receiver, and application events" : "Select Analyst to reset the local demo";
}

function scoreCell(value) {
  const width = number(value) ? Math.min(100, Math.max(0, value)) : 0;
  const tone = width >= 70 ? "hot" : width >= 40 ? "warm" : "";
  return `<div class="score-cell"><span class="score-number">${score(value)}</span><div class="score-track" aria-hidden="true"><span class="score-fill ${tone}" style="width:${width}%"></span></div></div>`;
}

function renderOverview() {
  const cert = usingBenchmark();
  const evaluation = analysisEvaluation();
  const counts = cert ? {
    training:evaluation.split?.train_user_days,
    validation:evaluation.split?.validation_user_days,
    testing:evaluation.split?.test_user_days,
    subjects:analysisSubjects().length
  } : state.counts || {};
  const metrics = cert ? [
    ["training","Training user-days","document","Earlier chronological partition"],
    ["validation","Validation user-days","activity","Calibration and operating points"],
    ["testing","Test user-days","shield","Later chronological partition"],
    ["subjects","Scored subjects shown","user","Latest available completed context"]
  ] : [
    ["attempted","Transfer attempts","activity","Recorded by the gateway"],
    ["forwarded","Forwarded","send","Confirmed delivery state"],
    ["blocked","Blocked","block","Stopped at the boundary"],
    ["unknown","Unconfirmed","clock","Requires reconciliation"]
  ];
  $("overview-counts").setAttribute("aria-label",cert ? "Historical benchmark support" : "Workspace transfer counters");
  $("live-control-panel").hidden = cert;
  $("live-activity-panel").hidden = cert;
  $("overview-primary-grid").classList.toggle("benchmark-layout",cert);
  $("overview-lower-grid").classList.toggle("benchmark-layout",cert);
  $("risk-source-description").textContent = cert ? "Historical benchmark rows, ordered by priority. V2 shows each displayed subject's highest-scored test day. Dates retain dataset-local time." : "Completed-day model plus separately explained live application signals.";
  $("evaluation-scope").textContent = cert ? (currentBenchmark().dataset || "CERT benchmark") : "Sample dataset";
  $("overview-counts").innerHTML = metrics.map(([key,label,iconName,note]) => `<div class="metric-card ${key}"><div class="metric-label">${label}${icon(iconName)}</div><div class="metric-number">${esc(display(counts[key]))}</div><div class="metric-footnote">${note}</div></div>`).join("");
  const subjects = [...analysisSubjects()].sort((a,b) => (b.behavior_score ?? -1) - (a.behavior_score ?? -1));
  $("subject-count").textContent = `${subjects.length} subject${subjects.length === 1 ? "" : "s"}`;
  $("risk-empty").hidden = subjects.length > 0;
  $("risk-rows").innerHTML = subjects.map(subject => `<tr><td><div class="subject-cell"><span class="avatar">${esc(String(subject.subject_id).slice(-2).toUpperCase())}</span><span><span class="subject-name">${esc(subject.subject_id)}</span><span class="subject-asof">${esc(analysisTimestamp(subject.as_of || subject.date,true))}</span></span></div></td><td class="context-cell">${esc(subject.role || "Role not supplied")}${subject.live_context?.score ? `<span class="subject-asof">Live rule: ${subject.live_context.score}</span>` : ""}</td><td>${scoreCell(subject.behavior_score)}</td><td>${scoreCell(number(subject.rule_score) ? subject.rule_score * 100 : null)}</td><td>${scoreCell(number(subject.ml_score) ? subject.ml_score * 100 : null)}</td><td><button class="review-button" data-investigate="${esc(subject.subject_id)}" data-source="${cert ? analysisSource : "lab"}" aria-label="Investigate ${esc(subject.subject_id)}">${icon("arrow")}</button></td></tr>`).join("");
  const recent = [...array(state.requests)].sort(newestFirst).slice(0,4);
  $("overview-requests").innerHTML = recent.length ? recent.map(request => {
    const tone = decisionTone(request);
    return `<div class="compact-request"><span class="status-icon ${tone}">${icon(tone === "red" ? "block" : tone === "amber" ? "clock" : "send")}</span><div class="compact-request-body"><button data-request="${esc(request.request_id)}"><span class="request-title">${esc(request.subject_id)} <span style="color:#a3af9b;font-weight:400">→</span> ${esc(request.destination || "public_ai")}</span></button><span class="request-time">${esc(dateTime(request.created_at))}</span></div>${badge(request.decision)}${badge(requestState(request),true)}</div>`;
  }).join("") : '<div class="empty-state inline">No gateway requests yet. Open Transfer Control to start the evidence trail.</div>';
  const comparisons = Object.entries(evaluation.comparisons || {});
  const comparisonTable = comparisons.length ? `<div class="evaluation-table-wrap"><table class="evaluation-table"><thead><tr><th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>${comparisons.map(([name,metrics]) => `<tr><th>${esc(name === "isolation_forest" ? "Isolation Forest" : titleCase(name))}</th><td>${metrics.alert_count === 0 ? "—" : percent(metrics.precision)}</td><td>${percent(metrics.recall)}</td><td>${percent(metrics.f1)}</td></tr>`).join("")}</tbody></table></div>` : "";
  const split = evaluation.split;
  const support = comparisons[0]?.[1];
  const splitDetail = split ? `<div class="evaluation-row"><span>Chronological user-days</span><strong>${esc(split.train_user_days)} train · ${esc(split.validation_user_days)} validation · ${esc(split.test_user_days)} test</strong></div><div class="evaluation-row"><span>Test interval</span><strong>${esc(split.test_start)} → ${esc(split.test_end)}</strong></div>` : "";
  const supportDetail = support ? `<div class="evaluation-row"><span>${cert && String(evaluation.label_provenance || "").includes("actor_interval") ? "Incident-associated positive user-days" : "Labeled positive user-days"}</span><strong>${esc(display(support.positive_user_days))} / ${esc(display(support.test_user_days))}</strong></div>` : "";
  const workloadDetail = comparisons.length ? `<div class="eval-extra">${comparisons.map(([name,m])=>`<div><b>${esc(titleCase(name))}</b>: TP ${m.confusion_matrix?.tp ?? "—"}, FP ${m.confusion_matrix?.fp ?? "—"}, FN ${m.confusion_matrix?.fn ?? "—"} · ${score(m.alerts_per_100_user_days)} alerts / 100 user-days · AP ${m.average_precision == null ? "—" : m.average_precision.toFixed(4)}</div>`).join("")}</div>` : "";
  const coverageDetail = evaluation.incident_coverage?.combined ? `<div class="eval-extra"><b>Coverage-adjusted incident recall</b>: ${evaluation.incident_coverage.combined.detected_incidents_on_exact_positive_days}/${evaluation.incident_coverage.combined.denominator_incidents}<br>Denominator retains incidents without modeled observables.</div>` : "";
  const selection = evaluation.dataset_selection;
  const selectionDetail = cert && selection ? `<div class="evaluation-row"><span>Population</span><strong>${esc(display(selection.population))}</strong></div><div class="evaluation-row"><span>Selected users</span><strong>${esc(display(selection.selected_users))} / ${esc(display(selection.available_users))}</strong></div>` : "";
  const failedGate = cert && comparisons.length > 0 && comparisons.every(([,m]) => m.positive_user_days > 0 && m.confusion_matrix?.tp === 0);
  const note = cert
    ? `${failedGate ? "Detection gate not passed: this baseline detected zero positive test days. " : ""}${currentBenchmark().dataset || "CERT r4.2"}: historical evaluation on a published synthetic research dataset. V2 uses a previously inspected release and cannot establish independent efficacy. Inspect the selected population and label definition with these results.`
    : `Controlled sample-data results.${["measured","measured_development"].includes(currentBenchmark()?.status) ? " The separate CERT evaluation is available in the data-source selector." : ` CERT status: ${titleCase(currentBenchmark()?.status || "unavailable")}.`}`;
  $("evaluation-content").innerHTML = `<div class="evaluation-note">${esc(note)}</div>` + comparisonTable + workloadDetail + coverageDetail + splitDetail + supportDetail + selectionDetail + (Object.keys(evaluation).length ? `<details class="evaluation-json"><summary>Inspect methodology, operating points & evidence</summary><pre>${esc(JSON.stringify(evaluation,null,2))}</pre></details>` : '<div class="empty-state inline">No evaluation results have been supplied by the server.</div>');
}

function renderSubjectOptions() {
  $("subject-select").innerHTML = analysisSubjects().map(s => `<option value="${esc(s.subject_id)}">${esc(s.subject_id)} · ${esc(s.role || "subject")}</option>`).join("");
  $("subject-select").value = selectedSubject || "";
}

function featureEntries(features) {
  if (Array.isArray(features)) return features.map((value,index) => typeof value === "object" && value ? [value.name || value.feature || `Feature ${index+1}`,value] : [`Feature ${index+1}`,value]);
  return features && typeof features === "object" ? Object.entries(features) : [];
}

function featureCard([key,raw]) {
  const nested = raw && typeof raw === "object";
  const value = nested ? raw.value ?? raw.observed ?? raw.current ?? raw : raw;
  const caption = nested ? raw.baseline !== undefined ? `Baseline: ${display(raw.baseline)}` : raw.description ?? raw.unit ?? "Observed feature" : "Completed user-day feature";
  return `<div class="feature-card"><div class="feature-name">${esc(titleCase(key))}</div><div class="feature-value">${esc(number(value) ? score(value) : display(value))}</div><div class="feature-caption">${esc(display(caption))}</div></div>`;
}

function reasonCard(reason) {
  if (typeof reason === "string") return `<div class="reason-card"><h3>${esc(reason)}</h3></div>`;
  const title = reason.label || reason.title || reason.feature || reason.code || reason.reason || "Observed signal";
  const detail = reason.explanation || reason.detail || reason.description || reason.evidence;
  const remainder = Object.fromEntries(Object.entries(reason).filter(([key]) => !["label","title","explanation","detail","description","evidence"].includes(key)));
  return `<div class="reason-card"><h3>${esc(titleCase(title))}</h3>${detail ? `<p>${esc(display(detail))}</p>` : ""}${Object.keys(remainder).length ? `<p><code>${esc(JSON.stringify(remainder))}</code></p>` : ""}</div>`;
}

function benchmarkSourceEvidence(subject) {
  const keys = ["dataset_release","operation","source_sha256","source_file","role_provenance","role_snapshot_month","label_provenance","label_evidence_level","episode_id","episode_start","episode_end"];
  const idKeys = Object.keys(subject).filter(key => /(?:source|original|observable|event).*ids?$/i.test(key));
  const selected = [...new Set([...keys,...idKeys])].filter(key => subject[key] !== null && subject[key] !== undefined);
  return `<div class="benchmark-source-evidence"><p class="benchmark-history-note">Historical benchmark; no live app actions attached.</p>${selected.map(key => `<div class="evaluation-row"><span>${esc(titleCase(key))}</span><strong>${esc(display(subject[key]))}</strong></div>`).join("")}${idKeys.length ? "" : '<p class="subtle benchmark-id-note">Original event IDs are not supplied in this aggregated record. Available dataset and episode identifiers are shown above.</p>'}</div>`;
}

function eventDetailHTML(detail) {
  if(!detail || typeof detail!=='object')return `<p>${esc(display(detail))}</p>`;
  return `<dl class="event-details">${Object.entries(detail).map(([key,value])=>`<div><dt>${esc(titleCase(key))}</dt><dd>${esc(typeof value==='boolean'?(value?'Yes':'No'):Array.isArray(value)?value.join(' · '):display(value))}</dd></div>`).join('')}</dl>`;
}

function renderInvestigation(backgroundRefresh=false) {
  // Preserve an analyst's in-progress controls; explicit navigation still renders immediately.
  if(backgroundRefresh && document.activeElement?.matches('.behavior-cases input,.behavior-cases select') &&
     document.activeElement.closest('.behavior-cases').dataset.behaviorSubject===selectedSubject &&
     typeof behaviorEpoch!=='undefined' && behaviorEpoch===state.session.csrf_token+'|'+state.session.role+'|'+state.behavior_cases?.generation){
    const message=$('behavior-operation-message');if(message)message.textContent='Live data refreshed. Move focus outside these controls to update the case view; actions check the current revision.';
    return;
  }
  const cert = usingBenchmark();
  const subject = analysisSubjects().find(s => s.subject_id === selectedSubject);
  if (!subject) { $("investigation-content").innerHTML = '<div class="panel no-data-panel">No subject data is available for this source.</div>'; return; }
  const features = featureEntries(subject.features);
  const reasons = array(subject.reasons);
  const events = cert ? [] : array(state.events).filter(event => event.subject_id === subject.subject_id).sort(newestFirst);
  const requests = cert ? [] : array(state.requests).filter(request => request.subject_id === subject.subject_id).sort(newestFirst);
  const provenance = typeof subject.provenance === "object" ? JSON.stringify(subject.provenance) : subject.provenance || (cert ? currentBenchmark().provenance || "cert_synthetic" : "synthetic_lab");
  const sourceCaption = cert ? `${currentBenchmark().dataset || "CERT r4.2"} · ${provenance} · historical completed-day evaluation` : `${provenance} · completed user-day context`;
  const activityContent = cert ? benchmarkSourceEvidence(subject) : `<div class="event-list">${events.length ? events.slice(0,20).map(event => `<div class="event-row"><span class="event-marker"></span><div class="event-body"><h3>${esc(titleCase(event.kind || event.event_type || "Event"))}</h3>${eventDetailHTML(event.detail ?? event.details)}<time class="event-time">${esc(dateTime(event.timestamp || event.created_at))}</time></div></div>`).join("") : '<div class="empty-state inline">No application events for this subject yet.</div>'}</div>`;
  const historyContent = cert
    ? `<section class="panel investigation-history"><div class="panel-heading"><div><h2>Completed-day source record</h2><p>Historical benchmark evidence as supplied by the server.</p></div><span class="neutral-tag">Read-only benchmark</span></div><div class="benchmark-record"><details class="evidence-json"><summary>Inspect full historical record and available source identifiers</summary><pre>${esc(JSON.stringify(subject,null,2))}</pre></details></div></section>`
    : `<section class="panel investigation-history"><div class="panel-heading"><div><h2>Transfer history</h2><p>Gateway decisions and delivery states for this subject.</p></div><span class="neutral-tag">${requests.length} requests</span></div>${requestList(requests)}</section>`;
  if(typeof rememberCaseExpansion==='function')rememberCaseExpansion();
  $("investigation-content").innerHTML = `
    ${!cert && typeof behaviorCasePanelHTML === "function" ? behaviorCasePanelHTML(subject) : ""}
    <section class="panel"><div class="subject-overview"><div class="subject-identification"><span class="avatar">${esc(String(subject.subject_id).slice(-2).toUpperCase())}</span><div><h2>${esc(subject.subject_id)}</h2><p>${esc(subject.role || "Role not supplied")} · ${esc(analysisTimestamp(subject.as_of || subject.date))}</p></div></div><div class="subject-score-row"><div class="subject-score"><label>B · Effective policy priority</label><strong>${score(subject.behavior_score)}</strong><small>Priority, not probability</small></div><div class="subject-score"><label>R · Completed-day rules</label><strong>${score(number(subject.rule_score) ? subject.rule_score*100 : null)}</strong><small>Displayed on 0–100 scale</small></div><div class="subject-score"><label>A · Completed-day IF tail</label><strong>${score(number(subject.ml_score) ? subject.ml_score*100 : null)}</strong><small>Displayed on 0–100 scale</small></div></div></div><div class="provenance-detail">Source: ${esc(sourceCaption)}</div>${!cert && subject.live_context && !subject.ueba ? liveContextHTML(subject) : ""}</section>
    ${!cert && typeof uebaInvestigationHTML === "function" ? uebaInvestigationHTML(subject) : ""}
    <h2 class="section-label">Observed behavioral features</h2><div class="feature-grid">${features.length ? features.map(featureCard).join("") : '<div class="empty-state">No feature values supplied.</div>'}</div>
    <div class="investigation-columns"><section class="panel"><div class="panel-heading"><div><h2>Completed-day model explanation</h2><p>Evidence returned by the behavioral scoring engine.</p></div><span class="neutral-tag">${reasons.length} signals</span></div><div class="reason-list">${reasons.length ? reasons.map(reasonCard).join("") : '<div class="empty-state inline">No explanatory signals were returned.</div>'}</div></section>
    <section class="panel"><div class="panel-heading"><div><h2>${cert ? "Historical source evidence" : "Application activity"}</h2><p>${cert ? "Dataset provenance and available original identifiers." : "Recorded application events. Separate from the completed-day baseline."}</p></div></div>${activityContent}</section></div>${historyContent}`;
}

function renderDocumentOptions() {
  $("document-select").innerHTML = array(state.documents).map(doc => `<option value="${esc(doc.id)}">${esc(doc.title || doc.id)}</option>`).join("");
  $("document-select").value = selectedDocument || "";
}

function getSelectedDoc() {
  const registered=array(state?.documents).find(doc => doc.id === selectedDocument);
  return openedDocument && openedDocument.id === selectedDocument ? {...openedDocument,metadata:registered?.metadata||openedDocument.metadata} : registered;
}

function renderDocument() {
  const doc = getSelectedDoc();
  $("open-document").disabled = !doc || mutating;
  $("fill-protected").disabled = !doc || mutating;
  if (!doc) {
    $("document-metadata").innerHTML = "";
    $("document-content").innerHTML = '<p>No registered document has been supplied.</p>';
    $("document-fragments").innerHTML = "";
    return;
  }
  const tags = [doc.classification,doc.language,doc.version !== undefined ? `v${doc.version}` : null,doc.token_count !== undefined ? `${doc.token_count} words (estimate)` : null].filter(value => value !== null && value !== undefined);
  $("document-metadata").innerHTML = `<div class="doc-meta">${sensitivityBadge(doc.metadata?.sensitivity || doc.classification)}${tags.slice(1).map(value => `<span class="state-badge neutral">${esc(value)}</span>`).join("")}</div><div class="tag-row">${array(doc.metadata?.business_tags).map(t=>`<span class="data-tag">${esc(t)}</span>`).join('')}</div>`;
  if (openedDocument?.id === selectedDocument) {
    $("document-content").textContent = openedDocument.text || openedDocument.content || "Document text not supplied.";
  } else {
    $("document-content").innerHTML = '<p>Open this document to inspect its actual contents and record an application access event.</p>';
  }
  const fragments = array(doc.fragments);
  $("document-fragments").innerHTML = fragments.length ? '<div class="fragment-heading">Use a documented excerpt</div>' + fragments.map((fragment,index) => `<button class="fragment-button" data-fragment="${index}">${esc(fragment.label || `Excerpt ${index+1}`)}</button>`).join("") : "";
}

function requestState(request) { return request.request_state ?? request.state ?? "not supplied"; }
function reasonsOf(request) { return array(request.reason_codes ?? request.reasoncodes ?? request.reasons); }
function matchesOf(request) { return array(request.matched_documents ?? request.matches); }
function newestFirst(a,b) { return String(b.created_at || b.timestamp || b.received_at || "").localeCompare(String(a.created_at || a.timestamp || a.received_at || "")); }
function decisionTone(request) {
  const text = `${request.decision || ""} ${requestState(request)}`.toLowerCase();
  if (/block|denied|reject/.test(text)) return "red";
  if (/unknown|uncertain|unconfirmed|reserved|pending/.test(text)) return "amber";
  if (/allow|forward|deliver|confirm/.test(text)) return "green";
  return "neutral";
}
function badge(value,isState = false) {
  const text = String(value ?? "Not supplied");
  const lower = text.toLowerCase();
  const tone = /block|denied|reject/.test(lower) ? "red" : /unknown|uncertain|unconfirmed|reserved|pending/.test(lower) ? "amber" : /allow|forward|deliver|confirm/.test(lower) ? "green" : "neutral";
  return `<span class="state-badge ${tone}"${isState ? ' title="Delivery state"' : ' title="Policy decision"'}>${esc(titleCase(text))}</span>`;
}

function renderLab() {
  $("lab-identity-note").classList.toggle("warning", !canTransfer());
  $("lab-identity-note").innerHTML = `${icon(canTransfer() ? "user" : "info")}<span>${canTransfer() ? `Acting as <strong>${esc(state.session.subject_id)}</strong>. The server session determines the subject of each transfer. This identity belongs to the sample workspace.` : state.session.principal?'Administrative review. Sign in with a User account to submit governed transfers.':'Analyst view. Select <strong>lab-001</strong> or <strong>lab-002</strong> in the identity selector to submit a transfer.'}</span>`;
  renderDocument();
  renderDecision();
  renderReceiver();
  const acting = array(state.subjects).find(s => s.subject_id === state.session.subject_id);
  $("live-context").innerHTML = acting ? liveContextHTML(acting) : "";
  $("live-burst").disabled = mutating || !canTransfer();
  $("run-mosaic").disabled = mutating || state.session.subject_id !== "lab-001";
  $("lab-request-history").innerHTML = requestList([...array(state.requests)].sort(newestFirst));
}

function liveContextHTML(subject) {
  const live = subject.live_context || {};
  return `<div class="live-signal"><div><span class="eyebrow">CURRENT POLICY CONTEXT</span><strong>${score(subject.behavior_score)}<small>/100</small></strong></div><p>Daily model applied: <b>${score(subject.model_context?.applied_score ?? subject.completed_day_score ?? subject.behavior_score)}</b> · ${esc(subject.model_context?.status || "dated snapshot")}<br>Live UEBA: <b>${score(live.score || 0)}</b> · ${live.active_rule_ids?.length || 0} active rules<br>${live.protected_document_reads || 0} protected reads / ${live.blocked_attempts || 0} unique blocks in 2m · ${live.sensitive_attempts_30m || 0} sensitive attempts in 30m.</p><span class="neutral-tag">${subject.behavior_score >= 70 ? 'Tighter excerpt limits active' : 'Standard excerpt limits'}</span></div>`;
}

function requestList(requests) {
  if (!requests.length) return '<div class="empty-state">No transfer requests have been recorded.</div>';
  return `<div class="request-list">${requests.map(request => `<article class="request-item"><div class="request-item-row"><div class="request-left"><strong>${esc(request.subject_id)} · ${esc(dateTime(request.created_at))}</strong><span class="request-id">${esc(request.request_id)}</span>${request.security_tags ? `<div class="tag-row">${sensitivityBadge(request.security_tags.sensitivity)}${array(request.security_tags.detector_tags).map(t=>`<span class="data-tag detector">${esc(titleCase(t))}</span>`).join("")}</div>` : ""}</div><div class="request-right"><div class="request-state-pair"><div><span class="ledger-caption">POLICY</span>${badge(request.decision)}</div><div><span class="ledger-caption">DELIVERY</span>${badge(requestState(request),true)}</div></div><button class="text-button" data-request="${esc(request.request_id)}">Inspect ↗</button>${/unknown|uncertain|unconfirmed/i.test(requestState(request)) ? `<button class="text-button" data-reconcile="${esc(request.request_id)}">Reconcile</button>` : ""}</div></div></article>`).join("")}</div>`;
}

function matchCard(match) {
  const title = match.title || match.document_title || match.id || match.doc_id || match.document_id || "Matched document";
  const coverage = match.prospective_coverage ?? match.forwarded_coverage ?? match.coverage ?? match.coverage_ratio;
  const details = [
    ["Attempted",match.attempted_coverage],
    ["Forwarded",match.forwarded_coverage],
    ["Reserved",match.reserved_coverage],
    ["Unknown",match.unknown_coverage]
  ].filter(([,value]) => number(value));
  const stats = [match.denominator !== undefined ? `Fingerprint denominator: ${match.denominator}` : null,match.eligible_match_count !== undefined ? `Eligible matches: ${match.eligible_match_count}` : null,match.confirmed !== undefined ? `Confirmed match: ${match.confirmed ? "yes" : "no"}` : null].filter(Boolean);
  return `<div class="match-card"><div class="match-top"><b>${esc(title)}</b><span>${percent(coverage)}</span></div>${number(coverage) ? `<div class="coverage-track" role="meter" aria-label="Prospective distinct four-gram fingerprint coverage" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${ratioWidth(coverage)}"><div class="coverage-fill" style="width:${ratioWidth(coverage)}%"></div></div>` : ""}<p>Distinct 4-gram fingerprint coverage${match.prospective_coverage !== undefined ? " · prospective" : ""}</p><div class="token-evidence"><span>Anchored token coverage <b>${percent(match.token_prospective_coverage)}</b></span><span>30-day maximum coverage <b>${percent(match.long_prospective_coverage)}</b></span><small>${esc(array(match.evidence_methods).join(" / "))}</small></div>${details.length ? `<p>${details.map(([label,value]) => `${label}: ${percent(value)}`).join(" · ")}</p>` : ""}${stats.length ? `<p>${esc(stats.join(" · "))}</p>` : ""}</div>`;
}

function renderDecision() {
  if (!activeRequest) {
    $("decision-content").innerHTML = `<div class="decision-placeholder"><span>${icon("boundary")}</span><h3>Ready for a request</h3><p>Submit text to see the decision, matched evidence, and actual delivery state.</p></div>`;
    return;
  }
  const request = activeRequest;
  const tone = decisionTone(request);
  const matches = matchesOf(request);
  const reasons = reasonsOf(request);
  const isReplay = request.idempotent_replay;
  const isUnknown = /unknown|uncertain|unconfirmed/i.test(requestState(request));
  const decisionWord = titleCase(request.decision || "Not supplied");
  const trace = array(request.history).map(item => `<span>${esc(titleCase(item.new_state))}</span>`).join("");
  const structured = array(request.structured_findings).map(item => `<div class="structured-finding"><h3>${esc(titleCase(item.type))}</h3><p>${esc(item.category || 'Legacy rule')} · ${esc(item.action || 'BLOCK')} · value masked</p><dl class="event-details"><div><dt>Validation checks</dt><dd>${esc(array(item.validation_checks).join(' · ') || 'Legacy structured detector')}</dd></div><div><dt>Representation</dt><dd>${esc(array(item.representations || item.representation).join(' · '))}</dd></div><div><dt>Unicode normalization</dt><dd>${esc(array(item.normalization_steps).join(' · ') || 'No additional normalization')}</dd></div><div><dt>Canonical value SHA-256</dt><dd>${esc(item.value_sha256)}</dd></div></dl>${item.additional_findings_omitted?'<p>Evidence limit reached; additional findings omitted. The request remains blocked.</p>':''}</div>`).join("");
  const explanation = tone === "red" ? "This request was stopped at the gateway." : isUnknown ? "The policy permitted this request, but delivery acknowledgement is unresolved. Inspect the receiver and reconcile." : tone === "green" ? "Inspect delivery state and receiver evidence below to verify the outcome." : "The gateway returned the state shown below.";
  const rows = [["Original payload SHA-256",`<code class="payload-hash">${esc(request.body_sha256)}</code>`,true],["Original UTF-8 bytes",request.body_bytes],["Delivery state",badge(requestState(request),true),true],["Subject",request.subject_id],["Behavioral priority",score(request.behavior_score)],["24h 4-gram / token limits",`${percent(request.threshold)} / ${percent(request.token_threshold)}`],["30d 4-gram / token limits",`${percent(request.long_threshold)} / ${percent(request.long_token_threshold)}`],["Request ID",request.request_id],["Created",dateTime(request.created_at)]];
  if (isReplay !== undefined) rows.push(["Idempotent replay",isReplay ? "Yes" : "No"]);
  $("decision-content").innerHTML = `<div class="decision-verdict ${tone}"><div class="decision-kicker">POLICY DECISION</div><h3>${icon(tone === "red" ? "block" : isUnknown ? "clock" : "shield")}${esc(decisionWord)}</h3><p>${esc(explanation)}</p></div><div class="detail-rows">${rows.map(([label,value,html]) => `<div class="detail-row"><span>${esc(label)}</span>${html ? value : label === "Request ID" ? `<code>${esc(display(value))}</code>` : `<strong>${esc(display(value))}</strong>`}</div>`).join("")}</div><div class="state-trace">${trace}</div>${structured}${securityTagsHTML(request.security_tags)}<div class="decision-reasons"><h3 class="mini-heading">Policy evidence</h3>${reasons.length ? reasons.map(reason => `<span class="reason-code">${esc(display(reason))}</span>`).join("") : '<p class="subtle">No reason codes supplied.</p>'}${matches.length ? matches.map(matchCard).join("") : '<p class="subtle" style="margin-top:12px">No matched documents returned.</p>'}</div>${isUnknown ? `<button class="button secondary full-width" data-reconcile="${esc(request.request_id)}">${icon("refresh")}Reconcile with receiver</button>` : ""}<details class="evidence-json"><summary>Inspect complete gateway evidence</summary><pre>${esc(JSON.stringify(request,null,2))}</pre></details>`;
}

function renderReceiver() {
  const receipts = [...array(state.receiver)].sort(newestFirst);
  $("receiver-count").textContent = `${receipts.length} received`;
  if (!receipts.length) { $("receiver-content").innerHTML = '<div class="empty-state">The receiver has no recorded deliveries. A blocked request should not create a receipt.</div>'; return; }
  $("receiver-content").innerHTML = `<div class="receiver-grid">${receipts.map(receipt => `<article class="receiver-card"><div class="receiver-top"><strong>${esc(receipt.subject_id || "Subject not supplied")}</strong><span>${esc(dateTime(receipt.received_at))}</span></div><div class="receiver-preview">${esc(receipt.preview ?? receipt.text_preview ?? "Preview not supplied")}</div><div class="proof-hash"><b>REQUEST ${esc(receipt.request_id || "Not supplied")}</b>SHA-256 · ${esc(receipt.sha256 || "Not supplied")}${receipt.utf8_bytes !== undefined ? `<br>UTF-8 bytes · ${esc(receipt.utf8_bytes)}` : ""}</div></article>`).join("")}</div>`;
}

async function openDocument({quiet = false} = {}) {
  if (!selectedDocument) return null;
  const docId = selectedDocument;
  const doc = await api(`/api/document?id=${encodeURIComponent(docId)}`);
  const metadata = array(state.documents).find(item => item.id === docId) || {};
  const loaded = {...metadata,...(doc.document || doc),id:docId};
  if (selectedDocument === docId) openedDocument = loaded;
  renderDocument();
  await loadState({silent:true});
  if (!quiet) notify("Document opened. The server recorded this application access.");
  return loaded;
}

function fillText(text) {
  $("transfer-text").value = String(text || "");
  updateText();
  $("transfer-text").focus();
}

function updateText() {
  const length = $("transfer-text").value.length;
  $("character-count").textContent = `${new Intl.NumberFormat("en").format(length)} character${length === 1 ? "" : "s"}`;
  $("send-transfer").disabled = mutating || !canTransfer() || !$("transfer-text").value.trim();
}

async function fillFragment(index = 0) {
  try {
    const doc = await openDocument({quiet:true});
    const fragments = array(doc?.fragments);
    const fragment = fragments[index];
    const text = typeof fragment === "string" ? fragment : fragment?.text;
    if (!text) throw new Error("This document has no text for that excerpt. Open it and select the content you want to test.");
    fillText(text);
    notify("Document access recorded. The selected excerpt is ready to submit.");
  } catch (error) { showError(error.message); }
}

function makeRequestId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = [...bytes].map(x => x.toString(16).padStart(2,"0")).join("");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

async function transfer() {
  const text = $("transfer-text").value;
  if (!canTransfer() || !text.trim() || mutating) return;
  setBusy(true,"send-transfer");
  $("send-transfer").innerHTML = `${icon("clock")}Evaluating request…`;
  showError("");
  try {
    await waitForRefresh();
    const ackLoss = $("ack-loss").checked;
    if (!pendingTransfer || pendingTransfer.text !== text || pendingTransfer.subject !== state.session.subject_id || pendingTransfer.ackLoss !== ackLoss) {
      pendingTransfer = {request_id:makeRequestId(),text,subject:state.session.subject_id,ackLoss};
    }
    const result = await api("/api/transfer", {request_id:pendingTransfer.request_id,text,destination:"public_ai",simulate_ack_loss:ackLoss});
    pendingTransfer = null;
    activeRequest = result.request || result.result || result;
    await loadState();
    renderDecision();
    notify(`Policy: ${titleCase(activeRequest.decision)}. Delivery: ${titleCase(requestState(activeRequest))}.`);
  } catch (error) { showError(error.message); }
  finally {
    setBusy(false,"send-transfer");
    $("send-transfer").innerHTML = `${icon("send")}Evaluate & send`;
    updateText();
  }
}

async function reconcile(requestId) {
  if (mutating) return;
  setBusy(true);
  try {
    await waitForRefresh();
    const result = await api("/api/reconcile", {request_id:requestId});
    const updated = result.request || result.result || result;
    if (updated.request_id) activeRequest = updated;
    await loadState();
    if (!updated.request_id) activeRequest = array(state.requests).find(request => request.request_id === requestId) || activeRequest;
    renderDecision();
    notify("Reconciliation completed. Inspect the updated delivery state.");
  } catch (error) { showError(error.message); }
  finally { setBusy(false); }
}

document.addEventListener("click", event => {
  const tab = event.target.closest("[data-tab]");
  if (tab) changeTab(tab.dataset.tab);
  const go = event.target.closest("[data-go]");
  if (go) changeTab(go.dataset.go);
  const subject = event.target.closest("[data-investigate]");
  if (subject) {
    analysisSource = subject.dataset.source || "lab";
    selectedSubject = subject.dataset.investigate;
    renderSubjectOptions();
    changeTab("investigation");
  }
  const fragment = event.target.closest("[data-fragment]");
  if (fragment && !mutating) fillFragment(Number(fragment.dataset.fragment));
  const requestButton = event.target.closest("[data-request]");
  if (requestButton) {
    activeRequest = array(state?.requests).find(request => request.request_id === requestButton.dataset.request) || null;
    changeTab("lab");
    $("decision-content").scrollIntoView({behavior:"smooth",block:"center"});
  }
  const reconciliation = event.target.closest("[data-reconcile]");
  if (reconciliation) reconcile(reconciliation.dataset.reconcile);
});

$("refresh-state").addEventListener("click", () => loadState());
$("data-source-select").addEventListener("change", event => {
  analysisSource = event.target.value;
  if (!benchmarkMeasured()) analysisSource = "lab";
  selectedSubject = null;
  ensureAnalysisSelection();
  render();
});
$("export-source-evidence").addEventListener("click", () => {
  if (!state || !isAnalyst()) return;
  const cert = usingBenchmark();
  const evidence = cert ? currentBenchmark() : {
    provenance:state.provenance || "synthetic_lab",
    profile:state.profile,
    evaluation:state.evaluation,
    subjects:state.subjects
  };
  const file = new Blob([JSON.stringify(evidence,null,2)+"\n"],{type:"application/json"});
  const url = URL.createObjectURL(file);
  const link = document.createElement("a");
  link.href = url;
  link.download = cert ? "sedra-cert-benchmark-evidence.json" : "sedra-workspace-evaluation.json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url),1000);
});
$("subject-select").addEventListener("change", event => { selectedSubject = event.target.value; renderInvestigation(); });
$("document-select").addEventListener("change", event => { selectedDocument = event.target.value; openedDocument = null; renderDocument(); });
$("transfer-text").addEventListener("input", updateText);
$("fill-benign").addEventListener("click", () => fillText("Please help me write a concise agenda for a public cybersecurity workshop. Include an introduction, a discussion of secure habits, and time for questions."));
$("fill-protected").addEventListener("click", () => {
  const doc = array(state?.documents).find(item => item.classification === "restricted");
  if (!doc) { showError("No restricted synthetic example document is registered."); return; }
  selectedDocument = doc.id;
  openedDocument = null;
  renderDocumentOptions();
  renderDocument();
  fillFragment(0);
});
$("send-transfer").addEventListener("click", transfer);
$("open-document").addEventListener("click", async () => {
  if (mutating) return;
  $("open-document").disabled = true;
  try { await openDocument(); } catch (error) { showError(error.message); }
  finally { $("open-document").disabled = !selectedDocument; }
});
$("identity-select").addEventListener("change", async event => {
  const identity = event.target.value;
  setBusy(true);
  try {
    await waitForRefresh();
    const result = await api("/api/session", {identity});
    if (result.session) state.session = result.session;
    activeRequest = null;
    openedDocument = null;
    if (identity !== "analyst") { analysisSource = "lab"; selectedSubject = identity; }
    await loadState();
    notify(`Local demo identity: ${identity === "analyst" ? "Analyst" : identity}.`);
  } catch (error) { showError(error.message); if (state) $("identity-select").value = isAnalyst() ? "analyst" : state.session.subject_id; }
  finally { setBusy(false); }
});
$("reset-demo").addEventListener("click", async () => {
  if (mutating || !state) return;
  setBusy(true,"reset-demo");
  try {
    await waitForRefresh();
    await api("/api/reset", {});
    activeRequest = null;
    openedDocument = null;
    $("transfer-text").value = "";
    $("ack-loss").checked = false;
    updateText();
    await loadState();
    notify("Demo ledger, receiver, and application events reset.");
  } catch (error) { showError(error.message); }
  finally { setBusy(false,"reset-demo"); }
});
window.addEventListener("hashchange", () => {if(location.hash!=="#main")changeTab(location.hash.slice(1),false);});
document.addEventListener("visibilitychange", () => { if (!document.hidden && !mutating) loadState({silent:true}); });
installIcons();
changeTab(alertPageId?'alerts':location.hash.slice(1)||(location.pathname==='/integrations'?'integrations':'overview'),false);
loadState();
setInterval(() => { if (!document.hidden && !mutating && !loading) loadState({silent:true}); }, 8000);

$("load-judge-example").addEventListener("click", () => {
  const samples = {
    short:"restricted runbook",
    homoglyph:"This fictionаl restricted runbооk contаins а lаborаtоry credentiаl mаrker.",
    inserted:"fictional filler restricted filler runbook filler laboratory filler credential",
    reversed:"credential laboratory runbook restricted fictional",
    base64:btoa("SEDRA_SECRET_A1B2C3D4E5F6G7H8"),
    card:"Card number: 4111 1111 1111 1111",
    iban:"Bank account: AZ21NABZ00000000137010001944",
    comparison:array(state.documents).find(d=>d.id==="araz-plan")?.fragments?.find(f=>f.label==="Context comparison excerpt")?.text
  };
  fillText(samples[$("judge-example").value]);
});
$("live-burst").addEventListener("click", async () => {
  if (!canTransfer() || mutating) return;
  setBusy(true);
  try {
    for (let i=0;i<6;i++) await api("/api/document?id=araz-plan");
    await loadState();
    notify("Six actual document requests recorded. The live rule now tightens excerpt limits for this identity.");
  } catch (error) { showError(error.message); }
  finally { setBusy(false); }
});
$("run-mosaic").addEventListener("click", async () => {
  if (mutating || state.session.subject_id!=="lab-001") return;
  if (state.requests.length) { showError("Start with a fresh ledger: select Analyst, reset the demo, then choose User 001."); return; }
  setBusy(true);
  try {
    const source = array(state.documents).find(d=>d.id==="araz-plan");
    for (const fragment of source.fragments.slice(0,3)) {
      await api("/api/document?id=araz-plan");
      fillText(fragment.text);
      activeRequest = await api("/api/transfer", {request_id:makeRequestId(),text:fragment.text});
      await loadState();
    }
    notify("Sequence complete. Inspect the third decision and the two independent receiver receipts.");
  } catch(error) { showError(error.message); }
  finally { setBusy(false); }
});

$('inventory-search').addEventListener('input',renderInventory);
$('inventory-filter').addEventListener('change',renderInventory);
document.addEventListener('click',event=>{
  const asset=event.target.closest('[data-asset]');
  if(asset){labelDraftDirty=false;selectedAsset=asset.dataset.asset;renderInventory();renderAssetInspector();$('asset-inspector').scrollIntoView({behavior:'smooth',block:'start'});}
  if(event.target.closest('#close-asset')){labelDraftDirty=false;selectedAsset=null;renderInventory();}
});
document.addEventListener('submit',async event=>{
  if(event.target.id!=='label-form')return;
  event.preventDefault();if(mutating)return;
  const form=event.target, button=form.querySelector('button[type="submit"]');
  const payload={doc_id:form.dataset.docId,expected_revision:Number(form.dataset.revision),sensitivity:$('label-sensitivity').value,owner:$('label-owner').value,business_tags:[...form.querySelectorAll('input[name="business-tag"]:checked')].map(e=>e.value),change_reason:$('label-reason').value};
  mutating=true;button.disabled=true;showError('');
  try{await api('/api/catalog/labels',payload);await loadState();labelDraftDirty=false;renderAssetInspector();notify('Governed labels saved. New admissions use this revision.');}
  catch(exc){showError(exc.message);}
  finally{mutating=false;button.disabled=false;render();}
});

for(const eventName of ['input','change'])document.addEventListener(eventName,event=>{if(event.target.closest('#label-form')){labelDraftDirty=true;$('label-save-note').textContent='Unsaved metadata changes';}});

$('load-datatype-example').addEventListener('click',()=>{
  const example=state?.data_types?.examples?.[$('datatype-example').value];
  if(!example)return;
  fillText(example.text);changeTab('lab');notify('Synthetic example loaded. Evaluate & send executes the real gateway.');
});
