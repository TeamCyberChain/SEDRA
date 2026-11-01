'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const path=require('node:path'),root=path.resolve(__dirname,'..');
const escaped=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

test('alert queue renders safe new-tab URLs instead of inline scrolling controls',async()=>{
  const elements=new Map(),opened=[],navigated=[];
  function node(id){if(!elements.has(id))elements.set(id,{hidden:false,textContent:'',innerHTML:'',value:id==='alert-status-filter'?'active':id==='alert-severity-filter'?'all':'',checked:false,setAttribute(){},contains(){return false;},addEventListener(){}});return elements.get(id);}
  const a={alert_id:'SE-123?x="<bad>',seq:1,display_id:'SEDRA-000001',title:'<img src=x onerror=attack()>',severity:'high',status:'OPEN',subject_id:'lab-001',destination:'browser:chatgpt.com',detector_types:['AZ_FIN_CONTEXTUAL'],reason_codes:[],outcome:'Blocked',occurred_at:1};
  const feed={available:true,generation:'g',watermark:1,counts:{active:1,unread:1,open:1,in_review:0,total:1,resolved:0,critical_active:0},items:[a]};
  let click;
  const context=vm.createContext({state:{session:{role:'analyst',csrf_token:'test'},alerts:feed},alertPageId:null,document:{hidden:false,addEventListener(type,fn){if(type==='click')click=fn;}},location:{assign(url){navigated.push(url);}},window:{open(...args){opened.push(args);}},$:node,esc:escaped,isAnalyst:()=>true,titleCase:s=>s,dateTime:()=>'',setInterval(){},crypto:{},api(){throw Error('A queue link must not mutate or fetch alert detail');}});
  vm.runInContext(fs.readFileSync(path.join(root,'static/alerts.js'),'utf8'),context);
  const html=node('alert-rows').innerHTML;
  assert(html.includes('target="_blank" rel="noopener"'));
  assert(html.includes('/alert?id='+encodeURIComponent(a.alert_id)));
  assert(html.includes('&lt;img'));assert(!html.includes('<img src=x'));
  assert(!html.includes('data-alert-open'));
  node('alert-search').value='User 1';assert.equal(vm.runInContext('visibleAlerts().length',context),1);
  await click({target:{closest(selector){return selector==='[data-alert-open]'?{dataset:{alertOpen:a.alert_id}}:null;}}});
  assert.deepEqual(opened,[['/alert?id='+encodeURIComponent(a.alert_id),'_blank','noopener']]);
  context.alertPageId='detail';vm.runInContext('alertDetail={alert:{subject_id:"lab-002"},request:{request_id:"request?encoded"}}',context);
  for(const id of ['#alert-investigate-subject','#alert-inspect-request'])await click({target:{closest(selector){return selector===id?{}:null;}}});
  assert.deepEqual(navigated,['/?subject=lab-002#investigation','/?request=request%3Fencoded#transfers']);
  assert(!fs.readFileSync(path.join(root,'static/alerts.js'),'utf8').includes('scrollIntoView'));
});

test('display aliases retain original identity values and protected content',()=>{
  class Element{
    constructor(tag,attrs={},children=[]){this.nodeType=1;this.tag=tag;this.attrs=attrs;this.childNodes=children;for(const n of children)n.parentElement=this;}
    matches(){return ['script','style','textarea','input','pre','code'].includes(this.tag)||'contenteditable' in this.attrs||'data-sensitive' in this.attrs||['document-content','document-fragments','answer'].includes(this.attrs.id)||this.attrs.class==='receiver-preview';}
    closest(){return this.matches()?this:this.parentElement?.closest();}
    hasAttribute(k){return k in this.attrs;}getAttribute(k){return this.attrs[k];}setAttribute(k,v){this.attrs[k]=v;}
  }
  const text=value=>({nodeType:3,nodeValue:value});
  const label=text('lab-001 · Synthetic lab'),protectedText=text('laboratory credential marker'),raw=text('{"subject_id":"lab-001"}'),secret=text('private key literal'),option=new Element('option',{value:'lab-001'},[label]);
  const answer=text('a lab-001 answer'),receipt=text('lab receiver content');
  const doc=new Element('html',{},[option,new Element('textarea',{},[protectedText]),new Element('pre',{},[raw]),new Element('div',{'data-sensitive':'true'},[secret]),new Element('div',{id:'answer'},[answer]),new Element('div',{class:'receiver-preview'},[receipt])]);
  const context=vm.createContext({document:{documentElement:doc},MutationObserver:class{observe(){}disconnect(){}}});
  vm.runInContext(fs.readFileSync(path.join(root,'static/presentation.js'),'utf8'),context);
  assert.equal(label.nodeValue,'User 001 · Synthetic workspace');assert.equal(option.attrs.value,'lab-001');
  assert.equal(protectedText.nodeValue,'laboratory credential marker');assert.equal(raw.nodeValue,'{"subject_id":"lab-001"}');assert.equal(secret.nodeValue,'private key literal');
  assert.equal(answer.nodeValue,'a lab-001 answer');assert.equal(receipt.nodeValue,'lab receiver content');
});

test('shared console has one integrations section and a centred refresh glyph',()=>{
  const html=fs.readFileSync(path.join(root,'static/index.html'),'utf8'),app=fs.readFileSync(path.join(root,'static/app.js'),'utf8');
  const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);assert.equal(ids.length,new Set(ids).size);
  assert(html.includes('data-tab="integrations"'));assert(html.includes('id="view-integrations"'));
  assert(!html.includes('style="margin-bottom:16px"'));
  assert(app.includes("location.pathname === '/alert'"));assert(app.includes("location.pathname==='/integrations'"));
  for(const token of ['Â·','â†','â€”'])assert(!app.includes(token),'UTF-8 UI literal corrupted');
  assert(app.includes('M21 3v5h-5'));
});

test('authentication expiry clears privileged presentation and recovery restores sign-in state',async()=>{
  const app=fs.readFileSync(path.join(root,'static/app.js'),'utf8');
  const source=app.slice(app.indexOf('async function loadState('),app.indexOf('function changeTab('));
  const nodes=new Map(),classes=new Set();let cleared=false;
  const node=id=>{if(!nodes.has(id))nodes.set(id,{hidden:true,disabled:false,innerHTML:'',classList:{add(){},remove(){}}});return nodes.get(id);};
  const expired=Object.assign(Error('SSO login required'),{status:401});
  const context=vm.createContext({state:{session:{role:'analyst'}},loading:false,refreshWaiters:[],selectedDocument:null,activeRequest:null,initialRequestId:'retained-request',openedDocument:null,lastLoaded:null,labelDraftDirty:false,document:{body:{classList:{add:v=>classes.add(v),remove:v=>classes.delete(v)}}},window:{SedraIntegrations:{sync(){cleared=true;}}},$:node,api:async()=>{throw expired;},showError(){},array:v=>v||[],ensureAnalysisSelection(){},render(){}});
  vm.runInContext(source,context);await vm.runInContext('loadState()',context);
  assert.equal(context.state,null);assert.equal(node('session-signin').hidden,false);assert(classes.has('session-required'));assert(cleared);assert.equal(node('identity-select').disabled,true);
  context.api=async()=>({session:{role:'analyst'},documents:[],requests:[{request_id:'retained-request'}]});
  await vm.runInContext('loadState()',context);
  assert.equal(node('session-signin').hidden,true);assert(!classes.has('session-required'));
  assert.equal(context.activeRequest.request_id,'retained-request');assert.equal(context.initialRequestId,null);
  context.initialRequestId='inaccessible-request';await vm.runInContext('loadState()',context);assert.equal(context.activeRequest,null);
});

 test('theme preference survives page loads and follows explicit cross-tab updates',()=>{
 const source=fs.readFileSync(path.join(root,'static/theme.js'),'utf8');
 function boot(stored){const listeners={},doc={documentElement:{dataset:{}},querySelectorAll:()=>[],addEventListener(){}};let mediaChange;
 const c=vm.createContext({document:doc,localStorage:{getItem:()=>stored},matchMedia:()=>({matches:true,addEventListener:(n,f)=>mediaChange=f}),addEventListener:(n,f)=>listeners[n]=f});vm.runInContext(source,c);return {doc,listeners,change:()=>mediaChange({matches:false})};}
 const a=boot('light');assert.equal(a.doc.documentElement.dataset.theme,'light');a.listeners.storage({key:'sedra-theme',newValue:'dark'});a.change();assert.equal(a.doc.documentElement.dataset.theme,'dark');assert.equal(boot('dark').doc.documentElement.dataset.theme,'dark');assert.equal(boot(null).doc.documentElement.dataset.theme,'dark');
 });

test('User presentation hides privileged navigation and population evaluation',()=>{
 const app=fs.readFileSync(path.join(root,'static/app.js'),'utf8');
 const code=app.slice(app.indexOf('function syncNavigationAccess()'),app.indexOf('function render()'));
 const nodes=[{hidden:false},{hidden:false}],panel={hidden:false},changes=[];
 const c=vm.createContext({selectedTab:'integrations',isAnalyst:()=>false,document:{querySelectorAll:()=>nodes,body:{classList:{remove(){}}}},$:()=>({closest:()=>panel}),changeTab:(tab,update)=>{changes.push([tab,update]);}});
 vm.runInContext(code,c);vm.runInContext('syncNavigationAccess()',c);
 assert(nodes.every(n=>n.hidden));assert(panel.hidden);assert.deepEqual(changes,[['overview',false]]);
 c.isAnalyst=()=>true;vm.runInContext('syncNavigationAccess()',c);assert(nodes.every(n=>!n.hidden));assert(!panel.hidden);
});
