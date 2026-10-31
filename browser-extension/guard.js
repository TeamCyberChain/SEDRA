/* Composer-event pilot. Page/network tampering and autosave require managed egress controls. */
'use strict';
(()=>{
  if(!SedraCore.destination(location.href))return;
  const sendToPolicy=location.origin==='http://127.0.0.1:8765'&&location.pathname==='/browser-harness'&&typeof SedraHarnessTransport==='function'
    ?SedraHarnessTransport:message=>chrome.runtime.sendMessage(message);
  const session=crypto.randomUUID(),replayed=new WeakSet();
  let busy=false,releaseDepth=0,timer,attachments=[],banner,lastEditor=null;
  const editorSelector='textarea,[contenteditable="true"],[contenteditable="plaintext-only"]';
  const editorFor=node=>node instanceof Element?node.closest(editorSelector):null;
  const visible=e=>e?.isConnected&&e.getClientRects().length>0&&getComputedStyle(e).visibility!=='hidden';
  const editor=()=>{const active=editorFor(document.activeElement);if(visible(active))return active;if(visible(lastEditor))return lastEditor;const candidates=[...document.querySelectorAll(editorSelector)].filter(visible);return candidates.length===1?candidates[0]:null;};
  document.addEventListener('focusin',e=>{const target=editorFor(e.target);if(target)lastEditor=target;},true);
  const textOf=e=>!e?'':e instanceof HTMLTextAreaElement?e.value:(e.innerText||e.textContent||'');
  function notice(message,blocked=true){
    if(!document.documentElement)return;
    if(!banner?.isConnected){banner=document.createElement('div');const root=banner.attachShadow({mode:'closed'});const box=document.createElement('div');
      box.style.cssText='position:fixed;z-index:2147483647;bottom:18px;right:18px;max-width:430px;padding:16px 20px;border:1px solid #6ecfbf;border-radius:9px;background:#122333;color:#fff;font:14px/1.5 system-ui;box-shadow:0 10px 40px #0005;white-space:pre-line';root.append(box);banner.sedraBox=box;document.documentElement.append(banner);}
    banner.sedraBox.textContent='SEDRA · '+message;banner.sedraBox.style.borderColor=blocked?'#edb06f':'#6ecfbf';
  }
  const stop=e=>{e.preventDefault();e.stopImmediatePropagation();};
  function selectionOf(target){if(target instanceof HTMLTextAreaElement)return [target.selectionStart,target.selectionEnd];const s=getSelection();return [s?.anchorNode,s?.anchorOffset,s?.focusNode,s?.focusOffset];}
  const sameSelection=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  async function inspect(operation,mode,text,files=[],reportedFailure){
    let encoded=[],failure=reportedFailure;
    if(files.length>2)failure='FILE_TOO_LARGE';
    else try{encoded=await Promise.all(files.map(SedraCore.fileData));}catch{failure='FILE_TOO_LARGE';}
    if(new TextEncoder().encode(text).length>SedraCore.maxText){failure='FILE_TOO_LARGE';text='';}
    const hash=await SedraCore.digest(JSON.stringify({operation,mode,text,files:encoded,failure}));
    const request_id=mode==='release'?'br-'+crypto.randomUUID():'br-'+session+'-'+hash.slice(0,32);
    try{
      const value=await sendToPolicy({kind:'inspect',payload:{request_id,operation,mode,text,files:encoded,...(failure?{failure}:{})}});
      if(!value||!['ALLOW','BLOCK'].includes(value.decision))throw Error('No policy response');
      if(value.decision==='BLOCK')notice((value.local_only?'Blocked locally; policy service unavailable.':'Blocked by policy.')+'\n'+(value.finding_types?.join(', ')||value.reason_codes?.join(', ')||'Inspection unavailable')+(value.alert_ids?.length?'\nAlert recorded in SEDRA.':''));
      return value;
    }catch{notice('Blocked locally. Connect Browser Guard and check the local policy service.');return {decision:'BLOCK',local_only:true};}
  }
  function currentFiles(){const values=[...document.querySelectorAll('input[type=file]')].flatMap(e=>[...e.files]);return values.length?values:attachments;}
  const replay=event=>{replayed.add(event);return event;};
  function insertText(target,value){
    if(target instanceof HTMLTextAreaElement){target.setRangeText(value,target.selectionStart,target.selectionEnd,'end');}
    else{const selection=getSelection();if(!selection?.rangeCount||!target.contains(selection.anchorNode))throw Error('Unsupported selection');const range=selection.getRangeAt(0);range.deleteContents();const node=document.createTextNode(value);range.insertNode(node);range.setStartAfter(node);range.collapse(true);selection.removeAllRanges();selection.addRange(range);}
    target.dispatchEvent(replay(new InputEvent('input',{bubbles:true,inputType:'insertFromPaste',data:value})));
  }
  function pastedText(target,value){
    if(target instanceof HTMLTextAreaElement)return target.value.slice(0,target.selectionStart)+value+target.value.slice(target.selectionEnd);
    const selection=getSelection();if(!selection?.rangeCount||!target.contains(selection.anchorNode))return textOf(target)+'\n'+value;
    const selected=selection.getRangeAt(0),before=selected.cloneRange(),after=selected.cloneRange();before.selectNodeContents(target);before.setEnd(selected.startContainer,selected.startOffset);after.selectNodeContents(target);after.setStart(selected.endContainer,selected.endOffset);
    return before.toString()+value+after.toString();
  }
  document.addEventListener('paste',async event=>{
    if(replayed.has(event)||releaseDepth)return;
    const target=editorFor(event.target),files=[...(event.clipboardData?.files||[])];if(!target&&!files.length)return;
    stop(event);if(busy){notice('Another check is in progress. Retry after it completes.');return;}
    if(files.length){notice('Clipboard files are blocked. Use the inspected file picker.');await inspect('file','preview','',files,'UNSUPPORTED_COMPOSER');return;}
    const value=event.clipboardData?.getData('text/plain')||'',before=textOf(target),selection=selectionOf(target),candidate=pastedText(target,value);busy=true;
    try{const result=await inspect('paste','preview',candidate);if(result.decision==='ALLOW'&&textOf(target)===before&&sameSelection(selection,selectionOf(target))){insertText(target,value);notice('Paste checked. Sending will be checked again.',false);}}
    catch{notice('Paste blocked: unsupported editor selection.');}finally{busy=false;}
  },true);
  async function fileEvent(event){
    if(replayed.has(event)||releaseDepth)return;
    const input=event.target;if(!(input instanceof HTMLInputElement)||input.type!=='file')return;
    stop(event);if(event.type==='change')return;
    const files=[...input.files];if(!files.length){attachments=[];return;}
    if(busy){input.value='';notice('File selection blocked while another check is pending.');return;}
    busy=true;
    try{const before=await Promise.all(files.map(SedraCore.fileData));const result=await inspect('file','release','',files);
      const after=await Promise.all([...input.files].map(SedraCore.fileData));
      if(result.decision!=='ALLOW'||JSON.stringify(before)!==JSON.stringify(after)){input.value='';attachments=[];return;}
      attachments=files;releaseDepth++;try{input.dispatchEvent(replay(new Event('input',{bubbles:true})));input.dispatchEvent(replay(new Event('change',{bubbles:true})));}finally{releaseDepth--;}
      notice('Attachment checked. External delivery is not independently confirmed.',false);
    }catch{input.value='';attachments=[];await inspect('file','preview','',[], 'LOCAL_INSPECTION_FAILED');notice('File blocked: inspection could not complete.');}finally{busy=false;}
  }
  document.addEventListener('input',fileEvent,true);document.addEventListener('change',fileEvent,true);
  document.addEventListener('drop',async event=>{
    if(replayed.has(event)||releaseDepth)return;
    const files=[...(event.dataTransfer?.files||[])],target=editorFor(event.target),value=event.dataTransfer?.getData('text/plain')||'';
    if(!files.length&&!target)return;
    stop(event);if(busy){notice('Drop blocked while another check is pending.');return;}
    busy=true;
    try{
      if(files.length){const result=await inspect('drop','release','',files);if(result.decision==='ALLOW'){const data=new DataTransfer();for(const file of files)data.items.add(file);attachments=files;releaseDepth++;try{event.target.dispatchEvent(replay(new DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:data})));}finally{releaseDepth--;}}}
      else{const before=textOf(target),result=await inspect('paste','preview',pastedText(target,value));if(result.decision==='ALLOW'&&textOf(target)===before)insertText(target,value);}
    }catch{await inspect('drop','preview','',[], 'LOCAL_INSPECTION_FAILED');notice('Drop blocked: unsupported drop target.');}finally{busy=false;}
  },true);
  function sendButton(node){
    const button=node instanceof Element?node.closest('button,[role=button],input[type=submit]'):null;if(!button)return null;
    const label=(button.getAttribute('aria-label')||button.textContent||'').trim();
    return SedraCore.isSendControl({type:button.type,formBound:!!(button.form||button.closest('form')),testId:button.getAttribute('data-testid'),sendClass:button.classList.contains('send-button'),label})?button:null;
  }
  function findSend(){return [...document.querySelectorAll('button,[role=button],input[type=submit]')].find(b=>sendButton(b)&&!b.disabled);}
  async function send(event,button,form){
    stop(event);if(busy){notice('Send blocked while inspection is pending. Retry after it completes.');return;}
    const target=editor();if(!target){await inspect('send','preview','',[], 'UNSUPPORTED_COMPOSER');notice('Send blocked: unsupported composer.');return;}
    if(!button&&!findSend()&&!form){await inspect('send','preview','',[], 'UNSUPPORTED_COMPOSER');notice('Send blocked: unsupported submit control.');return;}
    busy=true;
    try{const text=textOf(target),files=currentFiles(),before=JSON.stringify(await Promise.all(files.map(SedraCore.fileData)));
      const result=await inspect('send','release',text,files);
      const after=JSON.stringify(await Promise.all(currentFiles().map(SedraCore.fileData)));
      if(result.decision!=='ALLOW')return;
      if(textOf(target)!==text||before!==after){notice('Content changed during inspection. Send again to inspect the new content.');return;}
      const action=button||findSend();releaseDepth++;try{if(action)action.click();else if(form)form.requestSubmit();else{notice('Send blocked: unsupported submit control.');return;}}finally{releaseDepth--;}
      notice('Policy check passed. External delivery remains unconfirmed.',false);
    }catch{await inspect('send','preview','',[], 'LOCAL_INSPECTION_FAILED');notice('Send blocked: complete inspection was not possible.');}finally{busy=false;}
  }
  document.addEventListener('click',event=>{if(replayed.has(event)||releaseDepth)return;const button=sendButton(event.target);if(button)void send(event,button,button.closest('form'));},true);
  document.addEventListener('submit',event=>{if(replayed.has(event)||releaseDepth)return;void send(event,null,event.target);},true);
  document.addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey&&!event.isComposing&&!releaseDepth&&editorFor(event.target))void send(event,findSend(),event.target.closest('form'));},true);
  document.addEventListener('input',event=>{
    if(replayed.has(event)||releaseDepth||!editorFor(event.target))return;
    clearTimeout(timer);const target=editorFor(event.target);lastEditor=target;timer=setTimeout(async()=>{if(busy)return;const result=await inspect('draft','preview',textOf(target));if(result.decision==='ALLOW')notice('Draft checked. Send is checked separately.',false);},700);
  },true);
})();
