'use strict';
const status=document.getElementById('status'),key=document.getElementById('key');
async function refresh(){const value=await chrome.runtime.sendMessage({kind:'status'});status.textContent=(value.connected?'Session key configured; each action revalidates access':'Not connected')+' · queued offline reports '+value.queued+' · dropped/overflow reports '+value.lost;}
document.getElementById('connect').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;try{const result=await chrome.runtime.sendMessage({kind:'connect',key:key.value.trim()});key.value='';if(result.error)throw Error(result.error);await refresh();}catch(error){status.textContent=error.message;}finally{button.disabled=false;}});
document.getElementById('disconnect').onclick=async()=>{await chrome.runtime.sendMessage({kind:'disconnect'});await refresh();};
refresh();
