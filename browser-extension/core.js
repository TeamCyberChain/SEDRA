'use strict';
const SedraCore=Object.freeze({
  maxFile:512*1024,maxText:65536,
  isSendControl({type,formBound,testId,sendClass,label}){
    return (type==='submit'&&formBound)||['send-button','send-message-button'].includes(testId)||sendClass||/^(send|send message|send prompt|submit|göndər|mesaj göndər)$/i.test((label||'').trim());
  },
  destination(url){
    try{const u=new URL(url);if(u.protocol==='https:'&&['gemini.google.com','chatgpt.com','chat.openai.com','claude.ai'].includes(u.hostname)&&!u.username&&!u.password)return u.hostname;
      if(u.origin==='http://127.0.0.1:8765'&&['/browser-lab','/browser-harness'].includes(u.pathname))return 'sedra-browser-lab';}catch{}
    return null;
  },
  async digest(text){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text)))].map(b=>b.toString(16).padStart(2,'0')).join('');},
  async fileData(file){
    if(file.size>512*1024)throw Error('FILE_TOO_LARGE');
    const bytes=new Uint8Array(await file.arrayBuffer());let value='';
    for(let i=0;i<bytes.length;i+=8192)value+=String.fromCharCode(...bytes.subarray(i,i+8192));
    return {name:file.name,data:btoa(value)};
  }
});
if(typeof module!=='undefined')module.exports=SedraCore;
