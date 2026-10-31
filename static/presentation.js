/* Human-readable aliases only; payloads, bindings and original evidence stay unchanged. */
'use strict';
(() => {
  function text(value){return String(value).replace(/\blab-(\d+)\b/gi,'User $1').replace(/\blaboratory\b/gi,'validation').replace(/(?<![\w-])lab(?![\w-])/gi,'workspace');}
  if(typeof module!=='undefined')module.exports={text};
  if(typeof document==='undefined')return;
  const excluded='script,style,textarea,input,pre,code,[contenteditable],[data-sensitive],#document-content,#document-fragments,#answer,.receiver-preview';
  function clean(node){
    if(node.nodeType===3){if(!node.parentElement?.closest(excluded)){const next=text(node.nodeValue);if(next!==node.nodeValue)node.nodeValue=next;}return;}
    if(node.nodeType!==1||node.matches(excluded))return;
    for(const name of ['aria-label','title','placeholder'])if(node.hasAttribute(name)){const old=node.getAttribute(name),next=text(old);if(old!==next)node.setAttribute(name,next);}
    for(const child of node.childNodes)clean(child);
  }
  const config={subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['aria-label','title','placeholder']};
  clean(document.documentElement);
  const observer=new MutationObserver(records=>{
    observer.disconnect();
    for(const record of records){if(record.type==='childList'){for(const node of record.addedNodes)clean(node);}else{clean(record.target);}}
    observer.observe(document.documentElement,config);
  });
  observer.observe(document.documentElement,config);
})();
