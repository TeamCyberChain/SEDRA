/* Local cosmetic motion only. No form values, network calls or stored state. */
(()=>{
 'use strict';const reduced=matchMedia('(prefers-reduced-motion: reduce)');
 function start(){
  if(document.body.classList.contains('signin-page')&&!reduced.matches){
   const mark=document.querySelector('.signin-brand .sedra-logo');
   if(mark){const intro=document.createElement('div');intro.className='sedra-intro';intro.setAttribute('aria-hidden','true');intro.setAttribute('inert','');
    const box=document.createElement('div');box.className='sedra-intro-content';box.append(mark.cloneNode(true));
    const name=document.createElement('strong');name.textContent='SEDRA';const expansion=document.createElement('p');expansion.textContent='Sensitive Enterprise Data Risk Assurance';box.append(name,expansion);intro.append(box);document.body.append(intro);
    const remove=()=>intro.remove();intro.addEventListener('animationend',e=>{if(e.target===intro)remove();});setTimeout(remove,1300);
   }
  }
  document.addEventListener('pointerdown',e=>{
   if(reduced.matches||e.button!==0)return;const button=e.target.closest('button,.button');if(!button||button.disabled)return;
   const r=button.getBoundingClientRect(),size=Math.hypot(r.width,r.height)*2,wrap=document.createElement('span'),dot=document.createElement('span');wrap.className='motion-ripple-wrap';wrap.setAttribute('aria-hidden','true');dot.className='motion-ripple';dot.style.width=dot.style.height=size+'px';dot.style.left=(e.clientX-r.left-size/2)+'px';dot.style.top=(e.clientY-r.top-size/2)+'px';wrap.append(dot);button.append(wrap);setTimeout(()=>wrap.remove(),550);
  },{passive:true});
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start,{once:true});else start();
})();
