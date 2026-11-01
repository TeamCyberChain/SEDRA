/* Navigation preference only; never retain account or authentication values. */
(()=>{
 'use strict';
 const root=document.documentElement,sidebar=document.querySelector('.sidebar,.portal-nav');if(!sidebar)return;
 const header=document.querySelector('.topbar,.portal-workspace>header'),crumb=header?.querySelector('.breadcrumb,.portal-breadcrumb');if(!header||!crumb)return;
 sidebar.id='sedra-sidebar';const heading=document.createElement('div');heading.className='shell-heading';crumb.before(heading);heading.append(crumb);
 const button=document.createElement('button');button.type='button';button.className='shell-toggle';button.setAttribute('aria-controls',sidebar.id);
 button.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16m6-12-3 4 3 4"/></svg>';heading.prepend(button);
 let collapsed=false;try{collapsed=localStorage.getItem('sedra-nav-collapsed')==='true';}catch{}
 function apply(value){collapsed=value;root.dataset.nav=collapsed?'collapsed':'expanded';sidebar.inert=collapsed;if(collapsed)sidebar.setAttribute('inert','');else sidebar.removeAttribute('inert');sidebar.setAttribute('aria-hidden',String(collapsed));button.setAttribute('aria-expanded',String(!collapsed));const label=collapsed?'Expand sidebar':'Collapse sidebar';button.setAttribute('aria-label',label);button.title=label;dispatchEvent(new Event('sedra-sidebar-change'));}
 button.addEventListener('click',()=>{apply(!collapsed);try{localStorage.setItem('sedra-nav-collapsed',String(collapsed));}catch{}});
 addEventListener('storage',e=>{if(e.key==='sedra-nav-collapsed')apply(e.newValue==='true');});apply(collapsed);
})();
