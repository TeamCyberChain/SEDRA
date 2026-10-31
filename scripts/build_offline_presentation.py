"""Build a self-contained image deck from validated slide renders, with notes."""
import base64
import html
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[1]

def build():
    destination=ROOT/'presentation';destination.mkdir(exist_ok=True)
    rendered=ROOT/'presentation/slides' if (ROOT/'presentation/slides').exists() else ROOT/'work/presentation/rendered'
    images=sorted(rendered.glob('slide-*.png'),key=lambda p:int(p.stem.split('-')[-1]))
    if len(images)!=8 or not (destination/'SADD_Final_EN.pptx').exists():
        raise ValueError('Validated eight-slide deck and renders required')
    sections=[]
    for index,image in enumerate(images):
        data=base64.b64encode(image.read_bytes()).decode()
        sections.append(f'<section class="slide" data-number="{index+1}"'+('' if index==0 else ' hidden')+f'><img alt="SƏDD slide {index+1}" src="data:image/png;base64,{data}"></section>')
    document='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SƏDD — final presentation</title><link rel="stylesheet" href="presentation.css"><script src="presentation.js" defer></script></head><body><main>'''+''.join(sections)+'''</main><nav><button id="previous" aria-label="Previous slide">←</button><span id="counter">1 / 8</span><button id="next" aria-label="Next slide">→</button><a href="http://127.0.0.1:8765/#lab" target="_blank" rel="noopener">Open live demo</a><button id="fullscreen">Full screen</button><span>Arrows / Space · six core slides + Q&A</span></nav></body></html>'''
    (destination/'index.html').write_text(document,encoding='utf-8')
    (destination/'presentation.css').write_text('''*{box-sizing:border-box}body{margin:0;background:#0c1b28;color:#fff;font-family:Arial,sans-serif;overflow:hidden}main{height:calc(100vh - 58px);min-height:0;overflow:hidden;display:grid;place-items:center}.slide{width:100%;height:100%;min-width:0;min-height:0;overflow:hidden;display:grid;place-items:center}.slide[hidden]{display:none}.slide img{width:100%;height:100%;max-width:100%;max-height:100%;object-fit:contain}nav{height:58px;display:flex;align-items:center;justify-content:center;gap:16px;background:#132739;font-size:12px}button,a{border:1px solid #466457;background:#203f4b;color:#c2eddb;padding:8px 14px;border-radius:5px;text-decoration:none;cursor:pointer;font:inherit}button:focus-visible,a:focus-visible{outline:3px solid #a5e4c9;outline-offset:2px}nav>span:last-child{color:#b8c8d0}@media(max-width:700px){nav>span:last-child{display:none}nav{gap:8px}}@media print{body{overflow:visible;background:white}nav{display:none}main{height:auto;display:block}.slide,.slide[hidden]{display:block;height:100vh;break-after:page}.slide img{width:100%;height:100%}@page{size:landscape;margin:0}}''',encoding='utf-8')
    (destination/'presentation.js').write_text('''"use strict";const slides=[...document.querySelectorAll(".slide")];let current=0;function show(n){current=Math.max(0,Math.min(slides.length-1,n));slides.forEach((s,i)=>s.hidden=i!==current);document.getElementById("counter").textContent=`${current+1} / ${slides.length}`;}document.getElementById("previous").onclick=()=>show(current-1);document.getElementById("next").onclick=()=>show(current+1);document.getElementById("fullscreen").onclick=()=>{if(!document.fullscreenElement)document.documentElement.requestFullscreen?.();else document.exitFullscreen?.();};document.addEventListener("keydown",e=>{if(["ArrowRight"," ","PageDown"].includes(e.key)){e.preventDefault();show(current+1);}if(["ArrowLeft","PageUp"].includes(e.key)){e.preventDefault();show(current-1);}if(e.key==="Home")show(0);if(e.key==="End")show(slides.length-1);});show(0);''',encoding='utf-8')
    print('Offline browser deck built:',destination/'index.html')

if __name__=='__main__':build()
