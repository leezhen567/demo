() => {
  const root = document.querySelector('.gradio-container');
  if (!root || root.dataset.riskChartsBound === '3') return;
  root.dataset.riskChartsBound = '3';
  // Native controls in report HTML also need styles when Gradio replaces that HTML.
  // This scoped sheet avoids depending on Gradio's rewritten component selectors.
  let sheet = document.getElementById('tara-risk-portrait-styles');
  if (!sheet) { sheet=document.createElement('style'); sheet.id='tara-risk-portrait-styles'; document.head.append(sheet); }
  sheet.textContent = "__TARA_RISK_STYLES__";
  const states = new Map(), mounts = new WeakMap();
  const esc = value => String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const add = (counts,key) => counts.set(key,(counts.get(key)||0)+1);
  const total = counts => [...counts.values()].reduce((a,b)=>a+b,0);
  function overview(card, original, counts) {
    const n=total(counts);
    let content;
    if(!n) {
      content='<div class="chart-empty"><b>暂无评级数据</b><span>当前筛选下没有可统计结果</span></div>';
    } else {
      let cursor=0;
      const stops=[], entries=[];
      for(const label of original.labels) {
        const count=counts.get(label)||0;
        if(!count) continue;
        const end=cursor+count/n*100, color=original.palette.get(label)||'#ccd6e2';
        stops.push(`${color} ${cursor}% ${end}%`);
        entries.push(`<li data-label="${esc(label)}" data-count="${count}"><i style="background:${color}"></i><span>${esc(label)}</span><b>${count}<small>${(count/n*100).toFixed(0)}%</small></b></li>`);
        cursor=end;
      }
      content=`<div class="donut-layout"><div class="donut" role="img" aria-label="${esc(original.title)}，共 ${n} 个样本" style="background:conic-gradient(${stops.join(',')})"><div><b>${n}</b><small>样本</small></div></div><ul class="chart-legend">${entries.join('')}</ul></div>`;
    }
    card.innerHTML=`<div class="chart-card-title">${esc(original.title)}<small>分布 · N=${n}</small></div>${content}`;
    card.dataset.sampleCount=n;
  }
  function render(panel) {
    const mount=mounts.get(panel);
    if(!mount) return;
    const selected=Object.fromEntries([...panel.querySelectorAll('[data-risk-filter]')].map(s=>[s.dataset.riskFilter,s.value]));
    states.set(panel.dataset.portraitId,selected);
    if(states.size>20) states.delete(states.keys().next().value);
    const counts={impact:new Map(),feasibility:new Map(),risk:new Map()};
    let assetCount=0;
    mount.data.forEach((asset,index)=>{
      if(selected.assets!=='' && selected.assets!==String(index)) return;
      let matched=!asset.attributes.length && !selected.attributes && !selected.vectors;
      for(const attribute of asset.attributes) {
        if(selected.attributes && selected.attributes!==attribute.label) continue;
        const attacks=attribute.attacks.filter(a=>!selected.vectors||selected.vectors===a[1]);
        if(selected.vectors && !attacks.length) continue;
        matched=true;
        add(counts.impact,attribute.impact);
        for(const [risk,,level] of attacks) {
          add(counts.risk,risk==='unrated'?'未评级':risk);
          add(counts.feasibility,level);
        }
      }
      if(matched) assetCount++;
    });
    panel.querySelectorAll('[data-portrait-chart]').forEach(card=>overview(card,mount.charts.get(card.dataset.portraitChart),counts[card.dataset.portraitChart]));
    const all=!selected.assets && !selected.attributes && !selected.vectors;
    panel.dataset.filtered=String(!all);
    panel.querySelector('.risk-filter-summary').textContent=`${all?'整份报告':'筛选结果'} · ${assetCount} 个资产 · ${total(counts.impact)} 项资产属性 · ${total(counts.risk)} 条路径`;
    panel.querySelector('[data-risk-reset]').disabled=all;
  }
  function bind(panel) {
    if(mounts.has(panel)) return;
    let data;
    try { data=JSON.parse(panel.dataset.riskPayload); } catch { return; }
    const charts=new Map([...panel.querySelectorAll('[data-portrait-chart]')].map(card=>[
      card.dataset.portraitChart,{
        title:card.querySelector('.chart-card-title').firstChild.textContent,
        labels:[...card.querySelectorAll('.chart-legend li span')].map(e=>e.textContent),
        palette:new Map([...card.querySelectorAll('.chart-legend li')].map(e=>[e.querySelector('span').textContent,e.querySelector('i').style.background])),
      },
    ]));
    if(charts.size!==3) return;
    mounts.set(panel,{data,charts});
    const saved=states.get(panel.dataset.portraitId);
    if(saved) panel.querySelectorAll('[data-risk-filter]').forEach(s=>{s.value=saved[s.dataset.riskFilter]||'';});
    render(panel);
    panel.dataset.riskReady='true';
  }
  root.addEventListener('change',event=>{
    if(event.target.matches('[data-risk-filter]')) render(event.target.closest('.risk-portrait'));
  });
  root.addEventListener('click',event=>{
    const reset=event.target.closest('[data-risk-reset]');
    if(!reset) return;
    const panel=reset.closest('.risk-portrait');
    panel.querySelectorAll('[data-risk-filter]').forEach(s=>{s.value='';});
    render(panel);
  });
  let scheduled=false;
  const refresh=()=>{scheduled=false;root.querySelectorAll('.risk-portrait[data-risk-version="3"]').forEach(bind);};
  new MutationObserver(()=>{if(!scheduled){scheduled=true;requestAnimationFrame(refresh);}}).observe(root,{childList:true,subtree:true});
  refresh();
}
