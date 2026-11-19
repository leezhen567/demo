"""Code-native sidebar presentation; commands fill drafts and never auto-run."""

# Runs as Gradio's input preprocessor, before click/Enter starts the backend call.
CAPTURE_VIEW_JS = r"""(...values) => {
  const page = document.querySelector('#workflow-tabs')?.dataset.page || values[6] || '';
  const snippets = [];
  const visible = node => !!node && node.getClientRects().length > 0;
  for (const selector of ['#workspace-input-status','.dfd-extract-count','.agent-telemetry','.risk-filter-summary']) {
    for (const node of document.querySelectorAll(selector)) if (visible(node)) snippets.push(node.innerText.slice(0,2200));
  }
  for (const table of document.querySelectorAll('.result-preview-table,.ws-data-table table')) {
    if (!visible(table)) continue;
    const rows = [...table.querySelectorAll('tr')].slice(0,10).map(row =>
      [...row.children].slice(0,12).map(cell => cell.innerText.slice(0,240)).join(' | '));
    snippets.push('页面表格（前10行摘录）：\n'+rows.join('\n'));
  }
  for (const portrait of document.querySelectorAll('.risk-portrait')) {
    if (!visible(portrait)) continue;
    const heading = portrait.previousElementSibling?.innerText || '当前风险画像';
    snippets.push('风险画像分区：'+heading.slice(0,180));
    snippets.push([...portrait.querySelectorAll('[data-risk-filter]')].map(select =>
      select.getAttribute('aria-label')+'='+select.selectedOptions[0]?.textContent).join('；'));
    for (const card of portrait.querySelectorAll('[data-portrait-chart]')) {
      const title = card.querySelector('.chart-card-title')?.firstChild?.textContent || card.dataset.portraitChart;
      const count = card.dataset.sampleCount || card.querySelector('.donut b')?.textContent || '0';
      const legend = [...card.querySelectorAll('.chart-legend li')].map(row => {
        const label = row.dataset.label || row.querySelector('span')?.textContent || '';
        const quantity = row.dataset.count || row.querySelector('b')?.firstChild?.textContent || '0';
        const percent = row.querySelector('small')?.textContent || '';
        return label+'：数量='+quantity+'，占比='+percent;
      });
      snippets.push(title+'：N='+count+'；'+legend.join('；'));
    }
  }
  // gr.State is null in frontend preprocessors; the backend resolves it later.
  const context = document.querySelector('#project-assistant-context [data-assistant-job-id]');
  const jobId = context ? context.dataset.assistantJobId : (values[2]?.job_id || '');
  values[6] = JSON.stringify({page,job_id:jobId,preview:snippets.join('\n\n').slice(0,14000)});
  return values;
}"""

ICONS = {
    'settings':'<path d="m9 3 1-2h4l1 2 2 1 2-.1 2 3-1 2v2l1 2-2 3-2-.1-2 1-1 2h-4l-1-2-2-1-2 .1-2-3 1-2V9L3 7l2-3 2 .1Z"/><circle cx="12" cy="10" r="3"/>',
    'close':'<path d="m9 5 7 7-7 7M4 5v14"/>',
    'inspect':'<path d="M5 3h10l4 4v14H5Z"/><path d="M14 3v5h5m-9 5 2 2 4-4M9 18h6"/>',
    'path':'<circle cx="5" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="M5 7v8a4 4 0 0 0 4 4h8M9 5h6a4 4 0 0 1 4 4v4m-3-3 3 3 3-3"/>',
    'rating':'<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="8" cy="18" r="2"/>',
}


def icon(name):
    return '<svg viewBox="0 0 24 24" aria-hidden="true">'+ICONS[name]+'</svg>'


def toolbar():
    return ('<div class="assistant-toolbar">'
        '<button type="button" data-assistant-action="settings" aria-controls="project-assistant-settings" aria-expanded="false" aria-label="助手设置" title="助手设置">'+icon('settings')+'</button>'
        '<button type="button" data-assistant-action="collapse" aria-label="收起助手" title="收起助手">'+icon('close')+'</button></div>')


def suggestions():
    return ('<div class="assistant-starters"><span>从一个具体问题开始</span>'+
        ''.join('<button type="button" data-assistant-prompt="'+str(i)+'">'+icon(name)+
            '<span>'+label+'</span><b aria-hidden="true">↗</b></button>' for i,(name,label) in enumerate([
                ('inspect','检查项目资料'),('path','解释攻击路径'),('rating','复核风险评级')]))+'</div>')


ASSISTANT_UI_JS = """() => {
  const panel = document.querySelector('#project-assistant');
  if (!panel || panel.dataset.uiBound) return;
  panel.dataset.uiBound = 'true';
  panel.setAttribute('aria-label','安全分析助手');
  const root = document.querySelector('.gradio-container');
  const scroll = panel.querySelector('#project-assistant-scroll');
  const chat = panel.querySelector('#project-assistant-chat');
  let follow = true, scheduled = false;
  const prompts = {
    default: ['检查当前项目资料是否齐全，列出需要补充或修正的内容。',
      '结合当前项目的实际结果，解释攻击路径的入口、经过的ECU和最终影响，并引用依据。',
      '复核当前项目的风险评级，说明各维度分值与依据，先列出需要关注的问题。'],
    attack_tree: ['解释当前选中资产的攻击树，说明最终目标、OR与AND关系，并引用报告依据。',
      '核对当前选中资产的攻击路径，说明入口、经过的ECU和最终影响。',
      '查看当前选中资产的风险评级与安全需求，指出需要人工核对的依据。']
  };
  function refresh() {
    scheduled = false;
    const page = document.querySelector('#workflow-tabs')?.dataset.page;
    const viewInput = panel.querySelector('#project-assistant-view textarea, #project-assistant-view input');
    if (viewInput && page && viewInput.value !== page) {
      const proto = viewInput.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto,'value').set.call(viewInput,page);
      viewInput.dispatchEvent(new Event('input',{bubbles:true}));
    }
    const tree = page === 'attack_tree';
    const context = panel.querySelector('[data-assistant-page]');
    const names = {input:'项目资料',strategy:'评估方案',agent:'运行分析',delivery:'报告交付',attack_tree:'攻击树'};
    if (context && context.textContent !== (names[page] || '当前项目')) context.textContent = names[page] || '当前项目';
    panel.querySelectorAll('[data-assistant-prompt]').forEach((button,i) => {
      const text = (tree ? ['解释当前攻击树','核对攻击路径','查找风险依据'] : ['检查项目资料','解释攻击路径','复核风险评级'])[i];
      if (button.querySelector('span').textContent !== text) button.querySelector('span').textContent = text;
    });
    const empty = !!chat.querySelector('.placeholder-content');
    panel.dataset.hasMessages = empty ? 'false' : 'true';
    const fresh = document.querySelector('#project-assistant-clear');
    if (fresh) { fresh.setAttribute('aria-label','开始新对话'); fresh.title = '开始新对话'; }
    for (const [id,label] of [['project-assistant-send','发送消息'],['project-assistant-stop','停止本轮操作']]) {
      const button = document.getElementById(id);
      if (button) { button.setAttribute('aria-label',label); button.title = label; }
    }
    if (follow && scroll) scroll.scrollTop = scroll.scrollHeight;
  }
  scroll?.addEventListener('scroll', () => { follow = scroll.scrollHeight-scroll.scrollTop-scroll.clientHeight < 72; }, {passive:true});
  new MutationObserver(() => {
    if (!scheduled) { scheduled=true; requestAnimationFrame(refresh); }
  }).observe(panel,{subtree:true,childList:true,characterData:true});
  new MutationObserver(refresh).observe(document.querySelector('#workflow-tabs'), {attributes:true,attributeFilter:['data-page']});
  function settings(open) {
    panel.dataset.settings = open ? 'true' : 'false';
    panel.querySelector('[data-assistant-action="settings"]').setAttribute('aria-expanded',String(open));
  }
  document.addEventListener('click', event => {
    const action = event.target.closest('[data-assistant-action]')?.dataset.assistantAction;
    if (action === 'settings') settings(panel.dataset.settings !== 'true');
    if (action === 'settings-close') settings(false);
    if (action === 'collapse') {
      settings(false);
      if (innerWidth <= 900) { document.querySelector('.assistant-mobile-toggle')?.click(); return; }
      root.dataset.assistantCollapsed = 'true';
    }
    if (event.target.closest('.assistant-mobile-toggle')) root.dataset.assistantCollapsed = 'false';
    const starter = event.target.closest('[data-assistant-prompt]');
    if (starter) {
      const input = panel.querySelector('#project-assistant-question textarea');
      const page = document.querySelector('#workflow-tabs')?.dataset.page;
      const query = (prompts[page] || prompts.default)[Number(starter.dataset.assistantPrompt)];
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(input,query);
      input.dispatchEvent(new Event('input',{bubbles:true})); input.focus();
    }
    if (event.target.closest('#project-assistant-send')) { follow=true; settings(false); }
  });
  document.addEventListener('keydown',event => { if (event.key === 'Escape') settings(false); });
  refresh();
}"""
