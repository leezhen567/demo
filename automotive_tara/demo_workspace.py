"""Shared presentation for the 7860 and 7868 analysis workspaces."""

from html import escape
from pathlib import Path


WORKSPACE_CSS = Path(__file__).with_name("demo_workspace.css").read_text(encoding="utf-8")


def workspace_header() -> str:
    return """
    <header class="ws-header">
      <div class="ws-brand">
        <span class="ws-brand-symbol"><svg viewBox="0 0 28 28" aria-hidden="true"><path d="m5 9 9-5 9 5-9 5Z"/><path d="m5 14 9 5 9-5M5 19l9 5 9-5"/></svg></span>
        <div><b>TARA<span>AI</span></b><small>汽车网络安全分析平台</small></div>
      </div>
      <div class="ws-header-main"><div class="ws-breadcrumb"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5h5l2 2h7v9H3Z"/></svg>工作空间 <span>/</span> <b id="ws-current-page">分析总览</b></div>
      <div class="ws-header-meta"><span class="ws-edition">AI 辅助 · 专业评估</span><span class="ws-org">中汽中心</span></div></div>
    </header>
    <div class="ws-open-feedback" role="status">正在打开所选任务…</div>
    <div class="ws-sidebar-caption"><div class="ws-space"><span>汽车安全分析</span><small>Threat Analysis &amp; Risk Assessment</small></div><p>工作空间 <span>WORKSPACE</span></p></div>
    <div class="ws-sidebar-footer"><div class="ws-footer-mark">CATARC <span>中汽中心</span></div></div>
    """


def workspace_heading(number: str, title: str, description: str) -> str:
    sections = {"01": "PROJECT INPUT", "02": "ASSESSMENT PLAN", "runtime": "MODEL SERVICES", "03": "ANALYSIS STUDIO", "04": "ASSET ATTACK TREES", "05": "DELIVERABLES"}
    step = f'<span class="ws-step-label"><b>{number}</b><span>/ 05</span></span>' if number != 'runtime' else '<span class="ws-service-label">工作空间 · 共享服务</span>'
    return (
        '<div class="ws-page-heading"><div>'
        f'<div class="ws-page-overline"><i></i>{sections[number]}</div>'
        f'<h1>{title}</h1><p>{description}</p></div>'
        f'{step}</div>'
    )


def workspace_source_heading(kind: str, title: str, detail: str, extension: str) -> str:
    paths = {
        "dfd": '<rect x="3" y="3" width="6" height="6" rx="1.5"/><rect x="15" y="15" width="6" height="6" rx="1.5"/><path d="M9 6h9v9M6 9v9h9"/>',
        "topology": '<rect x="8" y="3" width="8" height="6" rx="1.5"/><rect x="2" y="16" width="7" height="5" rx="1.5"/><rect x="15" y="16" width="7" height="5" rx="1.5"/><path d="M12 9v4M5 16v-3h14v3"/>',
        "interfaces": '<path d="M8 3v5M16 3v5M6 8h12v4a6 6 0 0 1-12 0ZM12 18v4"/>',
    }
    return (
        f'<div class="ws-source-heading"><span class="ws-source-icon {kind}"><svg viewBox="0 0 24 24" aria-hidden="true">{paths[kind]}</svg></span>'
        f'<div><b>{title}</b><small>{detail}</small></div><span class="ws-file-type">{extension}</span></div>'
    )


def workspace_preflight_table(rows, columns, *, source_loaded=False, limit=200) -> str:
    """Bound DOM size, but only after the server has filtered the complete input."""
    headers = "".join(f'<th scope="col">{escape(str(column))}</th>' for column in columns)
    body = "".join(
        '<tr data-row="true">' + "".join(f'<td>{escape(str(value))}</td>' for value in row) + '</tr>'
        for row in rows[:limit]
    )
    if not body:
        message = "没有符合条件的记录，请调整筛选条件。" if source_loaded else "导入数据流图后，资产与信号将显示在这里。"
        body = f'<tr><td class="ws-table-empty" colspan="{len(columns)}">{message}</td></tr>'
    count = len(rows)
    note = f"共 {count} 条，当前预览前 {limit} 条；请通过上方筛选定位。" if count > limit else f"共 {count} 条记录"
    return (
        '<section class="ws-data-table" aria-label="DFD 资产与信号预览">'
        '<div class="ws-data-actions"><span>' + note + '</span><div>'
        '<button type="button" data-table-action="copy">复制预览</button>'
        '<button type="button" data-table-action="expand" aria-pressed="false">展开表格</button>'
        '</div></div><div class="ws-data-scroll" tabindex="0" role="region" aria-label="可滚动的资产与信号表格">'
        '<table><caption class="sr-only">DFD 预提取结果</caption><thead><tr>' + headers + '</tr></thead><tbody>'
        + body + '</tbody></table></div></section>'
    )


WORKSPACE_JS = """() => {
    const root = document.querySelector('.gradio-container');
    if (!root || root.dataset.workspaceBound) return;
    root.dataset.workspaceBound = 'true';
    const titles = {overview:'分析总览', history:'历史任务', input:'项目资料', strategy:'评估方案', runtime:'模型服务', agent:'运行分析', delivery:'报告交付', attack_tree:'攻击树'};
    const steps = ['input','strategy','agent','attack_tree','delivery'];
    const assistantPages = ['input','strategy','agent','delivery','attack_tree'];
    const icons = [
        '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        '<path d="M3 11a9 9 0 1 1 3 7M3 5v6h6M12 7v5l3 2"/>',
        '<rect x="5" y="5" width="14" height="14" rx="3"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M19 9h3M2 15h3M19 15h3"/>',
        '<path d="M3 5h6l2 2h10v13H3Z"/><path d="M3 11h18"/>',
        '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="8" cy="18" r="2"/>',
        '<path d="m9 5 11 7-11 7Z"/><path d="M4 5v14"/>',
        '<path d="M5 3h10l4 4v14H5Z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
        '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-5h14v5"/>'
    ];
    const key = 'tara.workspace.7868.lastJobId';
    let restoreAttempted = false;
    let scheduled = false;
    function refresh() {
        scheduled = false;
        const nav = document.querySelector('#workflow-tabs > .tab-wrapper [role="tablist"]');
        const tabs = nav ? [...nav.querySelectorAll('[role="tab"]')] : [];
        if (nav) nav.setAttribute('aria-orientation', window.innerWidth > 760 ? 'vertical' : 'horizontal');
        const selected = tabs.find(tab => tab.getAttribute('aria-selected') === 'true')?.dataset.tabId;
        const workflow = document.querySelector('#workflow-tabs');
        if (workflow && workflow.dataset.page !== selected) workflow.dataset.page = selected || '';
        root.dataset.assistantVisible = assistantPages.includes(selected) ? 'true' : 'false';
        const assistantPanel = document.querySelector('#project-assistant');
        if (assistantPanel) assistantPanel.dataset.visible = root.dataset.assistantVisible;
        const assistantToggle = document.querySelector('.assistant-mobile-toggle');
        if (assistantToggle) assistantToggle.dataset.visible = root.dataset.assistantVisible;
        if (!assistantPages.includes(selected)) {
            root.dataset.assistantOpen = 'false';
            const panel = document.querySelector('#project-assistant');
            if (panel) panel.dataset.open = 'false';
            if (assistantToggle) {
                assistantToggle.textContent = 'AI 助手';
                assistantToggle.setAttribute('aria-expanded', 'false');
            }
        }
        const crumb = document.querySelector('#ws-current-page');
        if (crumb && titles[selected] && crumb.textContent !== titles[selected]) crumb.textContent = titles[selected];
        tabs.forEach((tab, index) => {
            const step = steps.indexOf(tab.dataset.tabId);
            if (!tab.dataset.step) tab.dataset.step = step < 0 ? '' : String(step + 1).padStart(2, '0');
            tab.classList.toggle('ws-nav-flow-first', tab.dataset.tabId === 'input');
            if (!tab.querySelector('.ws-nav-icon')) tab.insertAdjacentHTML('afterbegin', '<svg class="ws-nav-icon" viewBox="0 0 24 24" aria-hidden="true">' + icons[index] + '</svg>');
        });
        const ready = document.querySelector('#workspace-input-status .input-ok');
        const inputTab = tabs.find(tab => tab.dataset.tabId === 'input');
        if (inputTab) inputTab.classList.toggle('ws-input-ready', Boolean(ready));
        document.querySelectorAll('.agent-telemetry small').forEach(label => {
            if (label.textContent === 'MODEL CALLS') label.textContent = '模型调用';
            if (label.textContent === 'TOTAL TOKENS') label.textContent = 'Token 用量';
        });
        document.querySelectorAll('.trace-title > span').forEach(label => {
            if (label.textContent === 'AI EXECUTION TRACE') label.textContent = '分析流程';
        });
        document.querySelectorAll('.trace-progress > span').forEach(label => {
            if (label.textContent === 'WORKFLOW PROGRESS') label.textContent = '整体进度';
        });
        const evidence = document.querySelector('#agent-timeline .execution-details');
        if (evidence && !evidence.dataset.workspaceEvidence) {
            evidence.dataset.workspaceEvidence = 'true';
            // These counts are keyword-matched log events, not successful tool
            // executions or verified cache hits. Keep the labels evidence-based.
            const labels = {
                'AGENT COGNITIVE LOOP': '分析机制',
                '真实事件驱动 · 非隐藏思维链': '机制示意 · 状态由运行日志映射',
                'CURRENT REASONING SUMMARY': '最近运行事件',
                'CURRENT PLAN': '阶段计划',
                'Agent 根据阶段状态自动更新': '随任务进度更新',
                'EVIDENCE LEDGER': '过程证据',
                '每项均来自运行事实': '根据阶段状态、请求统计与日志汇总',
                'POLICY GUARDRAILS': '分析约束',
                'TOOL EVENTS': '工具相关日志', 'VALIDATIONS': '校验相关日志',
                'RETRIES': '重试相关日志', 'CACHE HITS': '缓存相关日志',
                'CHECKPOINTS': '检查点日志',
            };
            const walker = document.createTreeWalker(evidence, NodeFilter.SHOW_TEXT);
            while (walker.nextNode()) {
                const node = walker.currentNode;
                const label = labels[node.textContent.trim()];
                if (label) node.textContent = label;
            }
            const factLabels = ['输入解析', '拓扑构建', '模型请求', '校验日志', '持久化日志', '结构化结果'];
            evidence.querySelectorAll('.ledger-item').forEach((item, index) => {
                item.querySelector('b').textContent = factLabels[index];
                const detail = item.querySelector('small');
                detail.textContent = detail.textContent.replace('响应', '请求').replace('检查点', '检查点日志');
                if (index < 2) detail.textContent = item.classList.contains('done') ? '阶段已完成' :
                    item.classList.contains('error') ? '阶段异常' : item.classList.contains('active') ? '正在处理' : '等待处理';
            });
            if (evidence.closest('.idle')) evidence.querySelector('.cognitive-head > b').textContent = '等待任务';
            evidence.querySelectorAll('.plan-step.error small').forEach(label => { label.textContent = '需要处理'; });
            // Small screens use readable HTML steps instead of shrinking SVG text.
            const steps = document.createElement('ol');
            steps.className = 'ws-mechanism-steps';
            steps.setAttribute('aria-label', '分析机制示意');
            evidence.querySelectorAll('.cog-node').forEach((node, index) => {
                const item = document.createElement('li');
                item.className = node.getAttribute('class');
                const number = document.createElement('span');
                number.textContent = String(index + 1).padStart(2, '0');
                const title = document.createElement('b');
                title.textContent = node.querySelector('.cog-sub').textContent;
                item.append(number, title);
                steps.append(item);
            });
            evidence.querySelector('.cognitive-map').append(steps);
        }
        const input = document.querySelector('#workspace-job-id input, #workspace-job-id textarea');
        if (input) {
            try {
                if (!restoreAttempted) {
                    restoreAttempted = true;
                    const saved = localStorage.getItem(key);
                    if (!input.value && saved && /^[A-Za-z0-9_.-]{6,180}$/.test(saved)) {
                        const proto = input.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                        Object.getOwnPropertyDescriptor(proto, 'value').set.call(input, saved);
                        input.dispatchEvent(new Event('input', {bubbles:true}));
                    }
                }
                if (/^[A-Za-z0-9_.-]{6,180}$/.test(input.value)) localStorage.setItem(key, input.value);
            } catch (_) { /* Storage may be disabled; manual reconnection remains available. */ }
        }
    }
    new MutationObserver(() => {
        if (!scheduled) { scheduled = true; requestAnimationFrame(refresh); }
    }).observe(root, {subtree:true, childList:true, attributes:true, attributeFilter:['aria-selected']});
    async function openJob(jobId, destination) {
        const input = document.querySelector('#workspace-open-selection input, #workspace-open-selection textarea');
        const button = document.querySelector('#workspace-open-job');
        if (!input || !button) return;
        destination = ['agent', 'delivery'].includes(destination) ? destination : 'agent';
        root.dataset.openingJob = jobId;
        const proto = input.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(proto, 'value').set.call(input, jobId + '|' + destination);
        input.dispatchEvent(new Event('input', {bubbles:true}));
        await new Promise(requestAnimationFrame);
        button.click();
        document.querySelector('#workflow-tabs > .tab-wrapper [data-tab-id="' + destination + '"]')?.click();
        window.scrollTo({top:0, behavior:'instant'});
        setTimeout(() => { if (root.dataset.openingJob === jobId) delete root.dataset.openingJob; }, 30000);
    }
    root.addEventListener('click', async event => {
        const destination = event.target.closest('[data-workspace-target]');
        if (destination) {
            document.querySelector('#workflow-tabs > .tab-wrapper [data-tab-id="' + destination.dataset.workspaceTarget + '"]')?.click();
            return;
        }
        const job = event.target.closest('[data-workspace-job]');
        if (job) { await openJob(job.dataset.workspaceJob, job.dataset.workspaceOpen || 'agent'); return; }
        const stage = event.target.closest('[data-workspace-stage]');
        if (stage) {
            const overview = stage.closest('[data-featured-job]');
            if (overview?.dataset.featuredJob) { await openJob(overview.dataset.featuredJob, 'agent'); return; }
            const tab = document.querySelector('.agent-workspace-tabs [role=tab][data-tab-id="trace"]');
            tab?.click();
            document.querySelector('.agent-workspace-tabs')?.scrollIntoView({behavior:'smooth', block:'start'});
            return;
        }
        const expandRow = event.target.closest('[data-preview-expand]');
        if (expandRow) {
            const expanded = expandRow.closest('tr').classList.toggle('ws-row-expanded');
            expandRow.textContent = expanded ? '收起该行' : '展开该行';
            expandRow.setAttribute('aria-expanded', String(expanded));
            return;
        }
        const action = event.target.closest('[data-table-action]');
        if (action) {
            const table = action.closest('.ws-data-table');
            if (action.dataset.tableAction === 'expand') {
                const expanded = table.classList.toggle('ws-table-expanded');
                action.textContent = expanded ? '收起表格' : '展开表格';
                action.setAttribute('aria-pressed', String(expanded));
            } else {
                const lines = [...table.querySelectorAll('thead tr, tbody tr[data-row]')].map(row =>
                    [...row.children].map(cell => cell.textContent.replace(/[\\t\\n\\r]+/g, ' ')).join('\\t')
                ).join('\\n');
                try {
                    await navigator.clipboard.writeText(lines);
                    action.textContent = '已复制';
                } catch (_) { action.textContent = '请选中文本复制'; }
                setTimeout(() => { if (action.isConnected) action.textContent = '复制预览'; }, 2000);
            }
        }
        const tab = event.target.closest('#workflow-tabs > .tab-wrapper [role="tab"]');
        if (tab) window.scrollTo({top:0, behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth'});
    });
    root.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
            document.querySelectorAll('.ws-table-expanded [data-table-action="expand"]').forEach(button => button.click());
        }
        const tab = event.target.closest('#workflow-tabs > .tab-wrapper [role="tab"]');
        if (!tab || window.innerWidth <= 760 || !['ArrowUp', 'ArrowDown'].includes(event.key)) return;
        const tabs = [...tab.parentElement.querySelectorAll('[role="tab"]')];
        const index = tabs.indexOf(tab);
        const next = tabs[(index + (event.key === 'ArrowDown' ? 1 : -1) + tabs.length) % tabs.length];
        event.preventDefault();
        next.focus();
        next.click();
    });
    refresh();
}"""
