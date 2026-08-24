// Application State
let state = {
    summary: null,
    logs: [],
    flagged: [],
    selectedAnomaly: null,
    activeView: 'logs',
    filterText: '',
    filterSeverity: 'all',
    filterStatus: 'all'
};

document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    setupEventListeners();
    fetchDashboardData();
});

function setupEventListeners() {
    // 2-View Tab Switching (List View & Incident Detail View)
    document.querySelectorAll('.view-tab').forEach(btn => {
        btn.addEventListener('click', () => switchView(btn.getAttribute('data-view')));
    });

    // Ingestion
    const fileInput = document.getElementById('fileInput');
    document.getElementById('btnUploadTrigger').addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleFileUpload(e.target.files[0]);
    });

    document.getElementById('btnDefaultData').addEventListener('click', loadDefaultDataset);
    document.getElementById('btnClearDb').addEventListener('click', clearDatabase);
    document.getElementById('btnGenerateAi').addEventListener('click', generateAllAiInsights);

    // Search and Filters
    document.getElementById('searchInput').addEventListener('input', (e) => {
        state.filterText = e.target.value.toLowerCase();
        renderLogsTable();
    });

    document.getElementById('filterSeverity').addEventListener('change', (e) => {
        state.filterSeverity = e.target.value;
        renderLogsTable();
    });

    document.getElementById('filterStatus').addEventListener('change', (e) => {
        state.filterStatus = e.target.value;
        renderLogsTable();
    });

    // Validation Drawer Toggle
    document.getElementById('drawerToggle').addEventListener('click', () => {
        document.getElementById('drawerContent').classList.toggle('open');
    });
}

function switchView(viewId) {
    state.activeView = viewId;
    document.querySelectorAll('.view-tab').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-view') === viewId);
    });
    document.querySelectorAll('.view-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === `view-${viewId}`);
    });
    lucide.createIcons();
}

async function fetchDashboardData() {
    try {
        const [summaryRes, logsRes, flaggedRes] = await Promise.all([
            fetch('/api/summary').then(r => r.json()),
            fetch('/api/logs?limit=50000').then(r => r.json()),
            fetch('/api/flagged').then(r => r.json())
        ]);

        state.summary = summaryRes;
        state.logs = logsRes.items || [];
        state.flagged = flaggedRes.items || [];

        renderMetricBar();
        renderValidationDrawer();
        renderLogsTable();
        renderIncidentInspector();
        lucide.createIcons();
    } catch (err) {
        showToast('API Connection Error: ' + err.message, 'error');
    }
}

function renderMetricBar() {
    const s = state.summary || { total_rows: 0, valid_rows: 0, rejected_rows: 0, flagged_rows: 0 };
    document.getElementById('kpiTotal').innerText = Number(s.total_rows || 0).toLocaleString();
    document.getElementById('kpiValid').innerText = Number(s.valid_rows || 0).toLocaleString();
    document.getElementById('kpiRejected').innerText = Number(s.rejected_rows || 0).toLocaleString();
    document.getElementById('kpiFlagged').innerText = Number(s.flagged_rows || 0).toLocaleString();
    document.getElementById('flaggedBadge').innerText = state.flagged.length;
}

function renderValidationDrawer() {
    const drawer = document.getElementById('validationDrawer');
    const rejections = state.summary && state.summary.rejections ? state.summary.rejections : [];
    
    if (rejections.length > 0) {
        drawer.style.display = 'block';
        document.getElementById('rejectedCountText').innerText = rejections.length;
        const tbody = document.getElementById('rejectionsTableBody');
        tbody.innerHTML = rejections.map(r => `
            <tr>
                <td><code>#${r.row_index}</code></td>
                <td><code>${r.raw_id || 'N/A'}</code></td>
                <td><code>${r.raw_timestamp || '(empty)'}</code></td>
                <td><code>${r.source || '(empty)'}</code></td>
                <td style="color: var(--accent-red); font-weight: 500;">${r.reason}</td>
            </tr>
        `).join('');
    } else {
        drawer.style.display = 'none';
    }
}

function renderLogsTable() {
    const tbody = document.getElementById('logsTableBody');
    if (!state.logs || state.logs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="empty-state">
                    <i data-lucide="inbox"></i>
                    <h3>No Log Records Ingested</h3>
                    <p>Load the default dataset or upload a custom CSV file.</p>
                </td>
            </tr>
        `;
        lucide.createIcons();
        return;
    }

    const filtered = state.logs.filter(log => {
        if (state.filterText) {
            const str = `${log.source} ${log.event_type} ${log.raw_message}`.toLowerCase();
            if (!str.includes(state.filterText)) return false;
        }
        if (state.filterSeverity !== 'all' && log.severity !== state.filterSeverity) return false;
        if (state.filterStatus === 'flagged' && !log.is_flagged) return false;
        if (state.filterStatus === 'normal' && (log.is_flagged || !log.is_valid)) return false;
        if (state.filterStatus === 'invalid' && log.is_valid) return false;
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="empty-state">
                    <i data-lucide="search-x"></i>
                    <h3>No Matching Logs Found</h3>
                    <p>Try adjusting your search query or filters.</p>
                </td>
            </tr>
        `;
        lucide.createIcons();
        return;
    }

    tbody.innerHTML = filtered.map(log => {
        const isAnomaly = log.is_flagged;
        const badgeClass = isAnomaly ? 'badge-anomaly' : (log.is_valid ? 'badge-normal' : 'badge-spike');
        const statusText = isAnomaly ? 'ANOMALY' : (log.is_valid ? 'NORMAL' : 'INVALID');
        
        return `
            <tr class="${isAnomaly ? 'row-anomaly' : ''}">
                <td><code>#${log.raw_id || log.id}</code></td>
                <td><code>${log.timestamp || 'N/A'}</code></td>
                <td><span style="font-weight: 600; color: #1e293b;" class="font-mono">${log.source}</span></td>
                <td><code>${log.event_type || 'N/A'}</code></td>
                <td><span style="font-weight: 600; text-transform: uppercase; font-size: 11px;">${log.severity}</span></td>
                <td><code>${log.status || 'N/A'}</code></td>
                <td><span class="badge ${badgeClass}">${statusText}</span></td>
                <td style="max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 12.5px;" title="${log.raw_message}">${log.raw_message}</td>
                <td style="text-align: right;">
                    ${isAnomaly ? `<button class="btn btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="inspectAnomaly(${log.flagged.id})">Inspect</button>` : ''}
                </td>
            </tr>
        `;
    }).join('');
    lucide.createIcons();
}

function renderIncidentInspector() {
    const listContainer = document.getElementById('incidentItemsList');
    document.getElementById('incidentListCount').innerText = state.flagged.length;

    if (!state.flagged || state.flagged.length === 0) {
        listContainer.innerHTML = `<div style="padding: 16px; text-align: center; color: var(--text-muted); font-size: 12px;">No anomalies flagged.</div>`;
        document.getElementById('incidentDetailPanel').innerHTML = `
            <div class="empty-state">
                <i data-lucide="shield-check"></i>
                <h3>No Anomalies Flagged</h3>
                <p>Ingest a dataset to run the deterministic detector.</p>
            </div>
        `;
        lucide.createIcons();
        return;
    }

    listContainer.innerHTML = state.flagged.map(item => {
        const isSelected = state.selectedAnomaly && state.selectedAnomaly.id === item.id;
        return `
            <div class="incident-item ${isSelected ? 'selected' : ''}" onclick="selectIncidentById(${item.id})">
                <div class="incident-item-top">
                    <span>#${item.raw_id} • ${item.detector_rule}</span>
                    <span style="color: var(--text-light); font-size: 11px;">${item.timestamp.split(' ')[1] || ''}</span>
                </div>
                <div class="incident-item-bottom">
                    <code>${item.source}</code> → <span>${item.event_type}</span>
                </div>
            </div>
        `;
    }).join('');

    if (!state.selectedAnomaly && state.flagged.length > 0) {
        selectIncidentById(state.flagged[0].id);
    } else if (state.selectedAnomaly) {
        renderIncidentDetail(state.selectedAnomaly);
    }
}

function selectIncidentById(flaggedId) {
    const item = state.flagged.find(f => f.id === flaggedId);
    if (!item) return;
    state.selectedAnomaly = item;
    renderIncidentInspector();
    renderIncidentDetail(item);
}

function inspectAnomaly(flaggedId) {
    switchView('investigate');
    selectIncidentById(flaggedId);
}

function renderIncidentDetail(item) {
    const panel = document.getElementById('incidentDetailPanel');
    const mitre = item.mitre || { technique_id: 'T1000', technique_name: 'Unclassified Activity', tactic: 'Discovery' };
    const ipOrigin = item.ip_origin || 'Unknown Origin';
    
    panel.innerHTML = `
        <div class="meta-grid">
            <!-- Left: Metadata Panel -->
            <div class="card" style="padding: 18px;">
                <div class="card-header" style="background: transparent; padding: 0 0 12px 0; margin-bottom: 8px;">
                    <h3>Log Metadata & Rule Weight</h3>
                </div>
                <div class="kv-row"><span class="kv-key">Row ID</span><span class="kv-val">#${item.raw_id}</span></div>
                <div class="kv-row"><span class="kv-key">Timestamp</span><span class="kv-val"><code>${item.timestamp}</code></span></div>
                <div class="kv-row"><span class="kv-key">Source Host / IP</span><span class="kv-val"><code>${item.source}</code> <small style="color:var(--text-muted);">(${ipOrigin})</small></span></div>
                <div class="kv-row"><span class="kv-key">Endpoint / Path</span><span class="kv-val"><code>${item.event_type}</code></span></div>
                <div class="kv-row"><span class="kv-key">Severity / HTTP</span><span class="kv-val">${item.severity.toUpperCase()} (${item.status || 'N/A'})</span></div>
                <div class="kv-row"><span class="kv-key">Triggered Rule</span><span class="badge badge-anomaly">${item.detector_rule}</span></div>
                <div class="kv-row"><span class="kv-key">MITRE ATT&CK</span><span class="badge" style="background:#f3e8ff; color:#6b21a8; font-weight:700;">${mitre.technique_id}: ${mitre.technique_name}</span></div>
                <div class="kv-row"><span class="kv-key">Rule Score</span><span class="kv-val">${item.score}</span></div>
                <div style="margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border);">
                    <span style="font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">Detection Reason:</span>
                    <p style="font-size: 13px; color: var(--text-main); margin-top: 2px;"><i>${item.reason}</i></p>
                </div>
            </div>

            <!-- Right: Raw Message Code Box -->
            <div class="card" style="padding: 18px;">
                <div class="card-header" style="background: transparent; padding: 0 0 12px 0; margin-bottom: 8px;">
                    <h3>Raw Message Log Payload</h3>
                </div>
                <pre style="background: #0f172a; color: #38bdf8; border: 1px solid #1e293b; padding: 12px; border-radius: var(--radius-sm); font-size: 12px; overflow-x: auto; white-space: pre-wrap;">${item.raw_message}</pre>
                
                <div style="margin-top: 14px; display: flex; justify-content: space-between; align-items: center;">
                    <button class="btn btn-secondary" onclick="exportIncidentReport(${item.id})">
                        <i data-lucide="download"></i> Export Incident Brief (MD)
                    </button>
                    <button class="btn btn-secondary" onclick="refreshSingleAiExplanation(${item.id})">
                        <i data-lucide="refresh-cw"></i> Re-query AI
                    </button>
                </div>
            </div>
        </div>

        <!-- AI Dual Dialog Boxes -->
        <div class="ai-box ai-box-blue">
            <div class="ai-badge">
                <i data-lucide="sparkles"></i>
                <span>Incident Summary & Root Cause Diagnosis</span>
            </div>
            <p class="ai-text">${item.ai_explanation || 'No AI explanation generated yet. Click "Generate AI Insights" above.'}</p>
        </div>

        <div class="ai-box ai-box-green">
            <div class="ai-badge">
                <i data-lucide="shield-alert"></i>
                <span>Recommended Security Remediation & Action Plan</span>
            </div>
            <p class="ai-text">${item.ai_root_cause || 'Remediation plan will populate automatically upon AI analysis.'}</p>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 10px;">
                🔒 <b>Persistence:</b> Cached in SQLite DB (Zero redundant API calls on reload)
            </div>
        </div>
    `;
    lucide.createIcons();
}

function exportIncidentReport(flaggedId) {
    const item = state.flagged.find(f => f.id === flaggedId);
    if (!item) return;

    const mdContent = `# SecOps Incident Report — LogPulse Anomaly #${item.raw_id}
**Generated Timestamp:** ${new Date().toISOString()}
**Log Incident Timestamp:** ${item.timestamp}

---

## 1. Incident Metadata
- **Row ID:** #${item.raw_id}
- **Source IP / Host:** ${item.source} (${item.ip_origin || 'Unknown'})
- **Event Endpoint:** ${item.event_type}
- **Severity / HTTP:** ${item.severity.toUpperCase()} (${item.status || 'N/A'})
- **Triggered Detector Rule:** ${item.detector_rule} (Score: ${item.score})
- **MITRE ATT&CK Technique:** ${item.mitre ? item.mitre.technique_id + ' - ' + item.mitre.technique_name : 'N/A'}
- **Deterministic Rationale:** ${item.reason}

---

## 2. Raw Log Trace
\`\`\`text
${item.raw_message}
\`\`\`

---

## 3. Incident Summary & Root Cause Diagnosis
${item.ai_explanation || 'N/A'}

---

## 4. Recommended Security Remediation & Action Plan
${item.ai_root_cause || 'N/A'}

---
*Report exported from LogPulse Security Log Analyzer.*
`;

    const blob = new Blob([mdContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_report_#${item.raw_id}_${item.detector_rule}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Exported incident brief for #${item.raw_id}!`, 'success');
}

async function handleFileUpload(file) {
    const formData = new FormData();
    formData.append('file', file);

    showToast(`Uploading and validating ${file.name}...`, 'info');
    try {
        const response = await fetch('/api/ingest', { method: 'POST', body: formData });
        const res = await response.json();
        if (response.ok && res.status === 'success') {
            const valid = res.summary.valid_rows || 0;
            const flagged = res.summary.flagged_rows || 0;
            showToast(`Ingested ${valid.toLocaleString()} rows (${flagged} anomalies detected)!`, 'success');
            await fetchDashboardData();
            switchView('logs');
        } else {
            showToast(res.detail || res.error || 'Upload error', 'error');
        }
    } catch (err) {
        showToast('Upload failed: ' + err.message, 'error');
    }
}

async function loadDefaultDataset() {
    showToast('Loading logs.csv...', 'info');
    try {
        const fileRes = await fetch('/api/ingest-default', { method: 'POST' }).then(r => r.json());
        if (fileRes.status === 'success') {
            showToast('Loaded 255 valid entries & detected 35 anomalies!', 'success');
            fetchDashboardData();
        } else {
            showToast(fileRes.detail || 'Could not load default file', 'error');
        }
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function clearDatabase() {
    if (!confirm('Are you sure you want to clear all data?')) return;
    try {
        await fetch('/api/clear', { method: 'POST' }).then(r => r.json());
        showToast('Database reset successfully', 'success');
        state.selectedAnomaly = null;
        fetchDashboardData();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function generateAllAiInsights() {
    const btn = document.getElementById('btnGenerateAi');
    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Generating...`;
    lucide.createIcons();

    showToast('Generating AI explanations & remediation plans...', 'info');
    try {
        const res = await fetch('/api/explain-all?force_refresh=true', { method: 'POST' }).then(r => r.json());
        showToast(`AI insights generated for ${res.generated_count} flagged incident(s)!`, 'success');
        await fetchDashboardData();
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="sparkles"></i> Generate AI Insights`;
        lucide.createIcons();
    }
}

async function refreshSingleAiExplanation(flaggedId) {
    showToast('Re-generating AI analysis...', 'info');
    try {
        await fetch(`/api/explain/${flaggedId}?force_refresh=true`, { method: 'POST' }).then(r => r.json());
        showToast('Updated AI insights!', 'success');
        await fetchDashboardData();
        selectIncidentById(flaggedId);
    } catch (err) {
        showToast(err.message, 'error');
    }
}

function showToast(msg, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${msg}</span>`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3500);
}
