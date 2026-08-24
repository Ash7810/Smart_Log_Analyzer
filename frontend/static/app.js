// Application State
let state = {
    summary: null,
    logs: [],
    flagged: [],
    threats: [],
    selectedAnomaly: null,
    activeView: 'logs',
    filterText: '',
    filterSeverity: 'all',
    filterStatus: 'all',
    threatFilterText: '',
    heatmapSlice: null, // [startTime, endTime] for time filtering
    neighborLogs: {
        targetId: null,
        sameHost: true,
        window: 5,
        items: []
    }
};

document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    setupEventListeners();
    fetchDashboardData();
});

function setupEventListeners() {
    // 4-View Tab Switching (Dashboard/Overview, Logs & Timeline, IP Threats, Investigation)
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

    // IP Threat Search
    const threatSearch = document.getElementById('threatSearchInput');
    if (threatSearch) {
        threatSearch.addEventListener('input', (e) => {
            state.threatFilterText = e.target.value.toLowerCase();
            renderThreatMatrix();
        });
    }

    // Heatmap Reset
    const resetHeatmapBtn = document.getElementById('btnResetHeatmapFilter');
    if (resetHeatmapBtn) {
        resetHeatmapBtn.addEventListener('click', () => {
            state.heatmapSlice = null;
            document.querySelectorAll('.timeline-bar-col').forEach(el => el.classList.remove('active-slice'));
            renderLogsTable();
            showToast('Timeline filter reset', 'info');
        });
    }

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
    if (viewId === 'threats') {
        renderThreatMatrix();
    }
    lucide.createIcons();
}

async function fetchDashboardData() {
    try {
        const [summaryRes, logsRes, flaggedRes, threatsRes] = await Promise.all([
            fetch('/api/summary').then(r => r.json()),
            fetch('/api/logs?limit=50000').then(r => r.json()),
            fetch('/api/flagged').then(r => r.json()),
            fetch('/api/threats/ips').then(r => r.json()).catch(() => ({ items: [] }))
        ]);

        state.summary = summaryRes;
        state.logs = logsRes.items || [];
        state.flagged = flaggedRes.items || [];
        state.threats = threatsRes.items || [];

        renderMetricBar();
        renderValidationDrawer();
        renderHeatmap();
        renderLogsTable();
        renderThreatMatrix();
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

/* =========================================================================
   1. TIME-SERIES INCIDENT HEATMAP & HISTOGRAM
   ========================================================================= */
function renderHeatmap() {
    const container = document.getElementById('timelineBarsContainer');
    const axis = document.getElementById('timelineAxisContainer');
    if (!container || !axis) return;
    
    const validLogs = state.logs.filter(l => l.timestamp && l.is_valid);
    if (validLogs.length === 0) {
        container.innerHTML = `<div style="width:100%; text-align:center; color:var(--text-light); font-size:12px; line-height:50px;">No time-series data available</div>`;
        axis.innerHTML = '';
        return;
    }

    // Sort by timestamp
    const sorted = [...validLogs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const startTime = new Date(sorted[0].timestamp).getTime();
    const endTime = new Date(sorted[sorted.length - 1].timestamp).getTime();
    
    const duration = Math.max(1, endTime - startTime);
    const BUCKETS = 36; // 36 vertical histogram bars
    const bucketDuration = duration / BUCKETS;

    const buckets = Array.from({ length: BUCKETS }, (_, i) => ({
        index: i,
        start: startTime + i * bucketDuration,
        end: startTime + (i + 1) * bucketDuration,
        normalCount: 0,
        anomalyCount: 0,
        total: 0
    }));

    sorted.forEach(log => {
        const t = new Date(log.timestamp).getTime();
        let bIdx = Math.floor((t - startTime) / bucketDuration);
        if (bIdx >= BUCKETS) bIdx = BUCKETS - 1;
        if (bIdx < 0) bIdx = 0;

        if (log.is_flagged) {
            buckets[bIdx].anomalyCount++;
        } else {
            buckets[bIdx].normalCount++;
        }
        buckets[bIdx].total++;
    });

    const maxCount = Math.max(1, ...buckets.map(b => b.total));

    container.innerHTML = buckets.map(b => {
        const heightPct = Math.max(8, (b.total / maxCount) * 100);
        const anomalyPct = b.total > 0 ? (b.anomalyCount / b.total) * 100 : 0;
        const normalPct = 100 - anomalyPct;

        const startStr = new Date(b.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const endStr = new Date(b.end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const tooltip = `${startStr} - ${endStr}: ${b.total} events (${b.anomalyCount} anomalies, ${b.normalCount} normal)`;

        return `
            <div class="timeline-bar-col" 
                 style="height: ${heightPct}%;" 
                 title="${tooltip}" 
                 onclick="filterByHeatmapBucket(${b.start}, ${b.end}, this)">
                <div class="bar-segment-normal" style="height: ${normalPct}%;"></div>
                ${b.anomalyCount > 0 ? `<div class="bar-segment-anomaly" style="height: ${anomalyPct}%;"></div>` : ''}
            </div>
        `;
    }).join('');

    const startLabel = new Date(startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const midLabel = new Date(startTime + duration / 2).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const endLabel = new Date(endTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    axis.innerHTML = `
        <span>${startLabel}</span>
        <span>${midLabel}</span>
        <span>${endLabel}</span>
    `;
}

function filterByHeatmapBucket(startMs, endMs, el) {
    document.querySelectorAll('.timeline-bar-col').forEach(bar => bar.classList.remove('active-slice'));
    if (el) el.classList.add('active-slice');
    
    state.heatmapSlice = [startMs, endMs];
    const sDate = new Date(startMs).toLocaleTimeString();
    const eDate = new Date(endMs).toLocaleTimeString();
    showToast(`Filtered logs to slice: ${sDate} - ${eDate}`, 'info');
    renderLogsTable();
}

/* =========================================================================
   2. ALL LOGS TABLE
   ========================================================================= */
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

        // Heatmap Time Slice Filter
        if (state.heatmapSlice && log.timestamp) {
            const logT = new Date(log.timestamp).getTime();
            if (logT < state.heatmapSlice[0] || logT > state.heatmapSlice[1]) {
                return false;
            }
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="empty-state">
                    <i data-lucide="search-x"></i>
                    <h3>No Matching Logs Found</h3>
                    <p>Try adjusting your search query, filters, or resetting the timeline filter.</p>
                </td>
            </tr>
        `;
        lucide.createIcons();
        return;
    }

    const maxDisplay = 250;
    const displayList = filtered.slice(0, maxDisplay);
    const hasMore = filtered.length > maxDisplay;

    const rowsHtml = displayList.map(log => {
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

    const moreBanner = hasMore ? `
        <tr>
            <td colspan="9" style="text-align: center; background: var(--bg-subtle); color: var(--text-muted); font-size: 12px; padding: 10px;">
                Showing first <b>${maxDisplay}</b> of <b>${filtered.length.toLocaleString()}</b> matching events. Use Search or Filters to pinpoint specific records.
            </td>
        </tr>
    ` : '';

    tbody.innerHTML = rowsHtml + moreBanner;
    lucide.createIcons();
}

/* =========================================================================
   3. IP THREAT AGGREGATION & RISK MATRIX
   ========================================================================= */
function renderThreatMatrix() {
    const grid = document.getElementById('threatCardsGrid');
    if (!grid) return;
    if (!state.threats || state.threats.length === 0) {
        grid.innerHTML = `
            <div style="grid-column: 1/-1;" class="empty-state">
                <i data-lucide="shield-check"></i>
                <h3>No Threat Intelligence Available</h3>
                <p>Ingest a dataset to aggregate source host risk statistics.</p>
            </div>
        `;
        lucide.createIcons();
        return;
    }

    const filtered = state.threats.filter(t => {
        if (!state.threatFilterText) return true;
        return t.source.toLowerCase().includes(state.threatFilterText) ||
               t.ip_origin.toLowerCase().includes(state.threatFilterText) ||
               t.threat_level.toLowerCase().includes(state.threatFilterText);
    });

    grid.innerHTML = filtered.map(t => {
        const level = t.threat_level.toLowerCase();
        let barColor = '#16a34a';
        if (level === 'critical') barColor = '#dc2626';
        else if (level === 'high') barColor = '#ea580c';
        else if (level === 'medium') barColor = '#d97706';

        const rulesBadges = t.triggered_rules.map(r => {
            return `<span class="badge" style="background:#fee2e2; color:#991b1b; font-size:10px;">${r}</span>`;
        }).join(' ') || '<span style="font-size:11px; color:var(--text-light);">No anomaly rules triggered</span>';

        return `
            <div class="threat-card">
                <div class="threat-card-top">
                    <div>
                        <div class="threat-ip-title">${t.source}</div>
                        <div class="threat-origin-label">${t.ip_origin}</div>
                    </div>
                    <span class="threat-badge ${level}">${t.threat_level} (${t.composite_score}/100)</span>
                </div>

                <div class="threat-score-bar-bg">
                    <div class="threat-score-bar-fill" style="width: ${t.composite_score}%; background: ${barColor};"></div>
                </div>

                <div class="threat-stats-row">
                    <div class="threat-stat-item">
                        <div class="threat-stat-label">Total Logs</div>
                        <div class="threat-stat-value">${t.total_requests}</div>
                    </div>
                    <div class="threat-stat-item">
                        <div class="threat-stat-label">Anomalies</div>
                        <div class="threat-stat-value text-red">${t.flagged_entries}</div>
                    </div>
                    <div class="threat-stat-item">
                        <div class="threat-stat-label">5xx / Errors</div>
                        <div class="threat-stat-value text-amber">${t.error_requests}</div>
                    </div>
                    <div class="threat-stat-item">
                        <div class="threat-stat-label">Endpoints</div>
                        <div class="threat-stat-value">${t.distinct_endpoints}</div>
                    </div>
                </div>

                <div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px; font-weight: 600; text-transform: uppercase;">Violations Triggered:</div>
                    <div class="threat-rules-tags">${rulesBadges}</div>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: auto; padding-top: 8px; border-top: 1px solid var(--border);">
                    <span style="font-size: 11px; color: var(--text-light);">First Seen: ${t.first_seen ? t.first_seen.split(' ')[1] : 'N/A'}</span>
                    <button class="btn btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="filterLogsByIp('${t.source}')">
                        <i data-lucide="filter"></i> View Logs
                    </button>
                </div>
            </div>
        `;
    }).join('');
    lucide.createIcons();
}

function filterLogsByIp(ip) {
    state.filterText = ip.toLowerCase();
    document.getElementById('searchInput').value = ip;
    switchView('logs');
    renderLogsTable();
    showToast(`Filtered logs stream for IP: ${ip}`, 'info');
}

/* =========================================================================
   4. INCIDENT INVESTIGATION & CONTEXTUAL NEIGHBOR LOGS
   ========================================================================= */
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
    fetchNeighborLogs(item.log_entry_id || item.id, true);
}

function inspectAnomaly(flaggedId) {
    switchView('investigate');
    selectIncidentById(flaggedId);
}

async function fetchNeighborLogs(logEntryId, sameHost = true) {
    try {
        const res = await fetch(`/api/logs/neighbors/${logEntryId}?window=5&same_host=${sameHost}`).then(r => r.json());
        state.neighborLogs = {
            targetId: logEntryId,
            sameHost: sameHost,
            window: 5,
            items: res.items || []
        };
        renderNeighborLogsTable();
    } catch (err) {
        console.error('Failed to fetch neighbor logs', err);
    }
}

function toggleNeighborHostFilter() {
    if (!state.selectedAnomaly) return;
    const currentSameHost = state.neighborLogs.sameHost;
    const newSameHost = !currentSameHost;
    fetchNeighborLogs(state.selectedAnomaly.log_entry_id || state.selectedAnomaly.id, newSameHost);
}

function renderNeighborLogsTable() {
    const container = document.getElementById('neighborLogsContainer');
    if (!container) return;

    const items = state.neighborLogs.items || [];
    const sameHost = state.neighborLogs.sameHost;

    container.innerHTML = `
        <div class="neighbor-logs-section">
            <div class="neighbor-header">
                <h4>
                    <i data-lucide="git-commit"></i>
                    Contextual Preceding & Subsequent Logs (&plusmn;5 Events)
                </h4>
                <button class="btn btn-secondary" style="font-size: 11px; padding: 3px 8px;" onclick="toggleNeighborHostFilter()">
                    ${sameHost ? 'Showing: Same Host Only (Click for All Hosts)' : 'Showing: All Hosts (Click for Same Host)'}
                </button>
            </div>
            <div style="overflow-x: auto;">
                <table class="neighbor-table">
                    <thead>
                        <tr>
                            <th>Position</th>
                            <th>ID</th>
                            <th>Timestamp</th>
                            <th>Source</th>
                            <th>Endpoint</th>
                            <th>Severity</th>
                            <th>HTTP</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${items.map(log => {
                            const isTarget = log.is_target;
                            const posLabel = isTarget ? '🚨 TARGET EVENT' : (log.id < state.neighborLogs.targetId ? 'Preceding' : 'Subsequent');
                            return `
                                <tr class="${isTarget ? 'neighbor-row-target' : 'neighbor-row-normal'}">
                                    <td><span style="font-size: 10px; font-weight: 700; ${isTarget ? 'color: #dc2626;' : 'color: var(--text-muted);'}">${posLabel}</span></td>
                                    <td><code>#${log.raw_id || log.id}</code></td>
                                    <td><code>${log.timestamp}</code></td>
                                    <td><code>${log.source}</code></td>
                                    <td><code>${log.event_type || 'N/A'}</code></td>
                                    <td><span style="font-size: 10.5px; font-weight: 600; text-transform: uppercase;">${log.severity}</span></td>
                                    <td><code>${log.status || 'N/A'}</code></td>
                                    <td style="max-width: 260px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${log.raw_message}">${log.raw_message}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    lucide.createIcons();
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

        <!-- Contextual Preceding / Subsequent Neighbor Logs -->
        <div id="neighborLogsContainer"></div>
    `;
    lucide.createIcons();
    renderNeighborLogsTable();
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

function showLoader(title = "Processing CSV Ingestion...", subtitle = "Parsing records, validating timestamps, and executing deterministic anomaly detection.") {
    const loader = document.getElementById('globalLoader');
    const titleEl = document.getElementById('loaderTitle');
    const subEl = document.getElementById('loaderSubtitle');
    if (titleEl) titleEl.innerText = title;
    if (subEl) subEl.innerText = subtitle;
    if (loader) loader.style.display = 'flex';
}

function hideLoader() {
    const loader = document.getElementById('globalLoader');
    if (loader) loader.style.display = 'none';
}

async function handleFileUpload(file) {
    const uploadBtn = document.getElementById('btnUploadTrigger');
    const fileInput = document.getElementById('fileInput');
    
    showLoader(
        `Ingesting & Validating ${file.name}...`,
        "Parsing CSV rows, validating timestamps, and calculating anomaly detections."
    );

    if (uploadBtn) {
        uploadBtn.disabled = true;
        uploadBtn.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Processing...`;
        lucide.createIcons();
    }

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch('/api/ingest', { method: 'POST', body: formData });
        const res = await response.json();
        
        if (response.ok && res.status === 'success') {
            const valid = res.summary.valid_rows || 0;
            const flagged = res.summary.flagged_rows || 0;
            const rejected = res.summary.rejected_rows || 0;
            await fetchDashboardData();
            switchView('logs');
            showToast(`Ingested ${valid.toLocaleString()} rows (${flagged} anomalies, ${rejected} rejected)!`, 'success');
        } else {
            showToast(res.detail || res.error || 'Upload error', 'error');
        }
    } catch (err) {
        showToast('Upload failed: ' + err.message, 'error');
    } finally {
        hideLoader();
        if (fileInput) fileInput.value = '';
        if (uploadBtn) {
            uploadBtn.disabled = false;
            uploadBtn.innerHTML = `<i data-lucide="upload"></i> Upload CSV`;
            lucide.createIcons();
        }
    }
}

async function loadDefaultDataset() {
    const defaultBtn = document.getElementById('btnDefaultData');
    
    showLoader(
        "Loading Default Dataset (logs.csv)...",
        "Validating sample log records and calculating ground-truth anomaly scores."
    );

    if (defaultBtn) {
        defaultBtn.disabled = true;
        defaultBtn.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Ingesting...`;
        lucide.createIcons();
    }

    try {
        const fileRes = await fetch('/api/ingest-default', { method: 'POST' }).then(r => r.json());
        if (fileRes.status === 'success') {
            const valid = fileRes.summary.valid_rows || 0;
            const flagged = fileRes.summary.flagged_rows || 0;
            await fetchDashboardData();
            switchView('logs');
            showToast(`Loaded ${valid} valid entries & detected ${flagged} anomalies!`, 'success');
        } else {
            showToast(fileRes.detail || 'Could not load default file', 'error');
        }
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        hideLoader();
        if (defaultBtn) {
            defaultBtn.disabled = false;
            defaultBtn.innerHTML = `<i data-lucide="database"></i> Load Default`;
            lucide.createIcons();
        }
    }
}

async function clearDatabase() {
    if (!confirm('Are you sure you want to clear all data?')) return;
    
    showLoader(
        "Resetting Database...",
        "Truncating log tables, clearing flagged incident records, and purging validation audit summaries."
    );

    try {
        await fetch('/api/clear', { method: 'POST' }).then(r => r.json());
        showToast('Database reset successfully', 'success');
        state.selectedAnomaly = null;
        await fetchDashboardData();
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        hideLoader();
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
