/**
 * ForensiQ - Investigation Dashboard Logic & API Client
 * JWT handling, resilient state management, and unified aggregation.
 */

// Dynamic API Base URL: Uses the current hostname when running on Vite/LiveServer ports, relative /api/v1 otherwise
const isDedicatedDevClient = window.location.port === '5173' || window.location.port === '3000';
const API_BASE = isDedicatedDevClient ? `http://${window.location.hostname}:8000/api/v1` : '/api/v1';

// Application State

const state = {
  token: localStorage.getItem('forensiq_token') || null,
  user: null,
  investigations: [],
  activeInvestigationId: localStorage.getItem('forensiq_active_inv_id') || null,
  summary: null,
  _refreshing: false,
};

// Default dev credentials — used for silent token refresh on expiry
const DEV_CREDENTIALS = {
  email: 'dev@forensiq.local',
  password: 'Dev123!@#',
};

// API Client Helper
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = options.headers || {};

  if (state.token) {
    headers['Authorization'] = `Bearer ${state.token}`;
  }

  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  try {
    const res = await fetch(url, { ...options, headers });

    if (res.status === 401 && endpoint !== '/auth/login') {
      // Attempt silent token refresh before giving up
      if (!state._refreshing) {
        const refreshed = await silentRefreshToken();
        if (refreshed) {
          // Retry original request with new token
          headers['Authorization'] = `Bearer ${state.token}`;
          const retryRes = await fetch(url, { ...options, headers });
          if (retryRes.ok) {
            return await retryRes.json();
          }
        }
      }
      // Refresh failed — show login screen
      handleAuthFailure();
      throw new Error('Session expired. Please log in again.');
    }

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.detail || `Request failed with status ${res.status}`);
    }
    return data;
  } catch (err) {
    if (!err.message.includes('Session expired')) {
      console.error(`API Error on ${endpoint}:`, err);
    }
    throw err;
  }
}

// Silent Token Refresh — re-authenticates using stored or default credentials
async function silentRefreshToken() {
  state._refreshing = true;
  try {
    // Try stored email first, fall back to dev default
    const email = localStorage.getItem('forensiq_email') || DEV_CREDENTIALS.email;
    const password = localStorage.getItem('forensiq_password') || DEV_CREDENTIALS.password;

    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) return false;

    const data = await res.json();
    state.token = data.access_token;
    state.user = data.user;
    localStorage.setItem('forensiq_token', data.access_token);
    console.info('[ForensiQ] Token silently refreshed.');
    return true;
  } catch {
    return false;
  } finally {
    state._refreshing = false;
  }
}

// Authentication & Session Management
function handleAuthFailure() {
  state.token = null;
  state.user = null;
  localStorage.removeItem('forensiq_token');
  localStorage.removeItem('forensiq_email');
  localStorage.removeItem('forensiq_password');
  showAuthView();
}

function showAuthView() {
  document.getElementById('auth-view').style.display = 'flex';
  document.getElementById('dashboard-view').style.display = 'none';
  document.getElementById('case-selector-container').style.display = 'none';
  document.getElementById('user-profile-badge').style.display = 'none';
}

function showDashboardView() {
  document.getElementById('auth-view').style.display = 'none';
  document.getElementById('dashboard-view').style.display = 'block';
  document.getElementById('case-selector-container').style.display = 'flex';
  document.getElementById('user-profile-badge').style.display = 'flex';

  if (state.user) {
    document.getElementById('user-email-display').textContent = state.user.email;
  }
}

// Global Banner Notifications
function showAlert(message, type = 'warning', timeoutMs = 6000) {
  const alertEl = document.getElementById('dashboard-alert');
  alertEl.className = `alert alert-${type}`;
  alertEl.textContent = message;
  alertEl.style.display = 'block';

  if (timeoutMs > 0) {
    setTimeout(() => {
      alertEl.style.display = 'none';
    }, timeoutMs);
  }
}

// Initialization Flow
async function initApp() {
  setupEventListeners();

  // Pre-fill login form with dev credentials for convenience
  const emailInput = document.getElementById('login-email');
  const passInput = document.getElementById('login-password');
  if (emailInput && !emailInput.value) {
    emailInput.value = localStorage.getItem('forensiq_email') || DEV_CREDENTIALS.email;
  }
  if (passInput && !passInput.value) {
    passInput.value = localStorage.getItem('forensiq_password') || DEV_CREDENTIALS.password;
  }

  // Sample evidence dropdown — fetch available samples and update download link when selection changes
  const sampleSelect = document.getElementById('sample-evidence-select');
  const sampleDownloadLink = document.getElementById('btn-download-example');
  
  if (sampleSelect) {
    apiRequest('/examples').then(samples => {
      sampleSelect.innerHTML = '<option value="">Select a sample…</option>';
      samples.forEach(sample => {
        const option = document.createElement('option');
        option.value = sample.filename;
        option.textContent = sample.display_name;
        sampleSelect.appendChild(option);
      });
    }).catch(err => {
      console.warn('Failed to load sample list:', err);
      sampleSelect.innerHTML = '<option value="">Failed to load samples</option>';
    });

    if (sampleDownloadLink) {
      sampleSelect.addEventListener('change', () => {
        const chosen = sampleSelect.value;
        if (chosen) {
          const url = `${API_BASE}/examples/${chosen}`;
          sampleDownloadLink.href = url;
          sampleDownloadLink.download = chosen;
          sampleDownloadLink.style.opacity = '1';
          sampleDownloadLink.style.pointerEvents = 'auto';
        } else {
          sampleDownloadLink.href = '#';
          sampleDownloadLink.download = '';
          sampleDownloadLink.style.opacity = '0.5';
          sampleDownloadLink.style.pointerEvents = 'none';
        }
      });
    }
  }

  // Health check
  try {
    await apiRequest('/health');
  } catch {
    console.warn('Backend is offline');
  }

  if (state.token) {
    try {
      state.user = await apiRequest('/auth/me');
      showDashboardView();
      await loadInvestigations();
    } catch {
      handleAuthFailure();
    }
  } else {
    showAuthView();
  }
}

// Load Accessible Investigations
async function loadInvestigations() {
  try {
    const res = await apiRequest('/investigations?limit=100');
    state.investigations = res.items;

    const selectEl = document.getElementById('investigation-select');
    selectEl.innerHTML = '';

    if (state.investigations.length === 0) {
      selectEl.innerHTML = '<option value="">No investigations yet</option>';
      renderEmptyInvestigation();
      return;
    }

    state.investigations.forEach(inv => {
      const opt = document.createElement('option');
      opt.value = inv.id;
      opt.textContent = `[${inv.case_number}] ${inv.title}`;
      selectEl.appendChild(opt);
    });

    // Select active case or first available
    if (state.activeInvestigationId && state.investigations.some(i => i.id === state.activeInvestigationId)) {
      selectEl.value = state.activeInvestigationId;
    } else {
      state.activeInvestigationId = state.investigations[0].id;
      selectEl.value = state.activeInvestigationId;
    }
    localStorage.setItem('forensiq_active_inv_id', state.activeInvestigationId);

    await loadActiveInvestigationSummary();
  } catch (err) {
    showAlert(`Failed to load investigations: ${err.message}`, 'danger');
  }
}

// Load Active Investigation Summary (Unified Dashboard Endpoint)
async function loadActiveInvestigationSummary() {
  if (!state.activeInvestigationId) return;

  try {
    const summary = await apiRequest(`/investigations/${state.activeInvestigationId}/summary`);
    state.summary = summary;
    renderDashboard(summary);
  } catch (err) {
    showAlert(`Failed to load investigation summary: ${err.message}`, 'danger');
  }
}

// Render Dashboard Data
function renderDashboard(s) {
  // Case Header
  document.getElementById('case-title-display').textContent = s.investigation.title;
  document.getElementById('case-number-badge').textContent = s.investigation.case_number;
  const statusBadge = document.getElementById('case-status-badge');
  if (statusBadge) {
    statusBadge.textContent = s.investigation.status;
    statusBadge.style.display = 'inline-block';
  }
  document.getElementById('case-desc-display').textContent = s.investigation.description || 'No case description recorded.';
  document.getElementById('case-created-display').textContent = new Date(s.investigation.created_at).toLocaleString();

  // Show report download button now that a real case is loaded
  const reportBtn = document.getElementById('btn-download-report');
  if (reportBtn) reportBtn.style.display = 'inline-block';

  // Metrics Grid
  document.getElementById('metric-sources').textContent = s.total_sources;
  document.getElementById('metric-evidence').textContent = s.total_evidence;
  document.getElementById('metric-findings').textContent = s.total_findings;
  document.getElementById('metric-anomalies').textContent = s.total_anomalies;
  document.getElementById('metric-relationships').textContent = s.total_relationships;
  document.getElementById('metric-activities').textContent = s.total_activities;

  // Tier Breakdown Bars & Counts
  const tiers = s.priority_tier_counts;
  const totalPrio = s.total_priority_results || 1; // avoid / 0

  document.getElementById('count-critical').textContent = tiers.CRITICAL;
  document.getElementById('bar-critical').style.width = `${(tiers.CRITICAL / totalPrio) * 100}%`;

  document.getElementById('count-high').textContent = tiers.HIGH;
  document.getElementById('bar-high').style.width = `${(tiers.HIGH / totalPrio) * 100}%`;

  document.getElementById('count-medium').textContent = tiers.MEDIUM;
  document.getElementById('bar-medium').style.width = `${(tiers.MEDIUM / totalPrio) * 100}%`;

  document.getElementById('count-low').textContent = tiers.LOW;
  document.getElementById('bar-low').style.width = `${(tiers.LOW / totalPrio) * 100}%`;

  document.getElementById('count-info').textContent = tiers.INFORMATIONAL;
  document.getElementById('bar-info').style.width = `${(tiers.INFORMATIONAL / totalPrio) * 100}%`;

  // Top Priority Table
  renderTopPriorityTable(s.top_priority_results);

  // Evidence Sources Table
  renderSourcesTable(s.sources);
}

function renderEmptyInvestigation() {
  document.getElementById('case-title-display').textContent = 'No active investigation';
  document.getElementById('case-number-badge').textContent = '—';
  
  const statusBadge = document.getElementById('case-status-badge');
  if (statusBadge) {
    statusBadge.textContent = '';
    statusBadge.style.display = 'none';
  }
  
  document.getElementById('case-desc-display').textContent = 'Please select a case from the dropdown or click "+ New Case" to create your first investigation and begin forensic triage.';
  document.getElementById('case-created-display').textContent = '—';
  
  // Hide report button when there is no active case
  const reportBtn = document.getElementById('btn-download-report');
  if (reportBtn) reportBtn.style.display = 'none';
  
  // Use dash to represent "no data available" cleanly
  document.getElementById('metric-sources').textContent = '—';
  document.getElementById('metric-evidence').textContent = '—';
  document.getElementById('metric-findings').textContent = '—';
  document.getElementById('metric-anomalies').textContent = '—';
  document.getElementById('metric-relationships').textContent = '—';
  document.getElementById('metric-activities').textContent = '—';

  // Set default pipeline status for empty state
  setPipelineState('No Case Selected', 'info');

  // Clear tier bars
  ['critical','high','medium','low','info'].forEach(t => {
    const bar = document.getElementById(`bar-${t}`);
    const cnt = document.getElementById(`count-${t}`);
    if (bar) bar.style.width = '0%';
    if (cnt) cnt.textContent = '—';
  });

  const tbody = document.getElementById('top-priority-tbody');
  if (tbody) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No active case. Select or create an investigation to view priority artifacts.</td></tr>';
  }
  const sTbody = document.getElementById('sources-tbody');
  if (sTbody) {
    sTbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No active case. Import forensic evidence to view sources.</td></tr>';
  }
}

function renderTopPriorityTable(results) {
  const tbody = document.getElementById('top-priority-tbody');
  tbody.innerHTML = '';

  if (!results || results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No prioritization results yet. Run "Prioritize Evidence" or "Prioritize Activities" from the pipeline bar above.</td></tr>';
    return;
  }

  results.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge ${getTierBadgeClass(r.priority_tier)}">${r.priority_tier}</span></td>
      <td class="font-mono"><strong>${r.priority_score.toFixed(1)}</strong></td>
      <td><span class="badge badge-mono">${r.target_type}</span></td>
      <td>
        <div style="font-size: 11px; max-width: 480px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${r.explanation_text}
        </div>
      </td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="viewDetailModal('Priority Result', ${escapeHtml(JSON.stringify(r))})">Inspect</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderSourcesTable(sources) {
  const tbody = document.getElementById('sources-tbody');
  tbody.innerHTML = '';

  if (!sources || sources.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No evidence sources ingested yet. Click "Import Evidence" to upload a CSV, JSON, or JSONL forensic log.</td></tr>';
    return;
  }

  sources.forEach(s => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${s.filename}</strong></td>
      <td><span class="badge badge-mono">${s.file_format}</span></td>
      <td class="font-mono text-sm" title="${s.sha256_hash}">${s.sha256_hash.substring(0, 16)}...</td>
      <td>${formatBytes(s.file_size_bytes)}</td>
      <td class="font-mono">${s.total_records}</td>
      <td class="font-mono">${s.normalized_records}</td>
      <td><span class="badge ${s.ingestion_status === 'COMPLETED' ? 'badge-open' : 'badge-mono'}">${s.ingestion_status}</span></td>
      <td class="text-sm">${new Date(s.ingested_at).toLocaleString()}</td>
    `;
    tbody.appendChild(tr);
  });
}

function getTierBadgeClass(tier) {
  switch (tier) {
    case 'CRITICAL': return 'alert-danger';
    case 'HIGH': return 'alert-warning';
    case 'MEDIUM': return 'badge-mono';
    case 'LOW': return 'badge-mono';
    default: return 'badge-mono';
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function formatEnum(val) {
  if (!val) return '';
  const map = {
    'RULE_MATCH': 'Rule Match',
    'IOC_MATCH': 'IOC Match',
    'ML_ANOMALY': 'ML Anomaly',
    'PROCESS_ACTIVITY': 'Process Activity'
  };
  return map[val] || val.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ');
}

function compactId(id) {
  if (!id) return '';
  const str = String(id);
  if (str.length > 12) return str.substring(0, 8) + '…' + str.substring(str.length - 4);
  return str;
}

/// Detail Inspection Modal Helper with Structured Forensic Explainability
window.viewDetailModal = function(title, dataObj) {
  const modal = document.getElementById('modal-detail');
  const titleEl = document.getElementById('modal-detail-title');
  const tierBadge = document.getElementById('modal-detail-tier-badge');
  const explainPanel = document.getElementById('modal-explainability-panel');
  const provPanel = document.getElementById('modal-provenance-panel');
  const genericPanel = document.getElementById('modal-generic-panel');
  const genericContent = document.getElementById('modal-generic-content');

  titleEl.textContent = `${title} Inspection`;
  tierBadge.className = 'badge';
  tierBadge.textContent = '';
  tierBadge.style.display = 'none';
  
  explainPanel.style.display = 'none';
  provPanel.style.display = 'none';
  genericPanel.style.display = 'none';
  genericContent.innerHTML = '';

  // Check if data is a PriorityResult
  if (dataObj && typeof dataObj.priority_score === 'number') {
    tierBadge.textContent = dataObj.priority_tier || 'UNKNOWN';
    tierBadge.className = `badge ${getTierBadgeClass(dataObj.priority_tier)}`;
    tierBadge.style.display = 'inline-block';

    explainPanel.style.display = 'block';
    document.getElementById('modal-score-value').textContent = dataObj.priority_score.toFixed(1);
    document.getElementById('modal-explanation-text').textContent = dataObj.explanation_text || 'No automated narrative available.';

    // Populate Factor Breakdown Grid
    const factorGrid = document.getElementById('modal-factor-grid');
    factorGrid.innerHTML = '';
    const breakdown = dataObj.factor_breakdown || {};
    const factors = breakdown.factors || [];

    if (factors.length === 0) {
      factorGrid.innerHTML = '<div style="grid-column: 1 / -1; text-align: center; color: var(--text-secondary); padding: 10px;">No priority factors available.</div>';
    } else {
      const nameMap = {
        'deterministic_signal': 'Deterministic Signal',
        'ml_anomaly': 'ML Anomaly',
        'contextual_cohesion': 'Contextual Cohesion',
        'contextual_corroboration': 'Contextual Corroboration'
      };

      factors.forEach(f => {
        const card = document.createElement('div');
        card.className = 'factor-card';
        
        const displayName = nameMap[f.name] || f.name.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        const contributionStr = (f.contribution >= 0 ? '+' : '') + f.contribution.toFixed(2);
        const weightStr = (f.weight * 100).toFixed(0) + '%';
        const valueStr = typeof f.normalized_value === 'number' ? Number(f.normalized_value.toFixed(4)).toString() : String(f.normalized_value);
        
        card.innerHTML = `
          <strong class="factor-name" style="text-transform: none; color: var(--text-primary); font-size: 11px; font-weight: 600; display: block; margin-bottom: 2px;">${escapeHtml(displayName)}</strong>
          <span class="factor-val" style="color: var(--prio-high); font-size: 12px; font-weight: 600; display: block;">Contribution: ${escapeHtml(contributionStr)}</span>
          <span class="text-muted" style="font-size: 11px; display: block;">Weight: ${escapeHtml(weightStr)}</span>
          <span class="text-muted" style="font-size: 11px; display: block;">Value: ${escapeHtml(valueStr)}</span>
          <p class="text-muted" style="margin-top: 4px; font-size: 11px; line-height: 1.3;">${escapeHtml(f.description || '')}</p>
        `;
        factorGrid.appendChild(card);
      });
    }

    // Populate Provenance Chain
    provPanel.style.display = 'block';
    const chainEl = document.getElementById('modal-provenance-chain');
    chainEl.innerHTML = `
      <div class="prov-node">
        <div class="prov-info">
          <span class="prov-label">Target Entity</span>
          <span class="prov-detail">${escapeHtml(dataObj.target_type)} : ${escapeHtml(dataObj.target_id || '')}</span>
        </div>
      </div>
      <div class="prov-node">
        <div class="prov-info">
          <span class="prov-label">Investigation Container</span>
          <span class="prov-detail">${escapeHtml(state.summary?.investigation?.case_number || 'ACTIVE_CASE')} (${escapeHtml(dataObj.investigation_id || '')})</span>
        </div>
      </div>
    `;
  } else {
    genericPanel.style.display = 'block';
    if (!dataObj || Object.keys(dataObj).length === 0) {
      genericContent.innerHTML = '<div style="color: var(--text-secondary); text-align: center;">No additional context available.</div>';
    } else {
      for (const [key, val] of Object.entries(dataObj)) {
        if (val === null || val === undefined || val === '') continue;
        if (typeof val === 'object' && Object.keys(val).length === 0) continue;
        
        let formattedVal = val;
        if (typeof val === 'object') {
          formattedVal = Object.entries(val).map(([k, v]) => `${k}: ${v}`).join(' | ');
        }
        
        const formattedKey = key.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        
        genericContent.innerHTML += `
          <div style="display: flex; flex-direction: column; padding-bottom: 6px; border-bottom: 1px solid var(--border-subtle);">
            <span style="font-size: 10px; font-weight: 600; text-transform: uppercase; color: var(--text-secondary);">${escapeHtml(formattedKey)}</span>
            <span style="font-size: 12px; color: var(--text-primary); margin-top: 2px; word-break: break-all;">${escapeHtml(String(formattedVal))}</span>
          </div>
        `;
      }
      if (genericContent.innerHTML === '') {
        genericContent.innerHTML = '<div style="color: var(--text-secondary); text-align: center;">No additional details available.</div>';
      }
    }
  }

  if (window.openModal) window.openModal('modal-detail');
  else document.getElementById('modal-detail').style.display = 'flex';
};

window.triggerNormalizeSource = async function(sourceId) {
  try {
    setPipelineState('Running Normalization...', 'warning');
    showAlert(`Normalizing evidence source ${sourceId.substring(0, 8)}...`, 'warning');
    const res = await apiRequest(`/evidence/sources/${sourceId}/normalize`, { method: 'POST' });
    showAlert(`Normalization completed: ${res.normalized_records} records normalized.`, 'success');
    await loadActiveInvestigationSummary();
    setPipelineState('Ready', 'success');
  } catch (err) {
    showAlert(`Normalization failed: ${err.message}`, 'danger');
    setPipelineState('Error', 'danger');
  }
};

function setPipelineState(statusText, badgeClass = 'mono') {
  const badge = document.getElementById('pipeline-state-badge');
  if (badge) {
    badge.textContent = statusText;
    badge.className = `badge badge-${badgeClass}`;
  }

  // Define keyword mappings to identify which stage is active/running
  const btnMap = {
    'import': ['Ingesting', 'Import'],
    'normalize': ['Normalize', 'Normalizing'],
    'detect': ['Detections', 'Detect'],
    'ml': ['ML Anomaly', 'ML analysis'],
    'correlate': ['Correlating', 'Correlation'],
    'activities': ['Clustering', 'Activity formation'],
    'prioritize-artifact': ['Prioritize Evidence', 'Prioritizing Evidence'],
    'prioritize-activity': ['Prioritize Activities', 'Prioritizing Activities']
  };

  Object.entries(btnMap).forEach(([key, terms]) => {
    const btn = document.getElementById(`btn-action-${key}`);
    if (btn) {
      btn.classList.remove('running');
      const isRunning = terms.some(t => statusText.includes(t));
      if (isRunning) {
        btn.classList.add('running');
      }
    }
  });
}

function showExampleEvidenceBanner() {
  const banner = document.getElementById('example-evidence-banner');
  if (banner) banner.style.display = 'flex';
}

function hideExampleEvidenceBanner() {
  const banner = document.getElementById('example-evidence-banner');
  if (banner) banner.style.display = 'none';
}

// Event Listeners Setup
function setupEventListeners() {
  // Login Form
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const errAlert = document.getElementById('auth-error-alert');
    errAlert.style.display = 'none';

    try {
      const res = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      state.token = res.access_token;
      state.user = res.user;
      localStorage.setItem('forensiq_token', res.access_token);
      // Store credentials for silent token refresh on expiry
      localStorage.setItem('forensiq_email', email);
      localStorage.setItem('forensiq_password', password);
      showDashboardView();
      await loadInvestigations();
    } catch (err) {
      errAlert.textContent = err.message;
      errAlert.style.display = 'block';
    }
  });

  // Logout Button
  document.getElementById('btn-logout').addEventListener('click', () => {
    handleAuthFailure();
  });

  // Download Investigation Report
  document.getElementById('btn-download-report').addEventListener('click', async () => {
    if (!state.activeInvestigationId) return;

    const btn     = document.getElementById('btn-download-report');
    const spinner = document.getElementById('btn-download-report-spinner');
    btn.style.display     = 'none';
    spinner.style.display = 'inline';

    try {
      const url = `${API_BASE}/investigations/${state.activeInvestigationId}/report`;
      const res = await fetch(url, {
        headers: { 'Authorization': `Bearer ${state.token}` },
      });

      if (!res.ok) {
        let detail = `HTTP ${res.status}`;
        try { const j = await res.json(); detail = j.detail || j.message || detail; } catch {}
        throw new Error(detail);
      }

      // Determine filename from Content-Disposition or fall back to case number
      let filename = 'ForensiQ_Report.pdf';
      const cd = res.headers.get('Content-Disposition');
      if (cd) {
        const m = cd.match(/filename="?([^";\n]+)"?/i);
        if (m) filename = m[1].trim();
      } else if (state.summary?.investigation?.case_number) {
        filename = `ForensiQ_${state.summary.investigation.case_number}_Report.pdf`;
      }

      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href     = blobUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
    } catch (err) {
      showAlert(`Report generation failed: ${err.message}`, 'danger');
    } finally {
      spinner.style.display = 'none';
      btn.style.display     = 'inline-block';
    }
  });

  // Case Selection Change
  document.getElementById('investigation-select').addEventListener('change', async (e) => {
    state.activeInvestigationId = e.target.value;
    localStorage.setItem('forensiq_active_inv_id', state.activeInvestigationId);
    await loadActiveInvestigationSummary();
  });

  // Tab Switching
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', async () => {
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetPaneId = tab.getAttribute('data-tab');
      document.getElementById(targetPaneId).classList.add('active');

      // Trigger lazy tab loads
      if (targetPaneId === 'tab-prioritization') await loadAllPrioritizations();
      if (targetPaneId === 'tab-findings') await loadFindings();
      if (targetPaneId === 'tab-ml') await loadMLAnomalies();
      if (targetPaneId === 'tab-correlations') await loadCorrelations();
      if (targetPaneId === 'tab-activities') await loadActivities();
      if (targetPaneId === 'tab-sources') await loadSources();
    });
  });

  // Filter Event Listeners
  const filterPrioTier = document.getElementById('filter-prio-tier');
  if (filterPrioTier) filterPrioTier.addEventListener('change', loadAllPrioritizations);

  const filterPrioMethod = document.getElementById('filter-prio-method');
  if (filterPrioMethod) filterPrioMethod.addEventListener('change', loadAllPrioritizations);

  const filterFindingType = document.getElementById('filter-finding-type');
  if (filterFindingType) filterFindingType.addEventListener('change', loadFindings);

  const filterRelType = document.getElementById('filter-rel-type');
  if (filterRelType) filterRelType.addEventListener('change', loadCorrelations);

  // Modal Handling Helpers
  let lastFocusedElement = null;

  window.openModal = function(modalId) {
    lastFocusedElement = document.activeElement;
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.style.display = 'flex';
      modal.setAttribute('aria-hidden', 'false');
      const focusable = modal.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (focusable) focusable.focus();
    }
  };

  window.closeModal = function(modal) {
    if (modal) {
      modal.style.display = 'none';
      modal.setAttribute('aria-hidden', 'true');
      if (lastFocusedElement) {
        lastFocusedElement.focus();
        lastFocusedElement = null;
      }
    }
  };

  // Modal Closures
  document.querySelectorAll('[data-close]').forEach(btn => {
    btn.addEventListener('click', () => {
      const modalId = btn.getAttribute('data-close');
      window.closeModal(document.getElementById(modalId));
    });
  });

  // Escape key closes modals
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay, .modal-backdrop').forEach(m => {
        if (m.style.display !== 'none') window.closeModal(m);
      });
    }
  });

  // New Case Modal Trigger
  document.getElementById('btn-new-case').addEventListener('click', () => {
    window.openModal('modal-new-case');
  });

  // Use Example Case — fills form fields, does NOT submit
  document.getElementById('btn-use-example-case').addEventListener('click', () => {
    document.getElementById('new-case-title').value = 'Suspicious Workstation Compromise';
    document.getElementById('new-case-number').value = 'CASE-DEMO-001';
    document.getElementById('new-case-desc').value =
      'Investigation of suspicious process execution and unusual activity observed on WORKSTATION-01. ' +
      'Includes PowerShell execution, credential dumping attempt via mimikatz, and outbound connection to known C2 IP.';
    document.getElementById('new-case-error').style.display = 'none';
  });



  // New Case Form Submit
  document.getElementById('form-new-case').addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = document.getElementById('new-case-title').value.trim();
    const case_number = document.getElementById('new-case-number').value.trim();
    const description = document.getElementById('new-case-desc').value.trim();
    const errAlert = document.getElementById('new-case-error');
    errAlert.style.display = 'none';

    // Detect if this is the example case so we can offer example evidence after creation
    const isExampleCase = (case_number === 'CASE-DEMO-001' ||
      title === 'Suspicious Workstation Compromise');

    try {
      const newInv = await apiRequest('/investigations', {
        method: 'POST',
        body: JSON.stringify({ title, case_number, description, status: 'OPEN' }),
      });
      if (window.closeModal) window.closeModal(document.getElementById('modal-new-case'));
      else document.getElementById('modal-new-case').style.display = 'none';
      showAlert(`Investigation '${newInv.title}' created successfully.`, 'success');
      state.activeInvestigationId = newInv.id;
      await loadInvestigations();

      // Show example evidence banner if case was created from example template
      if (isExampleCase) {
        showExampleEvidenceBanner();
      }
    } catch (err) {
      errAlert.textContent = err.message;
      errAlert.style.display = 'block';
    }
  });

  // Example Evidence Banner — Import button
  document.getElementById('btn-import-example-evidence').addEventListener('click', async () => {
    if (!state.activeInvestigationId) {
      showAlert('No active investigation. Please create a case first.', 'warning');
      return;
    }
    try {
      setPipelineState('Importing Example Evidence...', 'warning');
      showAlert('Fetching and importing example evidence CSV...', 'warning');

      // Fetch the example CSV from the backend static examples endpoint
      const csvUrl = `${API_BASE}/examples/example_evidence.csv`;
      const csvResp = await fetch(csvUrl);
      if (!csvResp.ok) throw new Error(`Could not fetch example CSV (${csvResp.status})`);
      const csvBlob = await csvResp.blob();
      const csvFile = new File([csvBlob], 'example_evidence.csv', { type: 'text/csv' });

      const formData = new FormData();
      formData.append('investigation_id', state.activeInvestigationId);
      formData.append('file', csvFile);
      formData.append('allow_duplicates', false);

      const res = await apiRequest('/evidence/import', { method: 'POST', body: formData });
      showAlert(
        `Example evidence imported: ${res.total_records} records (SHA-256: ${res.sha256_hash.substring(0, 12)}...). ` +
        `Click "Normalize" then run each pipeline stage.`,
        'success',
        10000
      );
      hideExampleEvidenceBanner();
      await loadActiveInvestigationSummary();
      setPipelineState('Ready', 'success');
    } catch (err) {
      showAlert(`Example evidence import failed: ${err.message}`, 'danger');
      setPipelineState('Error', 'danger');
    }
  });

  // Example Evidence Banner — Dismiss button
  document.getElementById('btn-dismiss-example-banner').addEventListener('click', () => {
    hideExampleEvidenceBanner();
  });

  // Update example evidence download link to use correct API base
  const exampleBannerDl = document.getElementById('btn-download-example-evidence');
  if (exampleBannerDl) {
    exampleBannerDl.href = `${API_BASE}/examples/example_evidence.csv`;
  }

  // Import Evidence Modal Trigger
  document.getElementById('btn-action-import').addEventListener('click', () => {
    if (window.openModal) window.openModal('modal-import-evidence');
    else document.getElementById('modal-import-evidence').style.display = 'flex';
  });



  // Import Evidence Form Submit
  document.getElementById('form-import-evidence').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById('import-file');
    const allowDup = document.getElementById('import-allow-dup').checked;
    const errAlert = document.getElementById('import-error');
    const succAlert = document.getElementById('import-success');
    errAlert.style.display = 'none';
    succAlert.style.display = 'none';

    if (!fileInput.files || fileInput.files.length === 0) return;

    const formData = new FormData();
    formData.append('investigation_id', state.activeInvestigationId);
    formData.append('file', fileInput.files[0]);
    formData.append('allow_duplicates', allowDup);

    try {
      document.getElementById('btn-submit-import').disabled = true;
      setPipelineState('Ingesting Evidence...', 'warning');
      const res = await apiRequest('/evidence/import', {
        method: 'POST',
        body: formData,
      });
      succAlert.textContent = `Evidence ingested: ${res.total_records} records (SHA-256: ${res.sha256_hash.substring(0, 12)}...)`;
      succAlert.style.display = 'block';
      setTimeout(() => {
        if (window.closeModal) window.closeModal(document.getElementById('modal-import-evidence'));
        else document.getElementById('modal-import-evidence').style.display = 'none';
        document.getElementById('btn-submit-import').disabled = false;
        loadActiveInvestigationSummary();
        setPipelineState('Ready', 'success');
      }, 1500);
    } catch (err) {
      errAlert.textContent = err.message;
      errAlert.style.display = 'block';
      document.getElementById('btn-submit-import').disabled = false;
      setPipelineState('Import Error', 'danger');
    }
  });

  // Pipeline Action Triggers
  setupPipelineActions();
}

function setupPipelineActions() {
  // Normalize All
  document.getElementById('btn-action-normalize').addEventListener('click', async () => {
    if (!state.summary || state.summary.sources.length === 0) {
      showAlert('No evidence sources available to normalize.', 'warning');
      return;
    }
    setPipelineState('Normalizing...', 'warning');
    for (const src of state.summary.sources) {
      await triggerNormalizeSource(src.id);
    }
    setPipelineState('Ready', 'success');
  });

  // Run Deterministic Detections
  document.getElementById('btn-action-detect').addEventListener('click', async () => {
    if (!state.summary || state.summary.sources.length === 0) {
      showAlert('No evidence sources available.', 'warning');
      return;
    }
    try {
      setPipelineState('Running Detections...', 'warning');
      showAlert('Executing deterministic detection rules & IOCs...', 'warning');
      for (const src of state.summary.sources) {
        const res = await apiRequest(`/detection/sources/${src.id}/analyze-rules`, { method: 'POST' });
        showAlert(`Detections complete for ${src.filename}: ${res.findings_created} new findings created.`, 'success');
      }
      await loadActiveInvestigationSummary();
      setPipelineState('Ready', 'success');
    } catch (err) {
      showAlert(`Detection failed: ${err.message}`, 'danger');
      setPipelineState('Error', 'danger');
    }
  });

  // Run ML Anomaly Detection
  document.getElementById('btn-action-ml').addEventListener('click', async () => {
    if (!state.summary || state.summary.sources.length === 0) {
      showAlert('No evidence sources available.', 'warning');
      return;
    }
    try {
      setPipelineState('Running ML Anomaly...', 'warning');
      showAlert('Executing unsupervised ML anomaly detection...', 'warning');
      for (const src of state.summary.sources) {
        const res = await apiRequest(`/ml/sources/${src.id}/analyze`, { method: 'POST' });
        showAlert(`ML Anomaly analysis complete: ${res.anomalies_detected} outliers flagged (${res.status}).`, 'success');
      }
      await loadActiveInvestigationSummary();
      setPipelineState('Ready', 'success');
    } catch (err) {
      showAlert(`ML analysis failed: ${err.message}`, 'danger');
      setPipelineState('Error', 'danger');
    }
  });

  // Run Contextual Correlation
  document.getElementById('btn-action-correlate').addEventListener('click', async () => {
    if (!state.summary || state.summary.sources.length === 0) {
      showAlert('No evidence sources available.', 'warning');
      return;
    }
    try {
      setPipelineState('Correlating Evidence...', 'warning');
      showAlert('Executing multi-dimensional evidence correlation...', 'warning');
      for (const src of state.summary.sources) {
        const res = await apiRequest(`/correlation/sources/${src.id}/analyze`, { method: 'POST' });
        showAlert(`Correlation complete: ${res.relationships_created} relationships formed.`, 'success');
      }
      await loadActiveInvestigationSummary();
      setPipelineState('Ready', 'success');
    } catch (err) {
      showAlert(`Correlation failed: ${err.message}`, 'danger');
      setPipelineState('Error', 'danger');
    }
  });

  // Cluster Activities
  document.getElementById('btn-action-activities').addEventListener('click', async () => {
    if (!state.summary || state.summary.sources.length === 0) {
      showAlert('No evidence sources available.', 'warning');
      return;
    }
    try {
      setPipelineState('Clustering Activities...', 'warning');
      showAlert('Clustering contextual evidence threads & activities...', 'warning');
      for (const src of state.summary.sources) {
        const res = await apiRequest(`/activities/sources/${src.id}/form`, { method: 'POST' });
        showAlert(`Activity formation complete: ${res.activities_created} coherent activities synthesized.`, 'success');
      }
      await loadActiveInvestigationSummary();
      setPipelineState('Ready', 'success');
    } catch (err) {
      showAlert(`Activity formation failed: ${err.message}`, 'danger');
      setPipelineState('Error', 'danger');
    }
  });

  // Prioritize Evidence
  document.getElementById('btn-action-prioritize-artifact').addEventListener('click', async () => {
    if (!state.activeInvestigationId) return;
    try {
      setPipelineState('Prioritizing Evidence...', 'warning');
      showAlert('Running Evidence Prioritization...', 'warning');
      const res = await apiRequest(`/prioritization/investigations/${state.activeInvestigationId}/baseline`, { method: 'POST' });
      showAlert(`Evidence Prioritization complete: ${res.results_created} artifact scores computed.`, 'success');
      await loadActiveInvestigationSummary();
      setPipelineState('Ready', 'success');
    } catch (err) {
      showAlert(`Prioritization failed: ${err.message}`, 'danger');
      setPipelineState('Error', 'danger');
    }
  });

  // Prioritize Activities
  document.getElementById('btn-action-prioritize-activity').addEventListener('click', async () => {
    if (!state.activeInvestigationId) return;
    try {
      setPipelineState('Prioritizing Activities...', 'warning');
      showAlert('Running Activity Prioritization...', 'warning');
      const res = await apiRequest(`/prioritization/investigations/${state.activeInvestigationId}/contextual`, { method: 'POST' });
      showAlert(`Activity Prioritization complete: ${res.results_created} activity scores computed.`, 'success');
      await loadActiveInvestigationSummary();
      setPipelineState('Ready', 'success');
    } catch (err) {
      showAlert(`Prioritization failed: ${err.message}`, 'danger');
      setPipelineState('Error', 'danger');
    }
  });
}

// Lazy Tab Data Loaders
async function loadAllPrioritizations() {
  if (!state.activeInvestigationId) return;
  const tbody = document.getElementById('all-prio-tbody');
  const tier = document.getElementById('filter-prio-tier').value;
  const method = document.getElementById('filter-prio-method').value;

  let query = `/prioritization/results?investigation_id=${state.activeInvestigationId}&limit=100`;
  if (tier) query += `&priority_tier=${tier}`;
  if (method) query += `&method_type=${method}`;

  try {
    const res = await apiRequest(query);
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No priority results yet. Run "Prioritize Evidence" or "Prioritize Activities" first.</td></tr>';
      return;
    }
    res.items.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="badge ${getTierBadgeClass(r.priority_tier)}">${r.priority_tier}</span></td>
        <td class="font-mono"><strong>${r.priority_score.toFixed(1)}</strong></td>
        <td><span class="badge badge-mono text-sm">${r.method_type === 'BASELINE_INDEPENDENT' ? 'Evidence' : 'Activity'}</span></td>
        <td><span class="badge badge-mono">${r.target_type}</span></td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="viewDetailModal('Priority Result Factors', ${escapeHtml(JSON.stringify(r))})">View Factors</button>
        </td>
        <td style="max-width: 320px; font-size: 11px;">${escapeHtml(r.explanation_text || '')}</td>
        <td class="text-sm">${new Date(r.computed_at).toLocaleString()}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-danger text-center">Error loading results: ${err.message}</td></tr>`;
  }
}

async function loadFindings() {
  if (!state.activeInvestigationId) return;
  const tbody = document.getElementById('findings-tbody');
  const ftype = document.getElementById('filter-finding-type').value;

  let query = `/detection/findings?investigation_id=${state.activeInvestigationId}&limit=100`;
  if (ftype) query += `&finding_type=${ftype}`;

  try {
    const res = await apiRequest(query);
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No findings yet. Run "Run Detections" to apply rules and IOC matching to normalized evidence.</td></tr>';
      return;
    }
    res.items.forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="badge badge-mono">${formatEnum(f.finding_type)}</span></td>
        <td class="font-mono"><strong>${f.severity.toFixed(2)}</strong></td>
        <td><strong class="font-mono text-sm">${f.rule_id}</strong></td>
        <td>${f.mitre_tactic ? `<span class="badge badge-mono">${f.mitre_tactic} / ${f.mitre_technique || ''}</span>` : '<span class="text-muted">None</span>'}</td>
        <td style="max-width: 400px; font-size: 11px;">${escapeHtml(f.description || '')}</td>
        <td class="text-sm">${new Date(f.created_at).toLocaleString()}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-danger text-center">Error loading findings: ${err.message}</td></tr>`;
  }
}

async function loadMLAnomalies() {
  if (!state.activeInvestigationId) return;
  const tbody = document.getElementById('ml-anomalies-tbody');

  try {
    const res = await apiRequest(`/detection/findings?investigation_id=${state.activeInvestigationId}&finding_type=ML_ANOMALY&limit=100`);
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No anomalies detected. Run "Run ML Anomaly" — requires at least 10 normalized evidence records.</td></tr>';
      return;
    }
    res.items.forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="badge badge-mono">${f.rule_id}</span></td>
        <td class="font-mono"><strong>${f.severity.toFixed(2)}</strong></td>
        <td><span class="badge alert-warning">ANOMALY</span></td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="viewDetailModal('Anomaly Details', ${escapeHtml(JSON.stringify({
            'Anomaly Score': f.severity.toFixed(2),
            'Status': 'Anomaly Detected',
            'Model': f.rule_id || 'Isolation Forest',
            'Description': f.description || '',
            'Detected At': new Date(f.created_at).toLocaleString()
          }))})">Inspect Details</button>
        </td>
        <td style="max-width: 420px; font-size: 11px;">${escapeHtml(f.description || '')}</td>
        <td class="text-sm">${new Date(f.created_at).toLocaleString()}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-danger text-center">Error loading anomalies: ${err.message}</td></tr>`;
  }
}

async function loadCorrelations() {
  if (!state.activeInvestigationId) return;
  const tbody = document.getElementById('correlations-tbody');
  const rtype = document.getElementById('filter-rel-type').value;

  let query = `/correlation/relationships?investigation_id=${state.activeInvestigationId}&limit=100`;
  if (rtype) query += `&relationship_type=${rtype}`;

  try {
    const res = await apiRequest(query);
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No evidence correlations discovered yet. Run "Correlate" — requires at least 2 normalized evidence records.</td></tr>';
      return;
    }
    res.items.forEach(rel => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="badge badge-mono">${formatEnum(rel.relationship_type)}</span></td>
        <td class="font-mono"><strong>${rel.weight.toFixed(2)}</strong></td>
        <td class="font-mono text-sm" title="${rel.source_evidence_id}">${compactId(rel.source_evidence_id)}</td>
        <td class="font-mono text-sm" title="${rel.target_evidence_id}">${compactId(rel.target_evidence_id)}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="viewDetailModal('Context Attributes', ${escapeHtml(JSON.stringify(rel.context_attributes))})">View Attributes</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-danger text-center">Error loading correlations: ${err.message}</td></tr>`;
  }
}

async function loadActivities() {
  if (!state.activeInvestigationId) return;
  const tbody = document.getElementById('activities-tbody');

  try {
    const res = await apiRequest(`/activities?investigation_id=${state.activeInvestigationId}&limit=100`);
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No activity clusters formed yet. Run "Cluster Activities" after correlating evidence.</td></tr>';
      return;
    }
    res.items.forEach(act => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${escapeHtml(act.title)}</strong></td>
        <td><span class="badge badge-mono">${formatEnum(act.activity_type)}</span></td>
        <td><span class="badge badge-open">${act.status}</span></td>
        <td class="text-sm">${new Date(act.start_time).toLocaleString()}</td>
        <td class="text-sm">${new Date(act.end_time).toLocaleString()}</td>
        <td class="font-mono">${act.evidence_count}</td>
        <td class="font-mono">${act.finding_count}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="viewDetailModal('Activity Details', ${escapeHtml(JSON.stringify({
            'Activity Title': act.title,
            'Activity Type': formatEnum(act.activity_type),
            'Status': act.status,
            'Start Time': new Date(act.start_time).toLocaleString(),
            'End Time': new Date(act.end_time).toLocaleString(),
            'Evidence Count': act.evidence_count,
            'Finding Count': act.finding_count,
            'Description': act.description || 'No description available.',
            'Useful Context': (act.context_attributes && Object.keys(act.context_attributes).length > 0) ? Object.entries(act.context_attributes).map(([k, v]) => k + ': ' + v).join(', ') : 'None'
          }))})">Inspect</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-danger text-center">Error loading activities: ${err.message}</td></tr>`;
  }
}

async function loadSources() {
  if (!state.activeInvestigationId) return;
  try {
    const sources = await apiRequest(`/investigations/${state.activeInvestigationId}/sources`);
    renderSourcesTable(sources);
  } catch (err) {
    showAlert(`Failed to refresh sources: ${err.message}`, 'danger');
  }
}

// Start application when DOM is ready
document.addEventListener('DOMContentLoaded', initApp);

