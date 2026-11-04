/**
 * ForensiQ - Investigation Dashboard Logic & API Client
 * Phase 2.1: Robust Pipeline Coordinator, Prerequisite Semantics & Investigation Concurrency Safety
 * Authentication removed — local single-investigator mode.
 */

// Dynamic API Base URL
const isDedicatedDevClient = window.location.port === '5173' || window.location.port === '3000';
const API_BASE = isDedicatedDevClient ? `http://${window.location.hostname}:8000/api/v1` : '/api/v1';

// Application State
const state = {
  investigations: [],
  activeInvestigationId: localStorage.getItem('forensiq_active_inv_id') || null,
  summary: null,
  isPipelineRunning: false,
  activeTab: 'tab-overview',
  activeSubtab: 'subpane-activities',
  sourcesCache: new Map(),
  selectedEvidenceId: null,
  currentEvidenceItems: [],
  investigationVersion: 0,
  requestSeq: {
    summary: 0,
    sources: 0,
    evidence: 0,
    activities: 0,
    findings: 0,
    correlations: 0,
    prioritization: 0,
    inspector: 0,
  },
  evidencePagination: {
    offset: 0,
    limit: 25,
    total: 0,
    source_id: '',
    event_type: '',
    user_id: '',
    device_id: '',
    loading: false,
    requestId: 0,
  },
  findingsState: {
    rawFindings: [],
    filteredFindings: [],
    selectedFindingId: null,
    searchQuery: '',
    priorityFilter: '',
    methodFilter: '',
    activityFilter: '',
  },
};

// URL-Driven Route Configuration (Phase 3)
const VALID_TABS = ['overview', 'evidence', 'analysis', 'report'];
const TAB_MAP = {
  'overview': 'tab-overview',
  'evidence': 'tab-evidence',
  'analysis': 'tab-analysis',
  'report': 'tab-report'
};
const PANE_TO_TAB = {
  'tab-overview': 'overview',
  'tab-evidence': 'evidence',
  'tab-analysis': 'analysis',
  'tab-report': 'report',
  'tab-findings': 'report'
};

let isUpdatingRouteInternally = false;

function parseCurrentRoute() {
  const hash = window.location.hash || '';
  const match = hash.match(/^#\/case\/([^\/]*)(?:\/([^\/]+))?$/);
  if (!match) {
    return { caseId: null, tab: 'overview' };
  }
  const rawCaseId = match[1] ? decodeURIComponent(match[1]).trim() : null;
  const rawTab = match[2] ? decodeURIComponent(match[2]).trim().toLowerCase() : 'overview';
  const tab = VALID_TABS.includes(rawTab) ? rawTab : 'overview';
  return {
    caseId: rawCaseId || null,
    tab: tab
  };
}

function updateRouteHash(caseId, tabName) {
  const cId = caseId !== undefined ? caseId : state.activeInvestigationId;
  const currentPane = state.activeTab;
  const tName = tabName || PANE_TO_TAB[currentPane] || 'overview';
  const targetHash = `#/case/${cId ? encodeURIComponent(cId) : ''}/${tName}`;
  if (window.location.hash !== targetHash) {
    isUpdatingRouteInternally = true;
    window.location.hash = targetHash;
    setTimeout(() => { isUpdatingRouteInternally = false; }, 0);
  }
}

function switchTabInternal(targetPaneId) {
  document.querySelectorAll('.nav-tab').forEach(t => {
    if (t.getAttribute('data-tab') === targetPaneId) {
      t.classList.add('active');
    } else {
      t.classList.remove('active');
    }
  });
  document.querySelectorAll('.tab-pane').forEach(p => {
    if (p.id === targetPaneId) {
      p.classList.add('active');
    } else {
      p.classList.remove('active');
    }
  });
  state.activeTab = targetPaneId;
}

function navigateToTab(tabShortName) {
  const targetPaneId = TAB_MAP[tabShortName] || 'tab-overview';
  if (state.activeTab === targetPaneId) return;
  switchTabInternal(targetPaneId);
  updateRouteHash(state.activeInvestigationId, tabShortName);
  refreshActiveDestinationView();
}

// Pipeline Stages Specification (7 Human-Readable Stages)
const PIPELINE_STAGES = [
  { id: 1, key: 'normalize', name: '01 Prepare Evidence', chipId: 'chip-stage-1', scope: 'source' },
  { id: 2, key: 'detect', name: '02 Detect Threats', chipId: 'chip-stage-2', scope: 'source' },
  { id: 3, key: 'ml', name: '03 AI Anomalies', chipId: 'chip-stage-3', scope: 'source', minRecords: 10 },
  { id: 4, key: 'correlate', name: '04 Connect Events', chipId: 'chip-stage-4', scope: 'source', minRecords: 2 },
  { id: 5, key: 'activities', name: '05 Group Activities', chipId: 'chip-stage-5', scope: 'source' },
  { id: 6, key: 'prioritize-baseline', name: '06 Rank Evidence', chipId: 'chip-stage-6', scope: 'investigation' },
  { id: 7, key: 'prioritize-contextual', name: '07 Rank Activities', chipId: 'chip-stage-7', scope: 'investigation' },
];

// API Client Helper
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = options.headers || {};

  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  try {
    const res = await fetch(url, { ...options, headers });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.detail || `Request failed with status ${res.status}`);
    }
    return data;
  } catch (err) {
    console.error(`API Error on ${endpoint}:`, err);
    throw err;
  }
}

// Global Banner Notifications
function showAlert(message, type = 'warning', timeoutMs = 6000) {
  const alertEl = document.getElementById('dashboard-alert');
  if (!alertEl) return;
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
  setupPipelineCoordinator();

  // Sample evidence dropdown
  const sampleSelect = document.getElementById('sample-evidence-select');
  const sampleDownloadLink = document.getElementById('btn-download-example');

  if (sampleSelect) {
    apiRequest('/examples').then(samples => {
      sampleSelect.innerHTML = '<option value="">Select a sample\u2026</option>';
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

  // Setup Hash Routing (Phase 3)
  window.addEventListener('hashchange', handleHashChange);

  // Load investigations immediately — local single investigator mode
  await loadInvestigations();
}

// URL Hash Router Handler
async function handleHashChange() {
  if (isUpdatingRouteInternally) return;

  const { caseId, tab } = parseCurrentRoute();
  const targetPaneId = TAB_MAP[tab] || 'tab-overview';

  // 1. If route specifies a caseId different from active case
  if (caseId && caseId !== state.activeInvestigationId) {
    if (state.isPipelineRunning) {
      showAlert('Pipeline is currently executing. Navigation is locked until execution completes.', 'warning');
      updateRouteHash();
      return;
    }

    try {
      // Validate requested case with GET /api/v1/investigations/{id}
      const inv = await apiRequest(`/investigations/${encodeURIComponent(caseId)}`);
      state.investigationVersion++;
      state.selectedEvidenceId = null;
      renderEvidenceInspector(null);

      state.activeInvestigationId = inv.id;
      localStorage.setItem('forensiq_active_inv_id', inv.id);

      // Ensure in list and dropdown
      if (!state.investigations.some(i => i.id === inv.id)) {
        state.investigations.push(inv);
      }
      const selectEl = document.getElementById('investigation-select');
      if (selectEl) {
        let opt = selectEl.querySelector(`option[value="${inv.id}"]`);
        if (!opt) {
          opt = document.createElement('option');
          opt.value = inv.id;
          opt.textContent = `[${inv.case_number}] ${inv.title}`;
          selectEl.appendChild(opt);
        }
        selectEl.value = inv.id;
      }

      resetCaseScopedState();
      switchTabInternal(targetPaneId);
      togglePipelineControls(true);
      await loadActiveInvestigationSummary();
      await refreshActiveDestinationView();
      return;
    } catch (err) {
      showAlert(`Investigation "${caseId}" could not be found or loaded: ${err.message}`, 'danger');
      state.activeInvestigationId = null;
      localStorage.removeItem('forensiq_active_inv_id');
      renderEmptyInvestigation();
      updateRouteHash('', 'overview');
      return;
    }
  }

  // 2. If route has no caseId, but cases exist
  if (!caseId && state.investigations.length > 0) {
    const firstCaseId = state.activeInvestigationId || state.investigations[0].id;
    updateRouteHash(firstCaseId, tab);
    return;
  }

  // 3. Same case, just tab switch
  if (state.activeTab !== targetPaneId) {
    switchTabInternal(targetPaneId);
    await refreshActiveDestinationView();
  }
}

// Load Investigations
async function loadInvestigations() {
  const route = parseCurrentRoute();

  try {
    const res = await apiRequest('/investigations?limit=100');
    state.investigations = res.items || [];

    const selectEl = document.getElementById('investigation-select');
    selectEl.innerHTML = '';

    // If route specified a caseId, try direct lookup if not in top 100
    let targetInv = null;
    if (route.caseId) {
      targetInv = state.investigations.find(i => i.id === route.caseId);
      if (!targetInv) {
        try {
          targetInv = await apiRequest(`/investigations/${encodeURIComponent(route.caseId)}`);
          if (targetInv && targetInv.id) {
            state.investigations.unshift(targetInv);
          }
        } catch {
          showAlert(`Requested investigation "${route.caseId}" could not be found.`, 'warning');
          targetInv = null;
        }
      }
    }

    if (state.investigations.length === 0) {
      selectEl.innerHTML = '<option value="">No investigations yet</option>';
      state.activeInvestigationId = null;
      localStorage.removeItem('forensiq_active_inv_id');
      renderEmptyInvestigation();
      updateRouteHash('', route.tab || 'overview');
      return;
    }

    state.investigations.forEach(inv => {
      const opt = document.createElement('option');
      opt.value = inv.id;
      opt.textContent = `[${inv.case_number}] ${inv.title}`;
      selectEl.appendChild(opt);
    });

    if (targetInv) {
      state.activeInvestigationId = targetInv.id;
    } else if (state.activeInvestigationId && state.investigations.some(i => i.id === state.activeInvestigationId)) {
      // Keep preserved id
    } else {
      state.activeInvestigationId = state.investigations[0].id;
    }

    selectEl.value = state.activeInvestigationId;
    localStorage.setItem('forensiq_active_inv_id', state.activeInvestigationId);

    // Switch to route's tab or overview
    const initialPane = TAB_MAP[route.tab] || 'tab-overview';
    switchTabInternal(initialPane);
    updateRouteHash(state.activeInvestigationId, route.tab || 'overview');

    togglePipelineControls(true);
    await loadActiveInvestigationSummary();
    await refreshActiveDestinationView();
  } catch (err) {
    showAlert(`Failed to load investigations: ${err.message}`, 'danger');
  }
}

function resetCaseScopedState() {
  state.selectedEvidenceId = null;
  state.currentEvidenceItems = [];
  state.evidencePagination.offset = 0;
  state.evidencePagination.source_id = '';
  state.evidencePagination.event_type = '';
  state.evidencePagination.user_id = '';
  state.evidencePagination.device_id = '';
  state.sourcesCache.clear();

  // Reset filter inputs if in DOM
  const srcFilter = document.getElementById('filter-evidence-source');
  if (srcFilter) srcFilter.value = '';
  const typeFilter = document.getElementById('filter-evidence-event-type');
  if (typeFilter) typeFilter.value = '';
  const userFilter = document.getElementById('filter-evidence-user');
  if (userFilter) userFilter.value = '';
  const devFilter = document.getElementById('filter-evidence-device');
  if (devFilter) devFilter.value = '';

  renderEvidenceInspector(null);
}

// Load Active Investigation Summary (with investigation-switch concurrency guard)
async function loadActiveInvestigationSummary() {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.summary;

  try {
    const summary = await apiRequest(`/investigations/${currentInvId}/summary`);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.summary) return; // Stale response guard
    state.summary = summary;
    renderDashboard(summary);
  } catch (err) {
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.summary) return;
    showAlert(`Failed to load investigation summary: ${err.message}`, 'danger');
  }
}

// ==========================================================================
// Modal Helpers & Case/Evidence Creation Dialog Triggers
// ==========================================================================
let lastFocusedElement = null;

function getFocusableElements(container) {
  if (!container) return [];
  return Array.from(container.querySelectorAll(
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  )).filter(el => {
    return el.offsetParent !== null || el.offsetWidth > 0 || el.offsetHeight > 0;
  });
}

window.openModal = function(modalId) {
  const triggerEl = document.activeElement;
  lastFocusedElement = triggerEl;
  const modal = typeof modalId === 'string' ? document.getElementById(modalId) : modalId;
  if (modal) {
    modal._triggerElement = triggerEl;
    modal.style.display = 'flex';
    modal.setAttribute('aria-hidden', 'false');
    const focusable = getFocusableElements(modal);
    if (focusable.length > 0) {
      focusable[0].focus();
    } else {
      modal.setAttribute('tabindex', '-1');
      modal.focus();
    }
  }
};

window.closeModal = function(modal) {
  const modalEl = typeof modal === 'string' ? document.getElementById(modal) : modal;
  if (modalEl) {
    modalEl.style.display = 'none';
    modalEl.setAttribute('aria-hidden', 'true');
    const restoreEl = modalEl._triggerElement || lastFocusedElement;
    if (restoreEl && typeof restoreEl.focus === 'function') {
      restoreEl.focus();
    }
    modalEl._triggerElement = null;
    lastFocusedElement = null;
  }
};

function openNewCaseModal() {
  if (state.isPipelineRunning) {
    showAlert('Pipeline is executing. Please wait for completion before creating cases.', 'warning');
    return;
  }
  const form = document.getElementById('form-new-case');
  if (form) form.reset();
  const errAlert = document.getElementById('new-case-error');
  if (errAlert) errAlert.style.display = 'none';

  window.openModal('modal-new-case');
}

function openImportEvidenceModal() {
  if (state.isPipelineRunning) {
    showAlert('Pipeline is currently executing. Wait for completion before importing evidence.', 'warning');
    return;
  }
  if (!state.activeInvestigationId) {
    showAlert('No active investigation. Please create or select a case first.', 'warning');
    openNewCaseModal();
    return;
  }
  const form = document.getElementById('form-import-evidence');
  if (form) form.reset();
  const errAlert = document.getElementById('import-error');
  if (errAlert) errAlert.style.display = 'none';
  const succAlert = document.getElementById('import-success');
  if (succAlert) succAlert.style.display = 'none';

  window.openModal('modal-import-evidence');
}

// State-Aware Guided Investigation Workflow Guide
function updateWorkflowGuide() {
  const step1 = document.getElementById('wf-step-1');
  const step2 = document.getElementById('wf-step-2');
  const step3 = document.getElementById('wf-step-3');
  const step4 = document.getElementById('wf-step-4');
  const step5 = document.getElementById('wf-step-5');

  const status1 = document.getElementById('wf-status-1');
  const status2 = document.getElementById('wf-status-2');
  const status3 = document.getElementById('wf-status-3');
  const status4 = document.getElementById('wf-status-4');
  const status5 = document.getElementById('wf-status-5');

  const hintEl = document.getElementById('workflow-step-hint');
  const actionBtn = document.getElementById('workflow-action-btn');

  if (!step1 || !actionBtn) return;

  const hasCase = Boolean(state.activeInvestigationId);
  const totalSources = state.summary ? state.summary.total_sources : state.sourcesCache.size;
  const hasSources = totalSources > 0;
  const totalEvidence = state.summary ? state.summary.total_evidence : 0;
  const totalFindings = state.summary ? (state.summary.total_findings + state.summary.total_anomalies) : 0;
  const totalPrio = state.summary ? state.summary.total_priority_results : 0;
  const isAnalyzed = totalEvidence > 0 && (totalPrio > 0 || totalFindings > 0);
  const isRunning = state.isPipelineRunning;

  // Reset all step classes to pending
  [step1, step2, step3, step4, step5].forEach(el => {
    el.className = 'workflow-step pending';
  });

  if (!hasCase) {
    // Step 1 active: Select or create case
    step1.className = 'workflow-step active';
    if (status1) status1.textContent = 'Active';
    if (status2) status2.textContent = 'Pending';
    if (status3) status3.textContent = 'Pending';
    if (status4) status4.textContent = 'Pending';
    if (status5) status5.textContent = 'Pending';

    if (hintEl) hintEl.textContent = 'Step 1 of 5: Select Case';
    actionBtn.textContent = '+ New Case';
    actionBtn.disabled = false;
    actionBtn.onclick = openNewCaseModal;
  } else if (!hasSources) {
    // Step 1 done, Step 2 active: Upload evidence
    step1.className = 'workflow-step completed';
    if (status1) status1.textContent = '✓ Done';
    step2.className = 'workflow-step active';
    if (status2) status2.textContent = 'Active';
    if (status3) status3.textContent = 'Pending';
    if (status4) status4.textContent = 'Pending';
    if (status5) status5.textContent = 'Pending';

    if (hintEl) hintEl.textContent = 'Step 2 of 5: Upload Evidence';
    actionBtn.textContent = 'Import Evidence CSV';
    actionBtn.disabled = false;
    actionBtn.onclick = openImportEvidenceModal;
  } else if (isRunning) {
    // Pipeline is actively executing (Step 3 running)
    step1.className = 'workflow-step completed';
    if (status1) status1.textContent = '✓ Done';
    step2.className = 'workflow-step completed';
    if (status2) status2.textContent = '✓ Done';
    step3.className = 'workflow-step active';
    if (status3) status3.textContent = 'Running...';
    if (status4) status4.textContent = 'Pending';
    if (status5) status5.textContent = 'Pending';

    if (hintEl) hintEl.textContent = 'Step 3: Analyzing...';
    actionBtn.textContent = 'Analyzing...';
    actionBtn.disabled = true;
    actionBtn.onclick = null;
  } else if (!isAnalyzed) {
    // Step 1 & 2 done, Step 3 ready: Run Analyze Investigation
    step1.className = 'workflow-step completed';
    if (status1) status1.textContent = '✓ Done';
    step2.className = 'workflow-step completed';
    if (status2) status2.textContent = '✓ Done';
    step3.className = 'workflow-step active';
    if (status3) status3.textContent = 'Ready';
    if (status4) status4.textContent = 'Pending';
    if (status5) status5.textContent = 'Pending';

    if (hintEl) hintEl.textContent = 'Step 3 of 5: Ready to Analyze';
    actionBtn.textContent = 'Analyze Investigation';
    actionBtn.disabled = false;
    actionBtn.onclick = () => {
      runFullAnalysisPipeline();
    };
  } else {
    // Analysis completed! Steps 1, 2, 3 completed. Step 4 & 5 available.
    step1.className = 'workflow-step completed';
    if (status1) status1.textContent = '✓ Done';
    step2.className = 'workflow-step completed';
    if (status2) status2.textContent = '✓ Done';
    step3.className = 'workflow-step completed';
    if (status3) status3.textContent = '✓ Done';
    step4.className = 'workflow-step completed';
    if (status4) status4.textContent = `${totalFindings} Finding${totalFindings === 1 ? '' : 's'}`;
    step5.className = 'workflow-step active';
    if (status5) status5.textContent = 'Ready';

    if (hintEl) hintEl.textContent = 'Ready: Review & Report';
    actionBtn.textContent = 'Download PDF Report';
    actionBtn.disabled = false;
    actionBtn.onclick = () => {
      const findingsBtn = document.getElementById('btn-findings-download-report');
      const findingsSpinner = document.getElementById('btn-findings-download-report-spinner');
      downloadInvestigationReport(findingsBtn, findingsSpinner);
    };
  }
}

// Render Dashboard Data
function renderDashboard(s) {
  document.getElementById('case-title-display').textContent = s.investigation.title;
  document.getElementById('case-number-badge').textContent = s.investigation.case_number;
  const statusBadge = document.getElementById('case-status-badge');
  if (statusBadge) {
    statusBadge.textContent = s.investigation.status;
    statusBadge.style.display = 'inline-block';
  }
  document.getElementById('case-desc-display').textContent = s.investigation.description || 'No case description recorded.';
  document.getElementById('case-created-display').textContent = new Date(s.investigation.created_at).toLocaleString();

  const reportBtnFindings = document.getElementById('btn-findings-download-report');
  if (reportBtnFindings) reportBtnFindings.disabled = false;

  const elSources = document.getElementById('metric-sources');
  if (elSources) elSources.textContent = s.total_sources;
  const elEvidence = document.getElementById('metric-evidence');
  if (elEvidence) elEvidence.textContent = s.total_evidence;
  const elFindings = document.getElementById('metric-findings');
  if (elFindings) elFindings.textContent = (s.total_findings || 0) + (s.total_anomalies || 0);
  const elActivities = document.getElementById('metric-activities');
  if (elActivities) elActivities.textContent = s.total_activities;

  const quickStatus = document.getElementById('case-pipeline-quick-status');
  if (quickStatus) {
    quickStatus.textContent = s.total_findings > 0 ? `${s.total_findings} FINDINGS` : (s.total_sources > 0 ? 'SOURCES READY' : 'EMPTY');
    quickStatus.className = `badge font-mono ${s.total_findings > 0 ? 'badge-danger' : 'badge-mono'}`;
  }

  updateReportPreview(s);

  const tiers = s.priority_tier_counts;
  const totalPrio = s.total_priority_results || 1;

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

  renderTopPriorityTable(s.top_priority_results);
  renderSourcesTable(s.sources);
  updateWorkflowGuide();
}

function updateReportPreview(s) {
  const caseEl = document.getElementById('report-preview-case');
  const srcEl = document.getElementById('report-preview-sources');
  const threatsEl = document.getElementById('report-preview-threats');
  const actEl = document.getElementById('report-preview-activities');

  if (!s || !s.investigation) {
    if (caseEl) caseEl.textContent = '\u2014';
    if (srcEl) srcEl.textContent = '0 files';
    if (threatsEl) threatsEl.textContent = '0 findings';
    if (actEl) actEl.textContent = '0 threads';
    return;
  }

  if (caseEl) caseEl.textContent = s.investigation.case_number || '\u2014';
  if (srcEl) srcEl.textContent = `${s.total_sources || 0} files (${s.total_evidence || 0} events)`;
  if (threatsEl) threatsEl.textContent = `${s.total_findings || 0} findings`;
  if (actEl) actEl.textContent = `${s.total_activities || 0} threads`;
}

function renderEmptyInvestigation() {
  document.getElementById('case-title-display').textContent = 'No active investigation';
  document.getElementById('case-number-badge').textContent = '\u2014';

  const statusBadge = document.getElementById('case-status-badge');
  if (statusBadge) {
    statusBadge.textContent = '';
    statusBadge.style.display = 'none';
  }

  document.getElementById('case-desc-display').textContent = 'Please select a case from the dropdown or click "+ New Case" to create your first investigation and begin forensic triage.';
  document.getElementById('case-created-display').textContent = '\u2014';

  const reportBtnFindings = document.getElementById('btn-findings-download-report');
  if (reportBtnFindings) reportBtnFindings.disabled = true;

  const elSources = document.getElementById('metric-sources');
  if (elSources) elSources.textContent = '\u2014';
  const elEvidence = document.getElementById('metric-evidence');
  if (elEvidence) elEvidence.textContent = '\u2014';
  const elFindings = document.getElementById('metric-findings');
  if (elFindings) elFindings.textContent = '\u2014';
  const elActivities = document.getElementById('metric-activities');
  if (elActivities) elActivities.textContent = '\u2014';

  const quickStatus = document.getElementById('case-pipeline-quick-status');
  if (quickStatus) {
    quickStatus.textContent = 'NO CASE';
    quickStatus.className = 'badge badge-mono font-mono';
  }

  updateReportPreview(null);

  setPipelineState('No Case Selected', 'info');
  setPipelineBannerLog('No active investigation. Select or create an investigation case to enable pipeline analysis.', 'normal');
  resetAllStageChips();

  // Disable analysis triggers while keeping case creation, case selector, and navigation enabled
  const runFullBtn = document.getElementById('btn-run-full-analysis');
  const runSingleBtn = document.getElementById('btn-run-single-stage');
  const selectStage = document.getElementById('select-pipeline-stage');
  const newCaseBtn = document.getElementById('btn-new-case');
  const importBtnHeader = document.getElementById('btn-action-import');
  const importBtnTab = document.getElementById('btn-evidence-tab-import');

  if (runFullBtn) runFullBtn.disabled = true;
  if (runSingleBtn) runSingleBtn.disabled = true;
  if (selectStage) selectStage.disabled = true;
  if (newCaseBtn) newCaseBtn.disabled = false;
  if (importBtnHeader) importBtnHeader.disabled = false;
  if (importBtnTab) importBtnTab.disabled = false;

  ['critical','high','medium','low','info'].forEach(t => {
    const bar = document.getElementById(`bar-${t}`);
    const cnt = document.getElementById(`count-${t}`);
    if (bar) bar.style.width = '0%';
    if (cnt) cnt.textContent = '\u2014';
  });

  const tbody = document.getElementById('top-priority-tbody');
  if (tbody) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No active case. Select or create an investigation to view priority artifacts.</td></tr>';
  }
  const sTbody = document.getElementById('sources-tbody');
  if (sTbody) {
    sTbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">No active case. Import forensic evidence to view sources.</td></tr>';
  }
  const actTbody = document.getElementById('activities-tbody');
  if (actTbody) actTbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No active case.</td></tr>';
  const corrTbody = document.getElementById('correlations-tbody');
  if (corrTbody) corrTbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No active case.</td></tr>';
  const mlTbody = document.getElementById('ml-anomalies-tbody');
  if (mlTbody) mlTbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No active case.</td></tr>';
  const prioTbody = document.getElementById('all-prio-tbody');
  if (prioTbody) prioTbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No active case.</td></tr>';
  const findTbody = document.getElementById('findings-tbody');
  if (findTbody) findTbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No active case.</td></tr>';
  const elFindTotal = document.getElementById('findings-count-total');
  if (elFindTotal) elFindTotal.textContent = '0';
  const elFindHigh = document.getElementById('findings-count-high');
  if (elFindHigh) elFindHigh.textContent = '0';
  const elFindMed = document.getElementById('findings-count-medium');
  if (elFindMed) elFindMed.textContent = '0';
  const elFindLow = document.getElementById('findings-count-low');
  if (elFindLow) elFindLow.textContent = '0';
  const selectedFindingCard = document.getElementById('selected-finding-summary-card');
  if (selectedFindingCard) selectedFindingCard.style.display = 'none';
  state.findingsState.rawFindings = [];
  state.findingsState.filteredFindings = [];
  state.findingsState.selectedFindingId = null;
  const evTbody = document.getElementById('evidence-records-tbody');
  if (evTbody) evTbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No active case.</td></tr>';
  const pageInfo = document.getElementById('evidence-page-info');
  if (pageInfo) pageInfo.textContent = 'Page 1 of 1';
  const recordSummary = document.getElementById('evidence-record-summary');
  if (recordSummary) recordSummary.textContent = 'Showing 0 records';
  const srcSelect = document.getElementById('filter-evidence-source');
  if (srcSelect) srcSelect.innerHTML = '<option value="">All Evidence Sources</option>';
  const btnPrev = document.getElementById('btn-evidence-prev');
  if (btnPrev) btnPrev.disabled = true;
  const btnNext = document.getElementById('btn-evidence-next');
  if (btnNext) btnNext.disabled = true;

  updateWorkflowGuide();
}

function renderTopPriorityTable(results) {
  const tbody = document.getElementById('top-priority-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!results || results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No prioritization results yet. Click "Analyze Investigation" to process evidence and compute priorities.</td></tr>';
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
          ${escapeHtml(r.explanation_text)}
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
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!sources || sources.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">No evidence sources ingested yet. Click "+ Import Evidence" to upload a CSV, JSON, or JSONL forensic log.</td></tr>';
    return;
  }

  sources.forEach(s => {
    const tr = document.createElement('tr');
    const rawHash = s.sha256_hash || '';
    const hashDisplay = rawHash
      ? (rawHash.length > 20 ? `${rawHash.substring(0, 8)}…${rawHash.substring(rawHash.length - 8)}` : rawHash)
      : '—';
    const copyBtnHtml = rawHash
      ? `<button type="button" class="btn btn-ghost btn-xs btn-copy-hash" onclick="copyDigest('${escapeHtml(rawHash)}', this)" title="Copy SHA-256 digest recorded at ingestion" aria-label="Copy SHA-256 digest">
           <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
         </button>`
      : '';
    const cachedIntegrity = state.sourcesIntegrityCache?.get(s.id);
    let integrityBadgeHtml = '';
    if (cachedIntegrity) {
      let bClass = 'badge-mono';
      let icon = '●';
      if (cachedIntegrity.status === 'VERIFIED') {
        bClass = 'badge-open';
        icon = '✓';
      } else if (cachedIntegrity.status === 'INTEGRITY_MISMATCH') {
        bClass = 'alert-danger';
        icon = '⚠';
      } else {
        bClass = 'alert-warning';
        icon = '—';
      }
      integrityBadgeHtml = `<span class="badge ${bClass} text-xs" style="cursor: pointer; margin-left: 4px;" title="Click to view cryptographic verification details" onclick="viewSourceIntegrityModal('${escapeHtml(s.id)}')">${icon} ${escapeHtml(cachedIntegrity.status)}</span>`;
    }

    tr.innerHTML = `
      <td><strong>${escapeHtml(s.filename)}</strong></td>
      <td><span class="badge badge-mono">${escapeHtml(s.file_format)}</span></td>
      <td>
        <div class="hash-cell" style="display: inline-flex; align-items: center; gap: 6px; flex-wrap: wrap;">
          <span class="font-mono text-sm hash-val" title="SHA-256 Digest (Recorded at Ingestion): ${escapeHtml(rawHash)}">${escapeHtml(hashDisplay)}</span>
          ${copyBtnHtml}
          <button type="button" class="btn btn-ghost btn-xs btn-verify-hash" id="btn-verify-source-${escapeHtml(s.id)}" onclick="verifySourceIntegrity('${escapeHtml(s.id)}')" title="Verify stored file content against recorded SHA-256 digest" style="padding: 1px 5px; font-size: 10px;">Verify</button>
          <span id="verify-badge-${escapeHtml(s.id)}">${integrityBadgeHtml}</span>
        </div>
      </td>
      <td>${formatBytes(s.file_size_bytes)}</td>
      <td class="font-mono">${s.total_records}</td>
      <td class="font-mono">${s.normalized_records}</td>
      <td><span class="badge ${s.ingestion_status === 'COMPLETED' ? 'badge-open' : 'badge-mono'}">${escapeHtml(s.ingestion_status)}</span></td>
      <td class="text-sm">${s.ingested_at ? new Date(s.ingested_at).toLocaleString() : '—'}</td>
      <td>
        <div style="display: flex; gap: 6px; align-items: center;">
          <button class="btn btn-secondary btn-sm" onclick="triggerNormalizeSource('${escapeHtml(s.id)}')" title="Normalize this evidence source">Normalize</button>
          <button class="btn btn-ghost btn-sm" onclick="exploreSourceRecords('${escapeHtml(s.id)}')" title="Filter and view records from this source in the Normalized Records Explorer">Explore</button>
        </div>
      </td>
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
  if (str.length > 12) return str.substring(0, 8) + '\u2026' + str.substring(str.length - 4);
  return str;
}

// Detail Inspection Modal
window.viewDetailModal = function(title, dataObj) {
  const modal = document.getElementById('modal-detail');
  const titleEl = document.getElementById('modal-detail-title');
  const tierBadge = document.getElementById('modal-detail-tier-badge');
  const explainPanel = document.getElementById('modal-explainability-panel');
  const provPanel = document.getElementById('modal-provenance-panel');
  const genericPanel = document.getElementById('modal-generic-panel');
  const genericContent = document.getElementById('modal-generic-content');
  const proofPanel = document.getElementById('modal-finding-proof-panel');
  const evDetailPanel = document.getElementById('modal-evidence-detail-panel');

  titleEl.textContent = `${title} Inspection`;
  tierBadge.className = 'badge';
  tierBadge.textContent = '';
  tierBadge.style.display = 'none';

  explainPanel.style.display = 'none';
  provPanel.style.display = 'none';
  genericPanel.style.display = 'none';
  if (proofPanel) proofPanel.style.display = 'none';
  if (evDetailPanel) evDetailPanel.style.display = 'none';
  genericContent.innerHTML = '';

  if (dataObj && typeof dataObj.priority_score === 'number') {
    tierBadge.textContent = dataObj.priority_tier || 'UNKNOWN';
    tierBadge.className = `badge ${getTierBadgeClass(dataObj.priority_tier)}`;
    tierBadge.style.display = 'inline-block';

    explainPanel.style.display = 'block';
    document.getElementById('modal-score-value').textContent = dataObj.priority_score.toFixed(1);
    document.getElementById('modal-explanation-text').textContent = dataObj.explanation_text || 'No automated narrative available.';

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

// ==========================================================================
// Pipeline Coordinator UI Helpers & Execution Engine
// ==========================================================================

function setPipelineState(statusText, badgeClass = 'mono') {
  const badge = document.getElementById('pipeline-state-badge');
  if (badge) {
    badge.textContent = statusText;
    badge.className = `badge badge-${badgeClass}`;
  }
}

function setPipelineBannerLog(message, type = 'normal') {
  const banner = document.getElementById('pipeline-log-banner');
  if (!banner) return;
  banner.className = `pipeline-log-banner text-sm ${type === 'running' ? 'log-running' : type === 'success' ? 'log-success' : type === 'error' ? 'log-error' : 'text-muted'}`;
  banner.textContent = message;
}

function setStageChipState(chipId, status, tooltip = '') {
  const chip = document.getElementById(chipId);
  if (!chip) return;
  chip.className = `stage-chip chip-${status}`;
  if (tooltip) chip.title = tooltip;
  const indicator = chip.querySelector('.chip-indicator');
  if (indicator) {
    if (status === 'completed') indicator.textContent = '✓';
    else if (status === 'running') indicator.textContent = '●';
    else if (status === 'skipped') indicator.textContent = '⊘';
    else if (status === 'blocked') indicator.textContent = '⏸';
    else if (status === 'partial') indicator.textContent = '◐';
    else if (status === 'failed') indicator.textContent = '✗';
    else indicator.textContent = '●';
  }
}

function resetAllStageChips() {
  PIPELINE_STAGES.forEach(s => setStageChipState(s.chipId, 'idle', s.name));
}

function togglePipelineControls(enabled) {
  const runFullBtn = document.getElementById('btn-run-full-analysis');
  const runSingleBtn = document.getElementById('btn-run-single-stage');
  const selectStage = document.getElementById('select-pipeline-stage');
  const caseSelect = document.getElementById('investigation-select');
  const newCaseBtn = document.getElementById('btn-new-case');
  const importBtnHeader = document.getElementById('btn-action-import');
  const importBtnTab = document.getElementById('btn-evidence-tab-import');
  const exampleImportBtn = document.getElementById('btn-import-example-evidence');
  const wfActionBtn = document.getElementById('workflow-action-btn');

  const hasCase = Boolean(state.activeInvestigationId);
  const isRunning = Boolean(state.isPipelineRunning);

  // Analysis pipeline execution triggers: only enabled when NOT running and active case exists
  if (runFullBtn) runFullBtn.disabled = !enabled || !hasCase || isRunning;
  if (runSingleBtn) runSingleBtn.disabled = !enabled || !hasCase || isRunning;
  if (selectStage) selectStage.disabled = !enabled || !hasCase || isRunning;

  // New Case creation is ONLY disabled during active pipeline run
  if (newCaseBtn) newCaseBtn.disabled = isRunning;

  // Case selection dropdown: locked only during active pipeline run
  if (caseSelect) caseSelect.disabled = isRunning;

  // Evidence import controls: locked only during active pipeline run
  if (importBtnHeader) importBtnHeader.disabled = isRunning;
  if (importBtnTab) importBtnTab.disabled = isRunning;
  if (exampleImportBtn) exampleImportBtn.disabled = isRunning;

  // Workflow guide action: disabled only during active pipeline run
  if (wfActionBtn && isRunning) {
    wfActionBtn.disabled = true;
  }
}

// Full Analysis Pipeline Runner with Rigorous Prerequisite Semantics & Investigation Guard
async function runFullAnalysisPipeline() {
  if (state.isPipelineRunning) return;
  if (!state.activeInvestigationId) {
    showAlert('No active investigation. Please select or create a case first.', 'warning');
    return;
  }

  const runInvestigationId = state.activeInvestigationId;
  state.isPipelineRunning = true;
  togglePipelineControls(false);
  updateWorkflowGuide();
  resetAllStageChips();
  setPipelineState('Running...', 'warning');
  setPipelineBannerLog('Initiating investigation analysis. Validating investigation sources...', 'running');

  // Track outcomes for truthful overall status
  const outcomes = {
    normalize: 'idle',
    detect: 'idle',
    ml: 'idle',
    correlate: 'idle',
    activities: 'idle',
    prioritize_baseline: 'idle',
    prioritize_contextual: 'idle',
  };

  try {
    // Step 0: Enumerate sources belonging strictly to this investigation
    const sources = await apiRequest(`/investigations/${runInvestigationId}/sources`);
    if (state.activeInvestigationId !== runInvestigationId) return; // Stale guard

    if (!sources || sources.length === 0) {
      setPipelineState('No Sources', 'warning');
      setPipelineBannerLog('No evidence sources found for this investigation. Import an evidence file first.', 'normal');
      showAlert('No evidence sources ingested for this case. Click "Import Evidence" first.', 'warning');
      state.isPipelineRunning = false;
      togglePipelineControls(true);
      return;
    }

    // =========================================================================
    // Stage 1: Normalize Evidence Sources
    // =========================================================================
    setStageChipState('chip-stage-1', 'running');
    setPipelineBannerLog(`[1/7] Normalizing ${sources.length} evidence source(s)...`, 'running');
    let totalNormalized = 0;
    let anyNormalizeFailed = false;
    let normalizeErrorMsg = '';

    for (const src of sources) {
      try {
        const res = await apiRequest(`/evidence/sources/${src.id}/normalize`, { method: 'POST' });
        if (state.activeInvestigationId !== runInvestigationId) return;
        totalNormalized += (res.normalized_records || 0);
        if (res.status === 'FAILED') {
          anyNormalizeFailed = true;
          normalizeErrorMsg = (res.errors && res.errors.length > 0) ? res.errors.join('; ') : `Failed to normalize ${src.filename}`;
          break;
        }
      } catch (err) {
        if (state.activeInvestigationId !== runInvestigationId) return;
        anyNormalizeFailed = true;
        normalizeErrorMsg = err.message;
        break;
      }
    }

    if (anyNormalizeFailed) {
      outcomes.normalize = 'failed';
      setStageChipState('chip-stage-1', 'failed', `Normalization failed: ${normalizeErrorMsg}`);
      // Block all downstream dependent stages
      ['chip-stage-2','chip-stage-3','chip-stage-4','chip-stage-5','chip-stage-6','chip-stage-7'].forEach(id => {
        setStageChipState(id, 'blocked', 'Blocked: Normalization failed');
      });
      setPipelineState('Blocked', 'danger');
      setPipelineBannerLog(`Pipeline halted at Stage 1: Normalization failed (${normalizeErrorMsg}). Downstream stages blocked.`, 'error');
      showAlert(`Pipeline halted: Normalization failed (${normalizeErrorMsg}).`, 'danger');
      return;
    }

    if (totalNormalized === 0) {
      // 0 records normalized: downstream stages have no inputs and are blocked
      outcomes.normalize = 'skipped';
      setStageChipState('chip-stage-1', 'skipped', 'Normalization completed with 0 usable records');
      ['chip-stage-2','chip-stage-3','chip-stage-4','chip-stage-5','chip-stage-6','chip-stage-7'].forEach(id => {
        setStageChipState(id, 'blocked', 'Blocked: 0 normalized records available');
      });
      setPipelineState('Blocked', 'warning');
      setPipelineBannerLog('Pipeline halted: 0 normalized evidence records available. Downstream stages blocked.', 'error');
      showAlert('Normalization yielded 0 records. Subsequent analysis stages blocked.', 'warning');
      return;
    }

    outcomes.normalize = 'completed';
    setStageChipState('chip-stage-1', 'completed', `Normalized ${totalNormalized} records`);

    // Refetch sources to get accurate record counts per source
    const activeSources = await apiRequest(`/investigations/${runInvestigationId}/sources`);
    if (state.activeInvestigationId !== runInvestigationId) return;

    // =========================================================================
    // Stage 2: Deterministic Detections & IOCs
    // =========================================================================
    setStageChipState('chip-stage-2', 'running');
    setPipelineBannerLog(`[2/7] Running deterministic detection rules & IOCs across ${activeSources.length} source(s)...`, 'running');
    let totalFindings = 0;
    let anyDetectionFailed = false;
    let detectionErrorMsg = '';

    for (const src of activeSources) {
      try {
        const res = await apiRequest(`/detection/sources/${src.id}/analyze-rules`, { method: 'POST' });
        if (state.activeInvestigationId !== runInvestigationId) return;
        totalFindings += (res.findings_created || 0);
      } catch (err) {
        if (state.activeInvestigationId !== runInvestigationId) return;
        anyDetectionFailed = true;
        detectionErrorMsg = err.message;
        break;
      }
    }

    if (anyDetectionFailed) {
      outcomes.detect = 'failed';
      setStageChipState('chip-stage-2', 'failed', `Detections failed: ${detectionErrorMsg}`);
      ['chip-stage-3','chip-stage-4','chip-stage-5','chip-stage-6','chip-stage-7'].forEach(id => {
        setStageChipState(id, 'blocked', 'Blocked: Rule detection failed');
      });
      setPipelineState('Blocked', 'danger');
      setPipelineBannerLog(`Pipeline halted at Stage 2: Detection failed (${detectionErrorMsg}).`, 'error');
      showAlert(`Pipeline halted: Detection failed (${detectionErrorMsg}).`, 'danger');
      return;
    }

    outcomes.detect = 'completed';
    setStageChipState('chip-stage-2', 'completed', `Created ${totalFindings} findings`);

    // =========================================================================
    // Stage 3: ML Anomaly Analysis
    // Precondition: >= 10 normalized records per source
    // =========================================================================
    setStageChipState('chip-stage-3', 'running');
    setPipelineBannerLog(`[3/7] Running unsupervised ML anomaly analysis (threshold: >= 10 records)...`, 'running');
    let mlCreated = 0;
    let mlEligibleCount = 0;
    let mlSkippedCount = 0;

    for (const src of activeSources) {
      const recCount = src.normalized_records || 0;
      if (recCount < 10) {
        mlSkippedCount++;
        continue;
      }
      mlEligibleCount++;
      const res = await apiRequest(`/ml/sources/${src.id}/analyze`, { method: 'POST' });
      if (state.activeInvestigationId !== runInvestigationId) return;
      if (res.status === 'INSUFFICIENT_DATA') {
        mlSkippedCount++;
      } else {
        mlCreated += (res.findings_created || 0);
      }
    }

    if (mlEligibleCount === 0) {
      outcomes.ml = 'skipped';
      setStageChipState('chip-stage-3', 'skipped', 'Skipped: All sources have < 10 normalized records');
    } else if (mlSkippedCount > 0) {
      outcomes.ml = 'partial';
      setStageChipState('chip-stage-3', 'partial', `Partial: ${mlEligibleCount} sources analyzed, ${mlSkippedCount} skipped (< 10 records)`);
    } else {
      outcomes.ml = 'completed';
      setStageChipState('chip-stage-3', 'completed', `ML analysis completed (${mlCreated} outliers)`);
    }

    // =========================================================================
    // Stage 4: Contextual Evidence Correlation
    // Precondition: >= 2 normalized records per source
    // =========================================================================
    setStageChipState('chip-stage-4', 'running');
    setPipelineBannerLog(`[4/7] Discovering multi-dimensional evidence relationships (threshold: >= 2 records)...`, 'running');
    let relCreated = 0;
    let relEligibleCount = 0;
    let relSkippedCount = 0;
    let correlationFailed = false;
    let correlationErrorMsg = '';

    for (const src of activeSources) {
      const recCount = src.normalized_records || 0;
      if (recCount < 2) {
        relSkippedCount++;
        continue;
      }
      relEligibleCount++;
      try {
        const res = await apiRequest(`/correlation/sources/${src.id}/analyze`, { method: 'POST' });
        if (state.activeInvestigationId !== runInvestigationId) return;
        if (res.status === 'FAILED') {
          correlationFailed = true;
          correlationErrorMsg = (res.errors && res.errors.length > 0) ? res.errors.join('; ') : 'Correlation failed';
          break;
        } else if (res.status === 'INSUFFICIENT_DATA') {
          relSkippedCount++;
        } else {
          relCreated += (res.relationships_created || 0);
        }
      } catch (err) {
        if (state.activeInvestigationId !== runInvestigationId) return;
        correlationFailed = true;
        correlationErrorMsg = err.message;
        break;
      }
    }

    if (correlationFailed) {
      outcomes.correlate = 'failed';
      setStageChipState('chip-stage-4', 'failed', `Correlation failed: ${correlationErrorMsg}`);
      ['chip-stage-5','chip-stage-6','chip-stage-7'].forEach(id => {
        setStageChipState(id, 'blocked', 'Blocked: Correlation failed');
      });
      setPipelineState('Blocked', 'danger');
      setPipelineBannerLog(`Pipeline halted at Stage 4: Correlation failed (${correlationErrorMsg}).`, 'error');
      showAlert(`Pipeline halted: Correlation failed (${correlationErrorMsg}).`, 'danger');
      return;
    }

    if (relEligibleCount === 0) {
      outcomes.correlate = 'skipped';
      setStageChipState('chip-stage-4', 'skipped', 'Skipped: All sources have < 2 normalized records');
    } else if (relSkippedCount > 0) {
      outcomes.correlate = 'partial';
      setStageChipState('chip-stage-4', 'partial', `Partial: ${relEligibleCount} sources correlated, ${relSkippedCount} skipped (< 2 records)`);
    } else {
      outcomes.correlate = 'completed';
      setStageChipState('chip-stage-4', 'completed', `Formed ${relCreated} relationships`);
    }

    // =========================================================================
    // Stage 5: Cluster Activity Threads
    // Precondition: Evidence exists; uses correlation graph and findings
    // =========================================================================
    setStageChipState('chip-stage-5', 'running');
    setPipelineBannerLog(`[5/7] Synthesizing graph-clustered activity threads...`, 'running');
    let actCreated = 0;
    let activityFailed = false;
    let activityErrorMsg = '';

    for (const src of activeSources) {
      try {
        const res = await apiRequest(`/activities/sources/${src.id}/form`, { method: 'POST' });
        if (state.activeInvestigationId !== runInvestigationId) return;
        if (res.status === 'FAILED') {
          activityFailed = true;
          activityErrorMsg = (res.errors && res.errors.length > 0) ? res.errors.join('; ') : 'Activity clustering failed';
          break;
        } else if (res.status === 'INSUFFICIENT_DATA') {
          // No evidence or no clusterable data
        } else {
          actCreated += (res.activities_created || 0);
        }
      } catch (err) {
        if (state.activeInvestigationId !== runInvestigationId) return;
        activityFailed = true;
        activityErrorMsg = err.message;
        break;
      }
    }

    if (activityFailed) {
      outcomes.activities = 'failed';
      setStageChipState('chip-stage-5', 'failed', `Activity clustering failed: ${activityErrorMsg}`);
      ['chip-stage-6','chip-stage-7'].forEach(id => {
        setStageChipState(id, 'blocked', 'Blocked: Activity clustering failed');
      });
      setPipelineState('Blocked', 'danger');
      setPipelineBannerLog(`Pipeline halted at Stage 5: Activity formation failed (${activityErrorMsg}).`, 'error');
      showAlert(`Pipeline halted: Activity formation failed (${activityErrorMsg}).`, 'danger');
      return;
    }

    outcomes.activities = 'completed';
    setStageChipState('chip-stage-5', 'completed', `${actCreated} activity clusters formed`);

    // =========================================================================
    // Stage 6: Operational Baseline Evidence Prioritization (Investigation-scoped)
    // Precondition: Evidence records exist in investigation
    // =========================================================================
    setStageChipState('chip-stage-6', 'running');
    setPipelineBannerLog(`[6/7] Prioritizing evidence artifacts (Baseline Dual-Level Triage)...`, 'running');
    let baseResultsCount = 0;

    try {
      const baseRes = await apiRequest(`/prioritization/investigations/${runInvestigationId}/baseline`, { method: 'POST' });
      if (state.activeInvestigationId !== runInvestigationId) return;
      if (baseRes.status === 'INSUFFICIENT_DATA') {
        outcomes.prioritize_baseline = 'skipped';
        setStageChipState('chip-stage-6', 'skipped', 'Skipped: No evidence records to prioritize');
      } else {
        outcomes.prioritize_baseline = 'completed';
        baseResultsCount = baseRes.results_created || 0;
        setStageChipState('chip-stage-6', 'completed', `Scored ${baseResultsCount} artifacts`);
      }
    } catch (err) {
      if (state.activeInvestigationId !== runInvestigationId) return;
      outcomes.prioritize_baseline = 'failed';
      setStageChipState('chip-stage-6', 'failed', `Baseline prioritization failed: ${err.message}`);
      setStageChipState('chip-stage-7', 'blocked', 'Blocked: Prioritization error');
      setPipelineState('Blocked', 'danger');
      setPipelineBannerLog(`Pipeline halted at Stage 6: Baseline prioritization failed (${err.message}).`, 'error');
      showAlert(`Pipeline halted: Prioritization failed (${err.message}).`, 'danger');
      return;
    }

    // =========================================================================
    // Stage 7: Contextual Activity Prioritization (Investigation-scoped)
    // Precondition: Activity clusters must exist in investigation
    // =========================================================================
    setStageChipState('chip-stage-7', 'running');
    setPipelineBannerLog(`[7/7] Prioritizing activity clusters (Contextual Dual-Level Triage)...`, 'running');
    let ctxResultsCount = 0;

    try {
      const ctxRes = await apiRequest(`/prioritization/investigations/${runInvestigationId}/contextual`, { method: 'POST' });
      if (state.activeInvestigationId !== runInvestigationId) return;
      if (ctxRes.status === 'INSUFFICIENT_DATA') {
        outcomes.prioritize_contextual = 'skipped';
        setStageChipState('chip-stage-7', 'skipped', 'Skipped: No activity clusters found to prioritize');
      } else {
        outcomes.prioritize_contextual = 'completed';
        ctxResultsCount = ctxRes.results_created || 0;
        setStageChipState('chip-stage-7', 'completed', `Scored ${ctxResultsCount} activities`);
      }
    } catch (err) {
      if (state.activeInvestigationId !== runInvestigationId) return;
      outcomes.prioritize_contextual = 'failed';
      setStageChipState('chip-stage-7', 'failed', `Contextual prioritization failed: ${err.message}`);
      setPipelineState('Error', 'danger');
      setPipelineBannerLog(`Contextual prioritization failed (${err.message}).`, 'error');
      showAlert(`Contextual prioritization failed: ${err.message}`, 'danger');
      return;
    }

    // =========================================================================
    // Truthful Overall Status Determination
    // =========================================================================
    const values = Object.values(outcomes);
    const hasSkipped = values.some(v => v === 'skipped' || v === 'partial');
    const hasFailed = values.some(v => v === 'failed');

    let overallState = 'Completed';
    let badgeClass = 'success';
    if (hasFailed) {
      overallState = 'Failed';
      badgeClass = 'danger';
    } else if (hasSkipped) {
      overallState = 'Completed (with skipped stages)';
      badgeClass = 'warning';
    }

    setPipelineState(overallState, badgeClass);

    let summaryMsg = `Pipeline execution finished (${overallState}): ${totalNormalized} records normalized, ${totalFindings} rule/IOC findings`;
    if (outcomes.ml === 'skipped') summaryMsg += ', ML skipped (<10 records)';
    else summaryMsg += `, ${mlCreated} ML anomalies`;
    if (outcomes.correlate === 'skipped') summaryMsg += ', correlation skipped (<2 records)';
    else summaryMsg += `, ${relCreated} links`;
    summaryMsg += `, ${actCreated} activities`;
    summaryMsg += `, ${baseResultsCount} artifact scores`;
    if (outcomes.prioritize_contextual === 'skipped') summaryMsg += ', activity triage skipped (no clusters)';
    else summaryMsg += `, ${ctxResultsCount} activity scores`;
    summaryMsg += '.';

    setPipelineBannerLog(summaryMsg, hasSkipped ? 'running' : 'success');
    showAlert(
      hasSkipped
        ? 'Investigation analysis finished: Core detection complete. Some stages skipped due to documented record thresholds.'
        : 'Investigation analysis completed successfully with all 7 stages.',
      hasSkipped ? 'warning' : 'success',
      8000
    );

    // Refresh summary metrics and active destination view
    await loadActiveInvestigationSummary();
    await refreshActiveDestinationView();
  } catch (err) {
    if (state.activeInvestigationId !== runInvestigationId) return;
    console.error('Pipeline Coordinator Failure:', err);
    setPipelineState('Error', 'danger');
    setPipelineBannerLog(`Pipeline execution halted due to unexpected error: ${err.message}`, 'error');
    showAlert(`Pipeline stopped: ${err.message}`, 'danger', 10000);

    // Mark running chip as failed
    PIPELINE_STAGES.forEach(s => {
      const chip = document.getElementById(s.chipId);
      if (chip && chip.classList.contains('chip-running')) {
        setStageChipState(s.chipId, 'failed', `Error: ${err.message}`);
      }
    });

    try {
      await loadActiveInvestigationSummary();
      await refreshActiveDestinationView();
    } catch {}
  } finally {
    if (state.activeInvestigationId === runInvestigationId) {
      state.isPipelineRunning = false;
      togglePipelineControls(true);
      updateWorkflowGuide();
    }
  }
}

// Single Pipeline Stage Runner with Explicit Prerequisite Communication & Truthful Status
async function runSinglePipelineStage(stageKey) {
  if (state.isPipelineRunning) return;
  if (!state.activeInvestigationId) {
    showAlert('Please select or create an investigation first.', 'warning');
    return;
  }

  const runInvestigationId = state.activeInvestigationId;
  const stage = PIPELINE_STAGES.find(s => s.key === stageKey);
  if (!stage) return;

  state.isPipelineRunning = true;
  togglePipelineControls(false);
  setStageChipState(stage.chipId, 'running');
  setPipelineState('Running Stage...', 'warning');
  setPipelineBannerLog(`Executing ${stage.name}...`, 'running');

  try {
    if (stage.scope === 'source') {
      const sources = await apiRequest(`/investigations/${runInvestigationId}/sources`);
      if (state.activeInvestigationId !== runInvestigationId) return;

      if (!sources || sources.length === 0) {
        setStageChipState(stage.chipId, 'skipped', 'No evidence sources found');
        setPipelineBannerLog(`${stage.name} skipped: No evidence sources found in this investigation. Import evidence first.`, 'error');
        showAlert('No evidence sources found for this investigation.', 'warning');
        setPipelineState('Prerequisite Missing', 'warning');
        return;
      }

      if (stageKey === 'normalize') {
        let total = 0;
        let anyFailed = false;
        let errDesc = '';
        for (const src of sources) {
          const res = await apiRequest(`/evidence/sources/${src.id}/normalize`, { method: 'POST' });
          if (state.activeInvestigationId !== runInvestigationId) return;
          total += (res.normalized_records || 0);
          if (res.status === 'FAILED') {
            anyFailed = true;
            errDesc = (res.errors && res.errors.length > 0) ? res.errors.join('; ') : 'Normalization error';
          }
        }
        if (anyFailed) {
          setStageChipState(stage.chipId, 'failed', errDesc);
          setPipelineBannerLog(`Normalization failed: ${errDesc}`, 'error');
          showAlert(`Normalization failed: ${errDesc}`, 'danger');
          setPipelineState('Failed', 'danger');
        } else if (total === 0) {
          setStageChipState(stage.chipId, 'skipped', '0 records normalized');
          setPipelineBannerLog('Normalization completed: 0 usable records normalized.', 'normal');
          showAlert('Normalization completed, but 0 records were produced.', 'warning');
          setPipelineState('0 Records', 'warning');
        } else {
          setStageChipState(stage.chipId, 'completed', `Normalized ${total} records`);
          setPipelineBannerLog(`Normalization complete: ${total} records normalized across ${sources.length} source(s).`, 'success');
          showAlert(`Normalization complete: ${total} records normalized.`, 'success');
          setPipelineState('Ready', 'success');
        }
      } else if (stageKey === 'detect') {
        let total = 0;
        for (const src of sources) {
          const res = await apiRequest(`/detection/sources/${src.id}/analyze-rules`, { method: 'POST' });
          if (state.activeInvestigationId !== runInvestigationId) return;
          total += (res.findings_created || 0);
        }
        setStageChipState(stage.chipId, 'completed', `Created ${total} findings`);
        setPipelineBannerLog(`Deterministic detection complete: ${total} findings generated.`, 'success');
        showAlert(`Detections complete: ${total} findings generated.`, 'success');
        setPipelineState('Ready', 'success');
      } else if (stageKey === 'ml') {
        let created = 0;
        let eligible = 0;
        let skipped = 0;
        for (const src of sources) {
          if ((src.normalized_records || 0) < 10) {
            skipped++;
            continue;
          }
          eligible++;
          const res = await apiRequest(`/ml/sources/${src.id}/analyze`, { method: 'POST' });
          if (state.activeInvestigationId !== runInvestigationId) return;
          if (res.status === 'INSUFFICIENT_DATA') skipped++;
          else created += (res.findings_created || 0);
        }
        if (eligible === 0) {
          setStageChipState(stage.chipId, 'skipped', 'Documented prerequisite not met: All sources have < 10 records');
          setPipelineBannerLog(`ML Anomaly analysis skipped: Documented prerequisite not met — requires >= 10 normalized records per source.`, 'normal');
          showAlert(`ML Anomaly analysis requires >= 10 records per source. None eligible.`, 'warning');
          setPipelineState('Prerequisite Missing', 'warning');
        } else {
          setStageChipState(stage.chipId, 'completed', `Flagged ${created} outliers`);
          setPipelineBannerLog(`ML Anomaly analysis complete: ${created} outliers flagged across ${eligible} eligible source(s).`, 'success');
          showAlert(`ML Anomaly analysis complete: ${created} outliers flagged.`, 'success');
          setPipelineState('Ready', 'success');
        }
      } else if (stageKey === 'correlate') {
        let created = 0;
        let eligible = 0;
        let skipped = 0;
        let failMsg = '';
        for (const src of sources) {
          if ((src.normalized_records || 0) < 2) {
            skipped++;
            continue;
          }
          eligible++;
          const res = await apiRequest(`/correlation/sources/${src.id}/analyze`, { method: 'POST' });
          if (state.activeInvestigationId !== runInvestigationId) return;
          if (res.status === 'FAILED') {
            failMsg = (res.errors && res.errors.length > 0) ? res.errors.join('; ') : 'Correlation failed';
            break;
          } else if (res.status === 'INSUFFICIENT_DATA') {
            skipped++;
          } else {
            created += (res.relationships_created || 0);
          }
        }
        if (failMsg) {
          setStageChipState(stage.chipId, 'failed', failMsg);
          setPipelineBannerLog(`Correlation failed: ${failMsg}`, 'error');
          showAlert(`Correlation failed: ${failMsg}`, 'danger');
          setPipelineState('Failed', 'danger');
        } else if (eligible === 0) {
          setStageChipState(stage.chipId, 'skipped', 'Documented prerequisite not met: Requires >= 2 records per source');
          setPipelineBannerLog(`Correlation skipped: Requires >= 2 normalized records per source.`, 'normal');
          showAlert(`Correlation requires >= 2 records per source. None eligible.`, 'warning');
          setPipelineState('Prerequisite Missing', 'warning');
        } else {
          setStageChipState(stage.chipId, 'completed', `Formed ${created} relationships`);
          setPipelineBannerLog(`Correlation complete: ${created} relationships formed.`, 'success');
          showAlert(`Evidence correlation complete: ${created} relationships formed.`, 'success');
          setPipelineState('Ready', 'success');
        }
      } else if (stageKey === 'activities') {
        let created = 0;
        let failMsg = '';
        for (const src of sources) {
          const res = await apiRequest(`/activities/sources/${src.id}/form`, { method: 'POST' });
          if (state.activeInvestigationId !== runInvestigationId) return;
          if (res.status === 'FAILED') {
            failMsg = (res.errors && res.errors.length > 0) ? res.errors.join('; ') : 'Clustering failed';
            break;
          } else if (res.status === 'INSUFFICIENT_DATA') {
            // Source had no records
          } else {
            created += (res.activities_created || 0);
          }
        }
        if (failMsg) {
          setStageChipState(stage.chipId, 'failed', failMsg);
          setPipelineBannerLog(`Activity formation failed: ${failMsg}`, 'error');
          showAlert(`Activity clustering failed: ${failMsg}`, 'danger');
          setPipelineState('Failed', 'danger');
        } else {
          setStageChipState(stage.chipId, 'completed', `Formed ${created} activities`);
          setPipelineBannerLog(`Activity clustering complete: ${created} activity threads synthesized.`, 'success');
          showAlert(`Activity clustering complete: ${created} activities formed.`, 'success');
          setPipelineState('Ready', 'success');
        }
      }
    } else {
      // Investigation-scoped
      if (stageKey === 'prioritize-baseline') {
        const res = await apiRequest(`/prioritization/investigations/${runInvestigationId}/baseline`, { method: 'POST' });
        if (state.activeInvestigationId !== runInvestigationId) return;
        if (res.status === 'INSUFFICIENT_DATA') {
          setStageChipState(stage.chipId, 'skipped', 'Prerequisite not met: No evidence records to prioritize');
          setPipelineBannerLog('Evidence Prioritization skipped: No evidence records exist in this investigation.', 'normal');
          showAlert('No evidence records exist in this investigation to prioritize.', 'warning');
          setPipelineState('Prerequisite Missing', 'warning');
        } else {
          setStageChipState(stage.chipId, 'completed', `Scored ${res.results_created} artifacts`);
          setPipelineBannerLog(`Evidence Prioritization complete: ${res.results_created} artifact scores computed.`, 'success');
          showAlert(`Evidence Prioritization complete: ${res.results_created} scores computed.`, 'success');
          setPipelineState('Ready', 'success');
        }
      } else if (stageKey === 'prioritize-contextual') {
        const res = await apiRequest(`/prioritization/investigations/${runInvestigationId}/contextual`, { method: 'POST' });
        if (state.activeInvestigationId !== runInvestigationId) return;
        if (res.status === 'INSUFFICIENT_DATA') {
          setStageChipState(stage.chipId, 'skipped', 'Prerequisite not met: No activity clusters exist to prioritize');
          setPipelineBannerLog('Activity Prioritization skipped: Prerequisite not met — 0 activity clusters exist in this investigation. Run "Cluster Activities" first.', 'normal');
          showAlert('Activity Prioritization requires formed activity clusters. Run Stage 5 first.', 'warning');
          setPipelineState('Prerequisite Missing', 'warning');
        } else {
          setStageChipState(stage.chipId, 'completed', `Scored ${res.results_created} activities`);
          setPipelineBannerLog(`Activity Prioritization complete: ${res.results_created} activity scores computed.`, 'success');
          showAlert(`Activity Prioritization complete: ${res.results_created} scores computed.`, 'success');
          setPipelineState('Ready', 'success');
        }
      }
    }

    await loadActiveInvestigationSummary();
    await refreshActiveDestinationView();
  } catch (err) {
    if (state.activeInvestigationId !== runInvestigationId) return;
    console.error(`Error executing ${stage.name}:`, err);
    setStageChipState(stage.chipId, 'failed', err.message);
    setPipelineState('Error', 'danger');
    setPipelineBannerLog(`${stage.name} failed: ${err.message}`, 'error');
    showAlert(`${stage.name} failed: ${err.message}`, 'danger');
  } finally {
    if (state.activeInvestigationId === runInvestigationId) {
      state.isPipelineRunning = false;
      togglePipelineControls(true);
    }
  }
}

// Single-source Normalize trigger (Evidence table action)
window.triggerNormalizeSource = async function(sourceId) {
  if (state.isPipelineRunning) return;
  const currentInvId = state.activeInvestigationId;

  try {
    setPipelineState('Normalizing...', 'warning');
    showAlert(`Normalizing evidence source ${sourceId.substring(0, 8)}...`, 'warning');
    const res = await apiRequest(`/evidence/sources/${sourceId}/normalize`, { method: 'POST' });
    if (state.activeInvestigationId !== currentInvId) return;
    showAlert(`Normalization completed: ${res.normalized_records} records normalized.`, 'success');
    await loadActiveInvestigationSummary();
    await loadSources();
    setPipelineState('Ready', 'success');
  } catch (err) {
    if (state.activeInvestigationId !== currentInvId) return;
    showAlert(`Normalization failed: ${err.message}`, 'danger');
    setPipelineState('Error', 'danger');
  }
};

function setupPipelineCoordinator() {
  const runFullBtn = document.getElementById('btn-run-full-analysis');
  if (runFullBtn) {
    runFullBtn.addEventListener('click', runFullAnalysisPipeline);
  }

  const runSingleBtn = document.getElementById('btn-run-single-stage');
  if (runSingleBtn) {
    runSingleBtn.addEventListener('click', () => {
      const selectStage = document.getElementById('select-pipeline-stage');
      if (selectStage) {
        runSinglePipelineStage(selectStage.value);
      }
    });
  }
}

// ==========================================================================
// Destination View Refresh & Tab Management
// ==========================================================================

async function refreshActiveDestinationView() {
  if (!state.activeInvestigationId) return;

  if (state.activeTab === 'tab-overview') {
    return;
  } else if (state.activeTab === 'tab-evidence') {
    await loadSources();
    await loadEvidenceRecords();
  } else if (state.activeTab === 'tab-analysis') {
    await Promise.all([loadActivities(), loadFindings()]);
    const adv = document.getElementById('advanced-analysis-details');
    if (adv && adv.open) {
      await Promise.all([loadCorrelations(), loadAllPrioritizations()]);
    }
  } else if (state.activeTab === 'tab-report' || state.activeTab === 'tab-findings') {
    if (!state.summary && state.activeInvestigationId) {
      await loadActiveInvestigationSummary();
    } else {
      updateReportPreview(state.summary);
    }
  }
}

function showExampleEvidenceBanner() {
  const banner = document.getElementById('example-evidence-banner');
  if (banner) banner.style.display = 'flex';
}

function hideExampleEvidenceBanner() {
  const banner = document.getElementById('example-evidence-banner');
  if (banner) banner.style.display = 'none';
}

// Download PDF Investigation Report Helper
async function downloadInvestigationReport(btnEl, spinnerEl) {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;

  const findingsBtn = document.getElementById('btn-findings-download-report');
  const findingsSpinner = document.getElementById('btn-findings-download-report-spinner');

  if (findingsBtn) findingsBtn.style.display = 'none';
  if (findingsSpinner) findingsSpinner.style.display = 'inline';

  try {
    const url = `${API_BASE}/investigations/${currentInvId}/report`;
    const res = await fetch(url);

    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try { const j = await res.json(); detail = j.detail || j.message || detail; } catch {}
      throw new Error(detail);
    }

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
    a.href = blobUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
    showAlert('Investigation report generated and downloaded successfully.', 'success', 4000);
  } catch (err) {
    showAlert(`Report generation failed: ${err.message}`, 'danger');
  } finally {
    if (findingsSpinner) findingsSpinner.style.display = 'none';
    if (findingsBtn) findingsBtn.style.display = 'inline-block';
  }
}

// ==========================================================================
// Event Listeners Setup
// ==========================================================================

function setupEventListeners() {
  // Download Investigation Report (Findings & Report tab button)
  const reportBtnFindings = document.getElementById('btn-findings-download-report');
  const spinnerFindings = document.getElementById('btn-findings-download-report-spinner');
  if (reportBtnFindings) {
    reportBtnFindings.addEventListener('click', () => downloadInvestigationReport(reportBtnFindings, spinnerFindings));
  }

  // Case Selection Change with Concurrency and Stale Guard
  document.getElementById('investigation-select').addEventListener('change', async (e) => {
    if (state.isPipelineRunning) {
      showAlert('Pipeline is currently executing. Case switching is locked until the pipeline halts.', 'warning');
      e.target.value = state.activeInvestigationId;
      return;
    }

    // Close any open modals to prevent displaying stale forensic records
    const detailModal = document.getElementById('modal-detail');
    if (detailModal && detailModal.style.display !== 'none') {
      window.closeModal(detailModal);
    }
    const importModal = document.getElementById('modal-import-evidence');
    if (importModal && importModal.style.display !== 'none') {
      window.closeModal(importModal);
    }

    const newInvId = e.target.value;
    if (!newInvId) {
      state.activeInvestigationId = null;
      localStorage.removeItem('forensiq_active_inv_id');
      renderEmptyInvestigation();
      updateRouteHash('', 'overview');
      return;
    }

    state.investigationVersion++;
    state.activeInvestigationId = newInvId;
    localStorage.setItem('forensiq_active_inv_id', state.activeInvestigationId);

    resetCaseScopedState();
    updateRouteHash(newInvId);

    await loadActiveInvestigationSummary();
    await refreshActiveDestinationView();
  });

  // Primary Navigation Tab Switching (4 Destinations) - Integrated with URL Route
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const targetPaneId = tab.getAttribute('data-tab');
      const tabShort = PANE_TO_TAB[targetPaneId] || 'overview';
      navigateToTab(tabShort);
    });
  });

  // Evidence Master-Detail Inspector Close Button
  const btnCloseInspector = document.getElementById('btn-close-inspector');
  if (btnCloseInspector) {
    btnCloseInspector.addEventListener('click', () => {
      selectEvidenceRecord(null);
    });
  }

  // Guided Investigation Workflow Steps click interactions
  const wfStep1 = document.getElementById('wf-step-1');
  if (wfStep1) {
    wfStep1.addEventListener('click', openNewCaseModal);
  }

  const wfStep2 = document.getElementById('wf-step-2');
  if (wfStep2) {
    wfStep2.addEventListener('click', openImportEvidenceModal);
  }

  const wfStep3 = document.getElementById('wf-step-3');
  if (wfStep3) {
    wfStep3.addEventListener('click', () => {
      if (!state.isPipelineRunning) runFullAnalysisPipeline();
    });
  }

  const wfStep4 = document.getElementById('wf-step-4');
  if (wfStep4) {
    wfStep4.addEventListener('click', () => {
      const analysisTab = document.getElementById('nav-tab-analysis');
      if (analysisTab) analysisTab.click();
    });
  }

  const wfStep5 = document.getElementById('wf-step-5');
  if (wfStep5) {
    wfStep5.addEventListener('click', () => {
      const reportTab = document.getElementById('nav-tab-report');
      if (reportTab) {
        reportTab.click();
      } else {
        const findingsBtn = document.getElementById('btn-findings-download-report');
        const findingsSpinner = document.getElementById('btn-findings-download-report-spinner');
        if (!state.isPipelineRunning) downloadInvestigationReport(findingsBtn, findingsSpinner);
      }
    });
  }

  const advDetails = document.getElementById('advanced-analysis-details');
  if (advDetails) {
    advDetails.addEventListener('toggle', () => {
      if (advDetails.open && state.activeInvestigationId) {
        loadCorrelations();
        loadAllPrioritizations();
      }
    });
  }

  // Analysis Subnavigation Pills Switching
  document.querySelectorAll('.subnav-pill').forEach(pill => {
    pill.addEventListener('click', async () => {
      document.querySelectorAll('.subnav-pill').forEach(p => {
        p.classList.remove('active');
        p.setAttribute('aria-selected', 'false');
      });
      document.querySelectorAll('.subtab-pane').forEach(sp => sp.classList.remove('active'));

      pill.classList.add('active');
      pill.setAttribute('aria-selected', 'true');
      const targetSubpaneId = pill.getAttribute('data-subtab');
      state.activeSubtab = targetSubpaneId;
      const targetSubpane = document.getElementById(targetSubpaneId);
      if (targetSubpane) targetSubpane.classList.add('active');

      if (targetSubpaneId === 'subpane-activities') await loadActivities();
      else if (targetSubpaneId === 'subpane-correlations') await loadCorrelations();
      else if (targetSubpaneId === 'subpane-ml') await loadMLAnomalies();
      else if (targetSubpaneId === 'subpane-prioritization') await loadAllPrioritizations();
    });
  });

  // Filters
  const filterPrioTier = document.getElementById('filter-prio-tier');
  if (filterPrioTier) filterPrioTier.addEventListener('change', loadAllPrioritizations);

  const filterPrioMethod = document.getElementById('filter-prio-method');
  if (filterPrioMethod) filterPrioMethod.addEventListener('change', loadAllPrioritizations);

  const filterFindingType = document.getElementById('filter-finding-type');
  if (filterFindingType) filterFindingType.addEventListener('change', loadFindings);

  // Threat Discovery Interface Event Listeners (Phase 1)
  const findingsSearchInput = document.getElementById('findings-search-input');
  const findingsSearchClear = document.getElementById('findings-search-clear');
  if (findingsSearchInput) {
    findingsSearchInput.addEventListener('input', (e) => {
      state.findingsState.searchQuery = e.target.value;
      if (findingsSearchClear) {
        findingsSearchClear.style.display = e.target.value ? 'inline-block' : 'none';
      }
      applyFindingsFilters();
    });
  }
  if (findingsSearchClear) {
    findingsSearchClear.addEventListener('click', () => {
      if (findingsSearchInput) findingsSearchInput.value = '';
      findingsSearchClear.style.display = 'none';
      state.findingsState.searchQuery = '';
      applyFindingsFilters();
    });
  }

  const filterFindingsPriority = document.getElementById('filter-findings-priority');
  if (filterFindingsPriority) {
    filterFindingsPriority.addEventListener('change', (e) => {
      state.findingsState.priorityFilter = e.target.value;
      applyFindingsFilters();
    });
  }

  const filterFindingsMethod = document.getElementById('filter-findings-method');
  if (filterFindingsMethod) {
    filterFindingsMethod.addEventListener('change', (e) => {
      state.findingsState.methodFilter = e.target.value;
      applyFindingsFilters();
    });
  }

  const filterFindingsActivity = document.getElementById('filter-findings-activity');
  if (filterFindingsActivity) {
    filterFindingsActivity.addEventListener('change', (e) => {
      state.findingsState.activityFilter = e.target.value;
      applyFindingsFilters();
    });
  }

  const btnResetFindings = document.getElementById('btn-reset-findings-filters');
  if (btnResetFindings) {
    btnResetFindings.addEventListener('click', resetFindingsFilters);
  }

  const btnClearActiveFilters = document.getElementById('btn-clear-active-filters');
  if (btnClearActiveFilters) {
    btnClearActiveFilters.addEventListener('click', resetFindingsFilters);
  }

  // Metric Cards click-to-filter
  const cardMetricTotal = document.getElementById('metric-card-total');
  if (cardMetricTotal) {
    cardMetricTotal.addEventListener('click', resetFindingsFilters);
  }

  const cardMetricHigh = document.getElementById('metric-card-high');
  if (cardMetricHigh) {
    cardMetricHigh.addEventListener('click', () => {
      const pSelect = document.getElementById('filter-findings-priority');
      if (pSelect) pSelect.value = 'HIGH';
      state.findingsState.priorityFilter = 'HIGH';
      applyFindingsFilters();
    });
  }

  const cardMetricMed = document.getElementById('metric-card-medium');
  if (cardMetricMed) {
    cardMetricMed.addEventListener('click', () => {
      const pSelect = document.getElementById('filter-findings-priority');
      if (pSelect) pSelect.value = 'MEDIUM';
      state.findingsState.priorityFilter = 'MEDIUM';
      applyFindingsFilters();
    });
  }

  const cardMetricLow = document.getElementById('metric-card-low');
  if (cardMetricLow) {
    cardMetricLow.addEventListener('click', () => {
      const pSelect = document.getElementById('filter-findings-priority');
      if (pSelect) pSelect.value = 'LOW';
      state.findingsState.priorityFilter = 'LOW';
      applyFindingsFilters();
    });
  }

  const filterRelType = document.getElementById('filter-rel-type');
  if (filterRelType) filterRelType.addEventListener('change', loadCorrelations);

  // Evidence Explorer Filters & Pagination
  const filterEvidenceSource = document.getElementById('filter-evidence-source');
  if (filterEvidenceSource) {
    filterEvidenceSource.addEventListener('change', (e) => {
      state.evidencePagination.source_id = e.target.value;
      state.evidencePagination.offset = 0;
      loadEvidenceRecords();
    });
  }

  const filterEvidenceEventType = document.getElementById('filter-evidence-event-type');
  if (filterEvidenceEventType) {
    filterEvidenceEventType.addEventListener('change', (e) => {
      state.evidencePagination.event_type = e.target.value;
      state.evidencePagination.offset = 0;
      loadEvidenceRecords();
    });
  }

  const btnFilterEvidence = document.getElementById('btn-filter-evidence');
  if (btnFilterEvidence) {
    btnFilterEvidence.addEventListener('click', () => {
      const srcEl = document.getElementById('filter-evidence-source');
      const typeEl = document.getElementById('filter-evidence-event-type');
      const userEl = document.getElementById('filter-evidence-user');
      const devEl = document.getElementById('filter-evidence-device');

      state.evidencePagination.source_id = srcEl ? srcEl.value : '';
      state.evidencePagination.event_type = typeEl ? typeEl.value : '';
      state.evidencePagination.user_id = userEl ? userEl.value.trim() : '';
      state.evidencePagination.device_id = devEl ? devEl.value.trim() : '';
      state.evidencePagination.offset = 0;
      loadEvidenceRecords();
    });
  }

  const btnResetEvidence = document.getElementById('btn-reset-evidence-filters');
  if (btnResetEvidence) {
    btnResetEvidence.addEventListener('click', () => {
      const srcEl = document.getElementById('filter-evidence-source');
      if (srcEl) srcEl.value = '';
      const typeEl = document.getElementById('filter-evidence-event-type');
      if (typeEl) typeEl.value = '';
      const userEl = document.getElementById('filter-evidence-user');
      if (userEl) userEl.value = '';
      const devEl = document.getElementById('filter-evidence-device');
      if (devEl) devEl.value = '';

      state.evidencePagination.source_id = '';
      state.evidencePagination.event_type = '';
      state.evidencePagination.user_id = '';
      state.evidencePagination.device_id = '';
      state.evidencePagination.offset = 0;
      loadEvidenceRecords();
    });
  }

  const evidencePageSize = document.getElementById('evidence-page-size');
  if (evidencePageSize) {
    evidencePageSize.addEventListener('change', (e) => {
      state.evidencePagination.limit = parseInt(e.target.value, 10) || 25;
      state.evidencePagination.offset = 0;
      loadEvidenceRecords();
    });
  }

  const btnEvidencePrev = document.getElementById('btn-evidence-prev');
  if (btnEvidencePrev) {
    btnEvidencePrev.addEventListener('click', () => {
      if (state.evidencePagination.offset > 0) {
        state.evidencePagination.offset = Math.max(0, state.evidencePagination.offset - state.evidencePagination.limit);
        loadEvidenceRecords();
      }
    });
  }

  const btnEvidenceNext = document.getElementById('btn-evidence-next');
  if (btnEvidenceNext) {
    btnEvidenceNext.addEventListener('click', () => {
      if (state.evidencePagination.offset + state.evidencePagination.limit < state.evidencePagination.total) {
        state.evidencePagination.offset += state.evidencePagination.limit;
        loadEvidenceRecords();
      }
    });
  }

  // Modal Close & Backdrop Interactions
  document.querySelectorAll('[data-close]').forEach(btn => {
    btn.addEventListener('click', () => {
      const modalId = btn.getAttribute('data-close');
      window.closeModal(document.getElementById(modalId));
    });
  });

  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        window.closeModal(overlay);
      }
    });
  });

  document.addEventListener('keydown', (e) => {
    // Check for open modals
    const openModals = Array.from(document.querySelectorAll('.modal-overlay, .modal-backdrop')).filter(m => m.style.display !== 'none' && m.getAttribute('aria-hidden') !== 'true');

    if (e.key === 'Escape') {
      if (openModals.length > 0) {
        e.preventDefault();
        openModals.forEach(m => window.closeModal(m));
        return;
      }
      // If no open modal, Escape deselects the evidence inspector
      if (state.selectedEvidenceId) {
        e.preventDefault();
        selectEvidenceRecord(null);
        return;
      }
      return;
    }

    if (e.key === 'Tab' && openModals.length > 0) {
      const activeModal = openModals[openModals.length - 1];
      const focusable = getFocusableElements(activeModal);
      if (focusable.length === 0) {
        e.preventDefault();
        return;
      }

      const firstEl = focusable[0];
      const lastEl = focusable[focusable.length - 1];

      if (e.shiftKey) {
        if (document.activeElement === firstEl || !activeModal.contains(document.activeElement)) {
          e.preventDefault();
          lastEl.focus();
        }
      } else {
        if (document.activeElement === lastEl || !activeModal.contains(document.activeElement)) {
          e.preventDefault();
          firstEl.focus();
        }
      }
      return;
    }

    // If modal is open, do not execute global navigation or inspector shortcuts
    if (openModals.length > 0) return;

    // Safety checks: do not intercept if typing in editable controls or modifier keys held
    const activeEl = document.activeElement;
    const tagName = activeEl ? activeEl.tagName.toUpperCase() : '';
    const isEditable = tagName === 'INPUT' || tagName === 'TEXTAREA' || tagName === 'SELECT' || (activeEl && activeEl.isContentEditable);
    if (isEditable) return;

    if (e.ctrlKey || e.altKey || e.metaKey) return;

    // Phase 3 Keyboard Navigation:
    // Tab shortcuts 1, 2, 3, 4
    if (e.key === '1') {
      e.preventDefault();
      navigateToTab('overview');
      return;
    }
    if (e.key === '2') {
      e.preventDefault();
      navigateToTab('evidence');
      return;
    }
    if (e.key === '3') {
      e.preventDefault();
      navigateToTab('analysis');
      return;
    }
    if (e.key === '4') {
      e.preventDefault();
      navigateToTab('report');
      return;
    }

    // Evidence Master-Detail Row Navigation: J (next), K (previous)
    if (e.key === 'j' || e.key === 'J') {
      if (state.activeTab === 'tab-evidence') {
        e.preventDefault();
        selectNextEvidenceRow();
        return;
      }
    }
    if (e.key === 'k' || e.key === 'K') {
      if (state.activeTab === 'tab-evidence') {
        e.preventDefault();
        selectPreviousEvidenceRow();
        return;
      }
    }
  });

  // New Case Modal Trigger
  const newCaseBtn = document.getElementById('btn-new-case');
  if (newCaseBtn) {
    newCaseBtn.addEventListener('click', openNewCaseModal);
  }

  document.getElementById('btn-use-example-case').addEventListener('click', () => {
    document.getElementById('new-case-title').value = 'Suspicious Workstation Compromise';
    document.getElementById('new-case-number').value = 'CASE-DEMO-001';
    document.getElementById('new-case-desc').value =
      'Investigation of suspicious process execution and unusual activity observed on WORKSTATION-01. ' +
      'Includes PowerShell execution, credential dumping attempt via mimikatz, and outbound connection to known C2 IP.';
    document.getElementById('new-case-error').style.display = 'none';
  });

  document.getElementById('form-new-case').addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = document.getElementById('new-case-title').value.trim();
    const case_number = document.getElementById('new-case-number').value.trim();
    const description = document.getElementById('new-case-desc').value.trim();
    const errAlert = document.getElementById('new-case-error');
    errAlert.style.display = 'none';

    const isExampleCase = (case_number === 'CASE-DEMO-001' || title === 'Suspicious Workstation Compromise');

    try {
      const newInv = await apiRequest('/investigations', {
        method: 'POST',
        body: JSON.stringify({ title, case_number, description, status: 'OPEN' }),
      });
      window.closeModal(document.getElementById('modal-new-case'));
      showAlert(`Investigation '${newInv.title}' created successfully.`, 'success');
      state.activeInvestigationId = newInv.id;
      await loadInvestigations();
      if (isExampleCase) showExampleEvidenceBanner();
    } catch (err) {
      errAlert.textContent = err.message;
      errAlert.style.display = 'block';
    }
  });

  // Example Evidence Banner
  document.getElementById('btn-import-example-evidence').addEventListener('click', async () => {
    if (state.isPipelineRunning) {
      showAlert('Pipeline is executing. Please wait for completion before importing evidence.', 'warning');
      return;
    }
    if (!state.activeInvestigationId) {
      showAlert('No active investigation. Please create a case first.', 'warning');
      return;
    }
    try {
      setPipelineState('Importing...', 'warning');
      showAlert('Fetching and importing example evidence CSV...', 'warning');

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
        `Ready for pipeline analysis.`,
        'success',
        8000
      );
      hideExampleEvidenceBanner();
      await loadActiveInvestigationSummary();
      setPipelineState('Ready', 'success');
    } catch (err) {
      showAlert(`Example evidence import failed: ${err.message}`, 'danger');
      setPipelineState('Error', 'danger');
    }
  });

  document.getElementById('btn-dismiss-example-banner').addEventListener('click', () => {
    hideExampleEvidenceBanner();
  });

  const exampleBannerDl = document.getElementById('btn-download-example-evidence');
  if (exampleBannerDl) {
    exampleBannerDl.href = `${API_BASE}/examples/example_evidence.csv`;
  }

  // Import Evidence Modal Triggers
  const headerImportBtn = document.getElementById('btn-action-import');
  if (headerImportBtn) headerImportBtn.addEventListener('click', openImportEvidenceModal);

  const tabImportBtn = document.getElementById('btn-evidence-tab-import');
  if (tabImportBtn) tabImportBtn.addEventListener('click', openImportEvidenceModal);

  // Import Evidence Form
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
      const res = await apiRequest('/evidence/import', { method: 'POST', body: formData });
      succAlert.textContent = `Evidence ingested: ${res.total_records} records (SHA-256: ${res.sha256_hash.substring(0, 12)}...)`;
      succAlert.style.display = 'block';
      setTimeout(() => {
        window.closeModal(document.getElementById('modal-import-evidence'));
        document.getElementById('btn-submit-import').disabled = false;
        loadActiveInvestigationSummary();
        refreshActiveDestinationView();
        setPipelineState('Ready', 'success');
      }, 1500);
    } catch (err) {
      errAlert.textContent = err.message;
      errAlert.style.display = 'block';
      document.getElementById('btn-submit-import').disabled = false;
      setPipelineState('Import Error', 'danger');
    }
  });
}

// ==========================================================================
// Lazy Destination Data Loaders with Stale Response Guards
// ==========================================================================

async function loadSources() {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.sources;

  try {
    const sources = await apiRequest(`/investigations/${currentInvId}/sources`);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.sources) return; // Stale guard
    state.sourcesCache.clear();
    (sources || []).forEach(s => state.sourcesCache.set(s.id, s));
    populateEvidenceSourceFilter(sources);
    renderSourcesTable(sources);
    updateWorkflowGuide();
  } catch (err) {
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.sources) return;
    showAlert(`Failed to refresh sources: ${err.message}`, 'danger');
  }
}

async function loadAllPrioritizations() {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.prioritization;
  const tbody = document.getElementById('all-prio-tbody');
  if (!tbody) return;
  const tier = document.getElementById('filter-prio-tier').value;
  const method = document.getElementById('filter-prio-method').value;

  let query = `/prioritization/results?investigation_id=${currentInvId}&limit=100`;
  if (tier) query += `&priority_tier=${tier}`;
  if (method) query += `&method_type=${method}`;

  try {
    const res = await apiRequest(query);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.prioritization) return; // Stale guard
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No priority results yet. Run "Run Full Analysis Pipeline" or selective prioritization.</td></tr>';
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
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.prioritization) return;
    tbody.innerHTML = `<tr><td colspan="7" class="text-danger text-center">Error loading results: ${err.message}</td></tr>`;
  }
}

function getFindingTierBadgeClass(tier) {
  const t = (tier || '').toUpperCase();
  if (t === 'CRITICAL') return 'badge-tier-critical';
  if (t === 'HIGH') return 'badge-tier-high';
  if (t === 'MEDIUM') return 'badge-tier-medium';
  if (t === 'LOW') return 'badge-tier-low';
  return 'badge-tier-info';
}

function updateFindingsSummaryMetrics(findings) {
  let highCount = 0;
  let medCount = 0;
  let lowCount = 0;

  findings.forEach(f => {
    const tier = (f.priority_tier || '').toUpperCase();
    const sev = typeof f.severity === 'number' ? f.severity : (f.severity_score || 0);

    if (tier === 'CRITICAL' || tier === 'HIGH' || (!tier && sev >= 0.6)) {
      highCount++;
    } else if (tier === 'MEDIUM' || (!tier && sev >= 0.4 && sev < 0.6)) {
      medCount++;
    } else {
      lowCount++;
    }
  });

  const elTotal = document.getElementById('findings-count-total');
  if (elTotal) elTotal.textContent = findings.length;
  const elHigh = document.getElementById('findings-count-high');
  if (elHigh) elHigh.textContent = highCount;
  const elMed = document.getElementById('findings-count-medium');
  if (elMed) elMed.textContent = medCount;
  const elLow = document.getElementById('findings-count-low');
  if (elLow) elLow.textContent = lowCount;
}

function applyFindingsFilters() {
  const raw = state.findingsState.rawFindings || [];
  const search = (state.findingsState.searchQuery || '').trim().toLowerCase();
  const prio = (state.findingsState.priorityFilter || '').toUpperCase().trim();
  const method = (state.findingsState.methodFilter || '').toUpperCase().trim();
  const activity = (state.findingsState.activityFilter || '').toUpperCase().trim();

  // Update visual state of summary KPI cards
  const cardTotal = document.getElementById('metric-card-total');
  const cardHigh = document.getElementById('metric-card-high');
  const cardMed = document.getElementById('metric-card-medium');
  const cardLow = document.getElementById('metric-card-low');

  if (cardTotal) cardTotal.classList.toggle('active-metric-filter', !prio && !search && !method && !activity);
  if (cardHigh) cardHigh.classList.toggle('active-metric-filter', prio === 'HIGH' || prio === 'CRITICAL');
  if (cardMed) cardMed.classList.toggle('active-metric-filter', prio === 'MEDIUM');
  if (cardLow) cardLow.classList.toggle('active-metric-filter', prio === 'LOW' || prio === 'INFORMATIONAL');

  const filtered = raw.filter(f => {
    // 1. Search filter: Title, description, finding ID, evidence IDs, rule ID/name
    if (search) {
      const title = (f.title || f.rule_name || '').toLowerCase();
      const desc = (f.description || '').toLowerCase();
      const fid = (f.id || '').toLowerCase();
      const rid = (f.rule_id || '').toLowerCase();
      const tactic = (f.mitre_tactic || '').toLowerCase();
      const technique = (f.mitre_technique || '').toLowerCase();
      const methodText = (f.detection_method || f.finding_type || '').toLowerCase();
      const evMatches = (f.evidence_ids || []).some(eid => String(eid).toLowerCase().includes(search));
      const actMatches = (f.activity_ids || []).some(aid => String(aid).toLowerCase().includes(search)) ||
                         (f.activity_id && String(f.activity_id).toLowerCase().includes(search));

      const matchesSearch = title.includes(search) ||
                            desc.includes(search) ||
                            fid.includes(search) ||
                            rid.includes(search) ||
                            tactic.includes(search) ||
                            technique.includes(search) ||
                            methodText.includes(search) ||
                            evMatches ||
                            actMatches;
      if (!matchesSearch) return false;
    }

    // 2. Priority Filter
    if (prio) {
      const tier = (f.priority_tier || '').toUpperCase();
      const sev = typeof f.severity === 'number' ? f.severity : (f.severity_score || 0);

      if (prio === 'CRITICAL') {
        if (tier !== 'CRITICAL' && (tier || sev < 0.8)) return false;
      } else if (prio === 'HIGH') {
        if (tier !== 'HIGH' && (tier || (sev < 0.6 || sev >= 0.8))) return false;
      } else if (prio === 'MEDIUM') {
        if (tier !== 'MEDIUM' && (tier || (sev < 0.4 || sev >= 0.6))) return false;
      } else if (prio === 'LOW') {
        if (tier !== 'LOW' && (tier || (sev < 0.2 || sev >= 0.4))) return false;
      } else if (prio === 'INFORMATIONAL') {
        if (tier !== 'INFORMATIONAL' && (tier || sev >= 0.2)) return false;
      }
    }

    // 3. Detection Method Filter
    if (method) {
      const ft = (f.finding_type || '').toUpperCase();
      const dm = (f.detection_method || '').toUpperCase();
      const rid = (f.rule_id || '').toUpperCase();

      if (method === 'RULE') {
        if (ft === 'ML_ANOMALY' || dm.includes('MACHINE LEARNING')) return false;
      } else if (method === 'DETERMINISTIC') {
        if (ft !== 'RULE_MATCH' || dm.includes('SEQUENCE') || rid.includes('SEQ')) return false;
      } else if (method === 'SEQUENCE') {
        if (!dm.includes('SEQUENCE') && !rid.includes('SEQ')) return false;
      } else if (method === 'IOC') {
        if (ft !== 'IOC_MATCH' && !dm.includes('IOC')) return false;
      } else if (method === 'ML') {
        if (ft !== 'ML_ANOMALY' && !dm.includes('MACHINE LEARNING')) return false;
      }
    }

    // 4. Activity Filter
    if (activity) {
      const hasAct = (f.activity_ids && f.activity_ids.length > 0) || !!f.activity_id;
      if (activity === 'CORRELATED' && !hasAct) return false;
      if (activity === 'UNCORRELATED' && hasAct) return false;
    }

    return true;
  });

  state.findingsState.filteredFindings = filtered;
  renderFindingsTable(filtered);
}

function renderFindingsTable(findings) {
  const tbody = document.getElementById('findings-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const filterStatusEl = document.getElementById('findings-filter-status');
  const matchCountEl = document.getElementById('findings-match-count');
  const isFiltered = !!(state.findingsState.searchQuery || state.findingsState.priorityFilter || state.findingsState.methodFilter || state.findingsState.activityFilter);

  if (filterStatusEl && matchCountEl) {
    if (isFiltered) {
      filterStatusEl.style.display = 'flex';
      matchCountEl.textContent = `Showing ${findings.length} of ${state.findingsState.rawFindings.length} findings matching filters`;
    } else {
      filterStatusEl.style.display = 'none';
    }
  }

  if (!findings || findings.length === 0) {
    if (state.findingsState.rawFindings.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted" style="padding: 24px;">No analytical findings detected in this case. Run detections to evaluate evidence against rules.</td></tr>';
    } else {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding: 24px;">
        <div style="margin-bottom: 8px;">No findings match the selected filters or search query.</div>
        <button class="btn btn-secondary btn-sm" onclick="resetFindingsFilters()">Clear Filters</button>
      </td></tr>`;
    }
    const summaryCard = document.getElementById('selected-finding-summary-card');
    if (summaryCard) summaryCard.style.display = 'none';
    return;
  }

  // Ensure selected finding is valid or select top finding
  let selectedId = state.findingsState.selectedFindingId;
  if (!selectedId || !findings.some(f => f.id === selectedId)) {
    selectedId = findings[0].id;
    state.findingsState.selectedFindingId = selectedId;
  }

  findings.forEach(f => {
    const isSelected = f.id === selectedId;
    const tr = document.createElement('tr');
    tr.className = `finding-row ${isSelected ? 'row-selected' : ''}`;
    tr.id = `finding-row-${f.id}`;
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-selected', isSelected ? 'true' : 'false');

    // Priority display & source attribution
    const tier = (f.priority_tier || (f.severity >= 0.8 ? 'CRITICAL' : f.severity >= 0.6 ? 'HIGH' : f.severity >= 0.4 ? 'MEDIUM' : 'LOW')).toUpperCase();
    const badgeClass = getFindingTierBadgeClass(tier);

    let prioBadgeHtml = '';
    if (typeof f.priority_score === 'number') {
      const srcLabel = f.priority_source === 'ACTIVITY' ? 'Contextual Activity' : 'Baseline Artifact';
      prioBadgeHtml = `
        <span class="badge ${badgeClass}" title="${srcLabel} Priority: ${f.priority_score.toFixed(1)} / 100">
          ${tier} <span style="opacity: 0.85; margin-left: 3px;">${f.priority_score.toFixed(0)}</span>
        </span>
      `;
    } else {
      prioBadgeHtml = `
        <span class="badge ${badgeClass}" title="Unprioritized: Tier derived from direct detection severity (${f.severity.toFixed(2)})">
          ${tier} <span style="opacity: 0.75; font-size: 9px; margin-left: 3px;">(SEV)</span>
        </span>
      `;
    }

    // Title & Rule subtext
    const primaryTitle = f.title || f.rule_name || formatEnum(f.finding_type);
    const ruleSubtext = f.rule_id || '—';

    // Detection Method
    const methodText = f.detection_method || (f.finding_type === 'ML_ANOMALY' ? 'ML Anomaly' : f.finding_type === 'IOC_MATCH' ? 'Rule (IOC)' : 'Rule (Deterministic)');

    // Supporting Evidence count & chips
    const evIds = f.evidence_ids || [];
    const evCount = f.evidence_count || evIds.length;
    let evChips = '';
    if (evIds.length > 0) {
      const previewIds = evIds.slice(0, 2);
      const chipsHtml = previewIds.map(eid => `<span class="finding-evidence-chip" title="${escapeHtml(eid)}">EVD-${escapeHtml(String(eid).slice(0, 6))}</span>`).join('');
      const moreHtml = evIds.length > 2 ? `<span class="text-xs text-muted" style="margin-left: 4px;">+${evIds.length - 2}</span>` : '';
      evChips = `<div style="display: flex; align-items: center; gap: 4px; margin-top: 3px; flex-wrap: wrap;">${chipsHtml}${moreHtml}</div>`;
    }

    // Related Activity
    const actId = f.activity_id || (f.activity_ids && f.activity_ids.length > 0 ? f.activity_ids[0] : null);
    let actHtml = '<span class="text-muted text-xs">Uncorrelated</span>';
    if (actId) {
      actHtml = `<span class="badge badge-mono text-xs" style="color: var(--accent-technical);" title="${escapeHtml(actId)}">ACT-${escapeHtml(String(actId).slice(0, 6))}</span>`;
    }

    tr.innerHTML = `
      <td>
        ${prioBadgeHtml}
      </td>
      <td>
        <div class="finding-title-cell">
          <span class="finding-primary-title">${escapeHtml(primaryTitle)}</span>
          <span class="finding-rule-subtext">${escapeHtml(ruleSubtext)}</span>
        </div>
      </td>
      <td>
        <span class="badge badge-mono text-xs">${escapeHtml(methodText)}</span>
      </td>
      <td>
        <div style="font-size: 11px;">
          <strong>${evCount}</strong> record${evCount === 1 ? '' : 's'}
        </div>
        ${evChips}
      </td>
      <td>
        ${actHtml}
      </td>
      <td class="text-xs text-muted">
        ${new Date(f.created_at).toLocaleString()}
      </td>
      <td style="text-align: center;">
        <button class="btn btn-secondary btn-xs" onclick="event.stopPropagation(); viewFindingProofModal('${escapeHtml(f.id)}')" title="Inspect evidence verification proof">
          Inspect
        </button>
      </td>
    `;

    tr.addEventListener('click', () => selectFinding(f.id));
    tr.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        selectFinding(f.id);
      }
    });

    tbody.appendChild(tr);
  });

  // Update selected finding summary card
  if (selectedId) {
    const activeItem = findings.find(f => f.id === selectedId) || findings[0];
    renderSelectedFindingSummary(activeItem);
  }
}

function selectFinding(findingId) {
  state.findingsState.selectedFindingId = findingId;

  // Update table row styling
  document.querySelectorAll('.finding-row').forEach(row => {
    row.classList.remove('row-selected');
    row.setAttribute('aria-selected', 'false');
  });
  const selectedRow = document.getElementById(`finding-row-${findingId}`);
  if (selectedRow) {
    selectedRow.classList.add('row-selected');
    selectedRow.setAttribute('aria-selected', 'true');
  }

  const finding = (state.findingsState.rawFindings || []).find(f => f.id === findingId);
  if (finding) {
    renderSelectedFindingSummary(finding);
  }
}

function renderSelectedFindingSummary(f) {
  const card = document.getElementById('selected-finding-summary-card');
  if (!card) return;
  card.style.display = 'flex';

  const titleEl = document.getElementById('selected-finding-title');
  if (titleEl) titleEl.textContent = f.title || f.rule_name || formatEnum(f.finding_type);

  const prioBadge = document.getElementById('selected-finding-prio-badge');
  if (prioBadge) {
    const tier = (f.priority_tier || (f.severity >= 0.8 ? 'CRITICAL' : f.severity >= 0.6 ? 'HIGH' : f.severity >= 0.4 ? 'MEDIUM' : 'LOW')).toUpperCase();
    prioBadge.className = `badge ${getFindingTierBadgeClass(tier)}`;
    if (typeof f.priority_score === 'number') {
      const srcText = f.priority_source === 'ACTIVITY' ? 'ACTIVITY PRIORITY' : 'ARTIFACT PRIORITY';
      prioBadge.textContent = `${tier} · ${srcText} ${f.priority_score.toFixed(1)} / 100`;
      prioBadge.title = `Computed by ${srcText} prioritization in the 7-stage pipeline.`;
    } else {
      prioBadge.textContent = `${tier} · SEVERITY ${f.severity.toFixed(2)} (FALLBACK)`;
      prioBadge.title = 'Target not yet prioritized by the pipeline. Tier derived from direct detection severity score.';
    }
  }

  const methodBadge = document.getElementById('selected-finding-method-badge');
  if (methodBadge) {
    methodBadge.textContent = f.detection_method || (f.finding_type === 'ML_ANOMALY' ? 'ML Anomaly' : 'Rule-based');
  }

  const sevBadge = document.getElementById('selected-finding-severity-badge');
  if (sevBadge) {
    sevBadge.textContent = `RAW SEV: ${f.severity.toFixed(2)} / 1.00`;
    sevBadge.title = 'Raw algorithmic or configured rule severity score';
  }

  const idDisplay = document.getElementById('selected-finding-id-display');
  if (idDisplay) idDisplay.textContent = `ID: ${f.id}`;

  const ruleEl = document.getElementById('selected-finding-rule');
  if (ruleEl) ruleEl.textContent = f.rule_id || '—';

  const methodDetailEl = document.getElementById('selected-finding-method-detail');
  if (methodDetailEl) methodDetailEl.textContent = f.detection_method || formatEnum(f.finding_type);

  const mitreEl = document.getElementById('selected-finding-mitre');
  if (mitreEl) {
    mitreEl.textContent = f.mitre_tactic ? `${f.mitre_tactic} / ${f.mitre_technique || 'General'}` : 'None specified';
  }

  const tsEl = document.getElementById('selected-finding-timestamp');
  if (tsEl) {
    tsEl.textContent = f.created_at ? new Date(f.created_at).toLocaleString() : '—';
  }

  const actEl = document.getElementById('selected-finding-activity');
  if (actEl) {
    const actId = f.activity_id || (f.activity_ids && f.activity_ids.length > 0 ? f.activity_ids[0] : null);
    actEl.textContent = actId ? `Activity ID: ${actId}` : 'None (Uncorrelated)';
    actEl.className = actId ? 'summary-meta-value font-mono text-accent' : 'summary-meta-value text-muted';
  }

  const evEl = document.getElementById('selected-finding-evidence');
  if (evEl) {
    const evIds = f.evidence_ids || [];
    evEl.textContent = `${evIds.length} associated record${evIds.length === 1 ? '' : 's'}${evIds.length > 0 ? ` (${evIds.slice(0, 2).map(id => 'EVD-' + String(id).slice(0, 6)).join(', ')}${evIds.length > 2 ? '...' : ''})` : ''}`;
  }

  const descEl = document.getElementById('selected-finding-desc');
  if (descEl) descEl.textContent = f.description || 'No description provided.';

  const fpEl = document.getElementById('selected-finding-fingerprint');
  if (fpEl) fpEl.textContent = f.detection_fingerprint || f.id || '—';

  const jsonPre = document.getElementById('selected-finding-raw-json');
  if (jsonPre) jsonPre.textContent = JSON.stringify(f, null, 2);

  const btnInspect = document.getElementById('btn-selected-finding-inspect');
  if (btnInspect) {
    btnInspect.onclick = () => viewFindingProofModal(f.id);
  }

  // Asynchronously fetch complete Phase 2 finding explanation
  loadDetailedFindingExplanation(f.id);
}

async function loadDetailedFindingExplanation(findingId) {
  const invId = state.activeInvestigationId;
  const whyContent = document.getElementById('finding-why-detected-content');
  const evContent = document.getElementById('finding-evidence-trace-content');
  const actContent = document.getElementById('finding-activity-trace-content');
  const prioContent = document.getElementById('finding-priority-trace-content');
  const chainTrack = document.getElementById('finding-chain-track');

  if (whyContent) whyContent.innerHTML = '<div class="text-muted text-xs" style="padding: 10px;">Resolving detection logic and condition evaluation...</div>';
  if (evContent) evContent.innerHTML = '<div class="text-muted text-xs" style="padding: 10px;">Resolving supporting evidence provenance and cryptographic hashes...</div>';
  if (actContent) actContent.innerHTML = '<div class="text-muted text-xs" style="padding: 10px;">Analyzing correlated activity clusters and graph relationships...</div>';
  if (prioContent) prioContent.innerHTML = '<div class="text-muted text-xs" style="padding: 10px;">Resolving priority triage and factor breakdown...</div>';

  try {
    const url = `/detection/findings/${findingId}${invId ? `?investigation_id=${encodeURIComponent(invId)}` : ''}`;
    const detail = await apiRequest(url);

    // Update raw json with enriched detail payload
    const jsonPre = document.getElementById('selected-finding-raw-json');
    if (jsonPre) jsonPre.textContent = JSON.stringify(detail, null, 2);

    const explanation = detail.explanation;
    if (!explanation) {
      if (whyContent) whyContent.innerHTML = '<div class="text-muted text-xs">Standard finding summary loaded. Detailed explanation unavailable.</div>';
      return;
    }

    // 1. Render Investigation Traceability Chain
    renderInvestigationChain(explanation.investigation_chain || []);

    // 2. Render "Why Was This Detected?"
    renderWhyDetectedSection(explanation.detection);

    // 3. Render Supporting Evidence Traceability
    renderSupportingEvidenceSection(explanation.evidence || []);

    // 4. Render Correlated Activities
    renderCorrelatedActivitiesSection(explanation.activities || []);

    // 5. Render Priority Determination & Breakdown
    renderPriorityExplanationSection(explanation.priority, explanation.secondary_priorities || []);

  } catch (err) {
    const errorHtml = `<div class="alert alert-danger" style="font-size: 11px; margin: 4px 0;">Error loading explanation: ${escapeHtml(err.message)}</div>`;
    if (whyContent) whyContent.innerHTML = errorHtml;
    if (evContent) evContent.innerHTML = errorHtml;
    if (actContent) actContent.innerHTML = errorHtml;
    if (prioContent) prioContent.innerHTML = errorHtml;
  }
}

function renderInvestigationChain(nodes) {
  const track = document.getElementById('finding-chain-track');
  if (!track) return;
  if (!nodes || nodes.length === 0) {
    track.innerHTML = '<div class="text-muted text-xs">Investigation chain unavailable.</div>';
    return;
  }

  let html = '';
  nodes.forEach((node, idx) => {
    const isInteractive = node.id && (node.node_type === 'EVIDENCE' || node.node_type === 'ACTIVITY');
    let typeClass = 'chain-node-finding';
    let clickAttr = '';

    if (node.node_type === 'EVIDENCE') {
      typeClass = 'chain-node-evidence';
      if (node.id) clickAttr = `onclick="window.jumpToEvidenceRecord('', '${escapeHtml(node.id)}')" title="View in Evidence Explorer"`;
    } else if (node.node_type === 'ACTIVITY') {
      typeClass = 'chain-node-activity';
      if (node.id) clickAttr = `onclick="window.jumpToActivityRecord('${escapeHtml(node.id)}')" title="Scroll to Activity"`;
    } else if (node.node_type === 'PRIORITY') {
      typeClass = 'chain-node-priority';
      clickAttr = `onclick="document.getElementById('finding-section-priority')?.scrollIntoView({behavior:'smooth'})" title="Inspect Priority Breakdown"`;
    }

    html += `
      <div class="chain-node ${typeClass} ${isInteractive || node.node_type === 'PRIORITY' ? 'interactive-node' : ''}" ${clickAttr}>
        <div class="chain-node-header">
          <span class="chain-node-type">${escapeHtml(node.node_type)}</span>
          ${node.status_or_tier ? `<span class="badge badge-mono text-xs">${escapeHtml(node.status_or_tier)}</span>` : ''}
        </div>
        <div class="chain-node-title">${escapeHtml(node.label)}</div>
        ${node.sublabel ? `<div class="chain-node-sub">${escapeHtml(node.sublabel)}</div>` : ''}
      </div>
    `;

    if (idx < nodes.length - 1) {
      html += `<span class="chain-connector">&rarr;</span>`;
    }
  });

  track.innerHTML = html;
}

function renderWhyDetectedSection(det) {
  const content = document.getElementById('finding-why-detected-content');
  const catBadge = document.getElementById('finding-why-category-badge');
  if (!content) return;
  if (!det) {
    content.innerHTML = '<div class="text-muted text-xs">No detection logic metadata available.</div>';
    return;
  }

  if (catBadge) {
    catBadge.textContent = det.category.replace(/_/g, ' ');
  }

  let bannerClass = 'why-banner-rule';
  if (det.category === 'SEQUENCE') bannerClass = 'why-banner-sequence';
  else if (det.category === 'IOC') bannerClass = 'why-banner-ioc';
  else if (det.category === 'ISOLATION_FOREST') bannerClass = 'why-banner-ml';

  let html = `
    <div class="why-summary-banner ${bannerClass}">
      <strong>Detection Summary:</strong> ${escapeHtml(det.summary)}
    </div>
  `;

  // Matched Conditions Table for Rule & IOC findings
  if (det.matched_conditions && det.matched_conditions.length > 0) {
    html += `
      <div style="margin-top: 4px;">
        <span class="summary-meta-label" style="display: block; margin-bottom: 6px;">Evaluated Rule Conditions &amp; Observed Attributes</span>
        <table class="conditions-table">
          <thead>
            <tr>
              <th>Target Field</th>
              <th>Operator</th>
              <th>Configured Value</th>
              <th>Observed Evidence Value</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            ${det.matched_conditions.map(c => `
              <tr>
                <td><code class="font-mono">${escapeHtml(c.field)}</code></td>
                <td><span class="badge badge-mono">${escapeHtml(c.operator)}</span></td>
                <td><code class="font-mono text-accent">${escapeHtml(String(c.expected_value))}</code></td>
                <td><code class="font-mono">${escapeHtml(String(c.actual_value !== null ? c.actual_value : '—'))}</code></td>
                <td><span class="condition-matched-pill">${c.matched ? 'MATCHED' : 'UNMATCHED'}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  // Sequence detection details
  if (det.category === 'SEQUENCE' && det.sequence_steps && det.sequence_steps.length > 0) {
    html += `
      <div style="margin-top: 6px;">
        <span class="summary-meta-label" style="display: block; margin-bottom: 6px;">Satisfied Sequence Progression (${det.actual_span_seconds !== null ? `${det.actual_span_seconds}s total` : ''})</span>
        <div class="sequence-steps-container">
          ${det.sequence_steps.map(step => `
            <div class="sequence-step-card">
              <div class="sequence-step-left">
                <span class="step-num-badge">${step.step_index}</span>
                <div>
                  <strong>${escapeHtml(step.event_type || 'Event')}</strong>
                  ${step.status ? `<span class="badge badge-mono text-xs" style="margin-left: 6px;">${escapeHtml(step.status)}</span>` : ''}
                  ${step.timestamp ? `<span class="text-xs text-muted font-mono" style="margin-left: 8px;">${new Date(step.timestamp).toLocaleTimeString()}</span>` : ''}
                </div>
              </div>
              <div>
                ${step.evidence_id ? `
                  <button type="button" class="btn btn-ghost btn-xs" onclick="window.jumpToEvidenceRecord('', '${escapeHtml(step.evidence_id)}')" title="Inspect Step Evidence">
                    View Step Event &rarr;
                  </button>
                ` : ''}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // IOC Match context note
  if (det.category === 'IOC') {
    html += `
      <div class="forensic-notice-box" style="margin-top: 6px;">
        <strong>Forensic Threat Indicator Context:</strong>
        <p style="margin: 4px 0 0;">${escapeHtml(det.context_note || 'Matches documented threat intelligence indicator.')}</p>
      </div>
    `;
  }

  // Isolation Forest ML context note & features
  if (det.category === 'ISOLATION_FOREST') {
    html += `
      <div style="display: flex; gap: 12px; margin-top: 6px; flex-wrap: wrap;">
        <div class="summary-meta-item" style="flex: 1; min-width: 140px;">
          <span class="summary-meta-label">Anomaly Score</span>
          <span class="summary-meta-value font-mono text-accent"><strong>${det.anomaly_score !== null ? det.anomaly_score.toFixed(2) : '—'}</strong> / 1.00</span>
        </div>
        <div class="summary-meta-item" style="flex: 1; min-width: 140px;">
          <span class="summary-meta-label">Decision Threshold</span>
          <span class="summary-meta-value font-mono">${typeof det.threshold === 'number' ? det.threshold.toFixed(2) : '95th %ile (Batch)'}</span>
        </div>
        <div class="summary-meta-item" style="flex: 1; min-width: 140px;">
          <span class="summary-meta-label">Model Classification</span>
          <span class="summary-meta-value"><span class="badge badge-mono">BEHAVIORAL OUTLIER</span></span>
        </div>
      </div>
      <div class="forensic-notice-box notice-ml" style="margin-top: 6px;">
        <strong>Isolation Forest Statistical Context:</strong>
        <p style="margin: 4px 0 0;">${escapeHtml(det.ml_note || 'Event classified as outlier based on multidimensional feature partition depths.')}</p>
      </div>
    `;
  }

  content.innerHTML = html;
}

function renderSupportingEvidenceSection(evidenceList) {
  const content = document.getElementById('finding-evidence-trace-content');
  const countBadge = document.getElementById('finding-evidence-count-badge');
  if (!content) return;

  if (countBadge) {
    countBadge.textContent = `${evidenceList.length} RECORD${evidenceList.length === 1 ? '' : 'S'}`;
  }

  if (!evidenceList || evidenceList.length === 0) {
    content.innerHTML = '<div class="empty-trace-note">No supporting evidence is currently linked to this finding.</div>';
    return;
  }

  let html = '';
  evidenceList.forEach(ev => {
    html += `
      <div class="evidence-trace-card">
        <div class="evidence-trace-header">
          <div class="evidence-trace-meta">
            <span class="badge badge-mono">${escapeHtml(ev.event_type)}</span>
            <span class="font-mono text-xs text-muted">${new Date(ev.timestamp).toLocaleString()}</span>
            <strong style="font-size: 12px;">${escapeHtml(ev.source_name)}</strong>
            <span class="badge badge-mono text-xs">Offset #${ev.raw_record_offset}</span>
          </div>
          <div>
            <button type="button" class="btn btn-secondary btn-xs" onclick="window.jumpToEvidenceRecord('${escapeHtml(ev.source_id)}', '${escapeHtml(ev.id)}')" title="Navigate directly to this record in Evidence Explorer">
              View Evidence &rarr;
            </button>
          </div>
        </div>

        <div class="evidence-entities-grid">
          <div class="evidence-entity-item">User: <strong>${escapeHtml(ev.user_id || '—')}</strong></div>
          <div class="evidence-entity-item">Device: <strong>${escapeHtml(ev.device_id || '—')}</strong></div>
          <div class="evidence-entity-item">Process: <code class="font-mono">${escapeHtml(ev.process_name || '—')}</code></div>
          <div class="evidence-entity-item">IP: <code class="font-mono">${escapeHtml(ev.ip_address || '—')}</code></div>
          <div class="evidence-entity-item">Action / Status: <strong>${escapeHtml(ev.action || '—')} / ${escapeHtml(ev.status || '—')}</strong></div>
          <div class="evidence-entity-item">File: <span class="font-mono text-xs">${escapeHtml(ev.file_path || ev.file_hash ? (ev.file_path || ev.file_hash).slice(0, 24) + '...' : '—')}</span></div>
        </div>

        ${ev.sha256_hash ? `
          <div style="font-size: 10px; color: var(--text-muted); display: flex; align-items: center; gap: 6px; padding-top: 2px;">
            <span>Source File Ingestion SHA-256 Digest:</span>
            <code class="font-mono" style="font-size: 10px; color: var(--text-secondary);">${escapeHtml(ev.sha256_hash)}</code>
          </div>
        ` : ''}
      </div>
    `;
  });

  content.innerHTML = html;
}

function renderCorrelatedActivitiesSection(activityList) {
  const content = document.getElementById('finding-activity-trace-content');
  const countBadge = document.getElementById('finding-activity-count-badge');
  if (!content) return;

  if (countBadge) {
    countBadge.textContent = `${activityList.length} ACTIVIT${activityList.length === 1 ? 'Y' : 'IES'}`;
  }

  if (!activityList || activityList.length === 0) {
    content.innerHTML = '<div class="empty-trace-note">No correlated activity is currently associated with this finding.</div>';
    return;
  }

  let html = '';
  activityList.forEach(act => {
    const reasons = act.correlation_reasons || [];
    html += `
      <div class="activity-trace-card" id="activity-trace-${act.id}">
        <div class="activity-trace-header">
          <div>
            <strong style="font-size: 13px;">${escapeHtml(act.title)}</strong>
            <span class="badge badge-mono text-xs" style="margin-left: 6px;">${escapeHtml(act.activity_type)}</span>
            <span class="badge badge-open text-xs" style="margin-left: 4px;">${escapeHtml(act.status)}</span>
          </div>
          <div>
            <button type="button" class="btn btn-secondary btn-xs" onclick="window.jumpToActivityRecord('${escapeHtml(act.id)}')" title="Navigate to Activity in Timeline">
              View Activity &rarr;
            </button>
          </div>
        </div>

        <div style="font-size: 11px; color: var(--text-secondary); display: flex; gap: 14px; flex-wrap: wrap;">
          <span>Event Count: <strong>${act.evidence_count}</strong></span>
          <span>Findings Connected: <strong>${act.finding_count}</strong></span>
          <span>Time Span: <span class="font-mono">${new Date(act.start_time).toLocaleTimeString()} &ndash; ${new Date(act.end_time).toLocaleTimeString()}</span></span>
        </div>

        ${reasons.length > 0 ? `
          <div class="activity-reasons-list">
            <span style="font-size: 10px; font-weight: 600; text-transform: uppercase; color: var(--text-muted);">Correlation Metadata &amp; Connection Basis</span>
            ${reasons.map(r => `
              <div class="activity-reason-item">
                <span class="activity-reason-bullet">&bull;</span>
                <span>${escapeHtml(r)}</span>
              </div>
            `).join('')}
          </div>
        ` : ''}
      </div>
    `;
  });

  content.innerHTML = html;
}

function renderPriorityExplanationSection(prio, secondaries) {
  const content = document.getElementById('finding-priority-trace-content');
  const srcBadge = document.getElementById('finding-priority-source-badge');
  if (!content) return;

  if (srcBadge && prio) {
    srcBadge.textContent = prio.priority_source === 'ACTIVITY'
      ? 'CONTEXTUAL ACTIVITY TRIAGE'
      : prio.priority_source === 'ARTIFACT'
      ? 'BASELINE ARTIFACT TRIAGE'
      : 'SEVERITY FALLBACK';
  }

  if (!prio) {
    content.innerHTML = '<div class="empty-trace-note">Prioritization metadata unavailable.</div>';
    return;
  }

  const isFallback = prio.priority_source === 'SEVERITY_FALLBACK' || !prio.has_priority;
  const factors = prio.factors || [];

  let html = `
    <div style="padding: 10px 12px; background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-xs);">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 8px;">
        <div style="display: flex; align-items: baseline; gap: 10px;">
          <span class="badge ${getFindingTierBadgeClass(prio.priority_tier)}">${prio.priority_tier}</span>
          <span class="font-mono text-sm" style="font-weight: 700; color: var(--text-primary);">
            ${typeof prio.priority_score === 'number' ? `${prio.priority_score.toFixed(1)} / 100.0` : 'SCORE: NONE'}
          </span>
          <span class="text-xs text-muted">(${prio.priority_source})</span>
        </div>
        ${prio.method_type ? `<span class="badge badge-mono text-xs">${escapeHtml(prio.method_type)}</span>` : ''}
      </div>
      <p style="font-size: 12px; color: var(--text-secondary); margin: 0; line-height: 1.4;">
        ${escapeHtml(prio.explanation_text || '')}
      </p>
    </div>
  `;

  if (isFallback) {
    html += `
      <div class="forensic-notice-box" style="margin-top: 6px;">
        <strong>Unprioritized Finding Notice:</strong>
        <p style="margin: 4px 0 0;">
          Prioritization has not been executed yet for this target. The displayed priority tier is derived directly from the raw detection severity score rather than an automated pipeline prioritization triage calculation.
        </p>
      </div>
    `;
  } else if (factors.length > 0) {
    html += `
      <div style="margin-top: 6px;">
        <span class="summary-meta-label" style="display: block; margin-bottom: 6px;">Factor Weight Breakdown &amp; Contributions</span>
        <table class="priority-factors-table">
          <thead>
            <tr>
              <th>Factor Name</th>
              <th>Configured Weight</th>
              <th>Normalized Value</th>
              <th>Score Contribution</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            ${factors.map(f => `
              <tr>
                <td><strong>${escapeHtml(f.name.replace(/_/g, ' '))}</strong></td>
                <td><span class="badge badge-mono">${(f.weight * 100).toFixed(0)}%</span></td>
                <td class="font-mono">${f.normalized_value.toFixed(4)}</td>
                <td class="factor-contrib-val">${f.contribution >= 0 ? '+' : ''}${f.contribution.toFixed(2)} pts</td>
                <td class="text-muted" style="font-size: 11px;">${escapeHtml(f.description)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  // Display secondary priorities (e.g. artifact-level baseline triage if primary was activity-level)
  if (secondaries && secondaries.length > 0) {
    secondaries.forEach(sec => {
      html += `
        <div style="margin-top: 8px; padding: 8px 10px; background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-xs);">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
            <span class="text-xs" style="font-weight: 600; color: var(--text-secondary);">Baseline Evidence Artifact Priority:</span>
            <span class="badge ${getFindingTierBadgeClass(sec.priority_tier)} text-xs">${sec.priority_tier} (${sec.priority_score !== null ? sec.priority_score.toFixed(1) : '—'} / 100)</span>
          </div>
          <p style="font-size: 11px; color: var(--text-muted); margin: 0;">${escapeHtml(sec.explanation_text || '')}</p>
        </div>
      `;
    });
  }

  content.innerHTML = html;
}

window.jumpToActivityRecord = function(activityId) {
  const analysisTab = document.getElementById('nav-tab-analysis');
  if (analysisTab) analysisTab.click();

  const targetRow = document.getElementById(`activity-row-${activityId}`) ||
                    document.getElementById(`activity-trace-${activityId}`);
  if (targetRow) {
    targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
    targetRow.style.outline = '2px solid var(--accent-technical)';
    setTimeout(() => { targetRow.style.outline = ''; }, 2000);
  } else {
    const actTable = document.getElementById('activities-tbody');
    if (actTable) actTable.scrollIntoView({ behavior: 'smooth' });
  }
};

window.copyFindingDetailJson = function(btn) {
  const pre = document.getElementById('selected-finding-raw-json');
  if (!pre) return;
  navigator.clipboard.writeText(pre.textContent).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1500);
  });
};


function resetFindingsFilters() {
  state.findingsState.searchQuery = '';
  state.findingsState.priorityFilter = '';
  state.findingsState.methodFilter = '';
  state.findingsState.activityFilter = '';

  const searchInput = document.getElementById('findings-search-input');
  if (searchInput) searchInput.value = '';
  const searchClear = document.getElementById('findings-search-clear');
  if (searchClear) searchClear.style.display = 'none';

  const prioSelect = document.getElementById('filter-findings-priority');
  if (prioSelect) prioSelect.value = '';

  const methodSelect = document.getElementById('filter-findings-method');
  if (methodSelect) methodSelect.value = '';

  const actSelect = document.getElementById('filter-findings-activity');
  if (actSelect) actSelect.value = '';

  const legacySelect = document.getElementById('filter-finding-type');
  if (legacySelect) legacySelect.value = '';

  document.querySelectorAll('.summary-metric-card').forEach(c => c.classList.remove('active-metric-filter'));

  applyFindingsFilters();
}

async function loadFindings() {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.findings;
  const tbody = document.getElementById('findings-tbody');
  if (!tbody) return;

  try {
    const res = await apiRequest(`/detection/findings?investigation_id=${encodeURIComponent(currentInvId)}&limit=200`);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.findings) return; // Stale guard

    const items = res.items || [];
    state.findingsState.rawFindings = items;

    // Update Investigation Summary metrics at top
    updateFindingsSummaryMetrics(items);

    // Apply active filters and search
    applyFindingsFilters();
  } catch (err) {
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.findings) return;
    tbody.innerHTML = `<tr><td colspan="7" class="text-danger text-center">Error loading findings: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function loadMLAnomalies() {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.findings;
  const tbody = document.getElementById('ml-anomalies-tbody');
  if (!tbody) return;

  try {
    const res = await apiRequest(`/detection/findings?investigation_id=${currentInvId}&finding_type=ML_ANOMALY&limit=100`);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.findings) return; // Stale guard
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No anomalies detected. Run ML Anomaly Analysis (requires >= 10 normalized records per source).</td></tr>';
      return;
    }
    res.items.forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="badge badge-mono">${escapeHtml(f.rule_id)}</span></td>
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
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.findings) return;
    tbody.innerHTML = `<tr><td colspan="6" class="text-danger text-center">Error loading anomalies: ${err.message}</td></tr>`;
  }
}

async function loadCorrelations() {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.correlations;
  const tbody = document.getElementById('correlations-tbody');
  if (!tbody) return;
  const rtype = document.getElementById('filter-rel-type').value;

  let query = `/correlation/relationships?investigation_id=${currentInvId}&limit=100`;
  if (rtype) query += `&relationship_type=${rtype}`;

  try {
    const res = await apiRequest(query);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.correlations) return; // Stale guard
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No evidence correlations discovered yet. Requires >= 2 normalized evidence records.</td></tr>';
      return;
    }
    res.items.forEach(rel => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="badge badge-mono">${formatEnum(rel.relationship_type)}</span></td>
        <td class="font-mono"><strong>${rel.weight.toFixed(2)}</strong></td>
        <td class="font-mono text-sm" title="${escapeHtml(rel.source_evidence_id)}">${compactId(rel.source_evidence_id)}</td>
        <td class="font-mono text-sm" title="${escapeHtml(rel.target_evidence_id)}">${compactId(rel.target_evidence_id)}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="viewDetailModal('Context Attributes', ${escapeHtml(JSON.stringify(rel.context_attributes))})">View Attributes</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.correlations) return;
    tbody.innerHTML = `<tr><td colspan="5" class="text-danger text-center">Error loading correlations: ${err.message}</td></tr>`;
  }
}

async function loadActivities() {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.activities;
  const tbody = document.getElementById('activities-tbody');
  if (!tbody) return;

  try {
    const res = await apiRequest(`/activities?investigation_id=${currentInvId}&limit=100`);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.activities) return; // Stale guard
    tbody.innerHTML = '';
    if (res.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No activity clusters formed yet. Execute "Cluster Activities" or run the full pipeline.</td></tr>';
      return;
    }
    res.items.forEach(act => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${escapeHtml(act.title)}</strong></td>
        <td><span class="badge badge-mono">${formatEnum(act.activity_type)}</span></td>
        <td><span class="badge badge-open">${escapeHtml(act.status)}</span></td>
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
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.activities) return;
    tbody.innerHTML = `<tr><td colspan="8" class="text-danger text-center">Error loading activities: ${err.message}</td></tr>`;
  }
}

// ==========================================================================
// Phase 3: Evidence Explorer & Finding Proof Traceability
// ==========================================================================

function populateEvidenceSourceFilter(sources) {
  const select = document.getElementById('filter-evidence-source');
  if (!select) return;
  const currentVal = select.value;
  select.innerHTML = '<option value="">All Evidence Sources</option>';
  if (sources && sources.length > 0) {
    sources.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s.id;
      opt.textContent = `${s.filename} (${s.file_format})`;
      if (s.id === currentVal) opt.selected = true;
      select.appendChild(opt);
    });
  }
}

window.exploreSourceRecords = function(sourceId) {
  const select = document.getElementById('filter-evidence-source');
  if (select) select.value = sourceId;
  state.evidencePagination.source_id = sourceId;
  state.evidencePagination.offset = 0;
  loadEvidenceRecords();
  const explorerPanel = document.getElementById('evidence-records-panel');
  if (explorerPanel) {
    explorerPanel.scrollIntoView({ behavior: 'smooth' });
  }
};

function formatOffsetBadge(sourceId, rawOffset) {
  const safeOffset = (rawOffset !== null && rawOffset !== undefined) ? rawOffset : 0;
  const source = state.sourcesCache.get(sourceId);
  const format = source ? (source.file_format || '').toUpperCase() : '';

  if (format === 'CSV') {
    return `<span class="tag-offset" title="0-indexed data row in source CSV (header excluded)">Data Row ${safeOffset}</span>`;
  } else if (format === 'JSON') {
    return `<span class="tag-offset" title="Array item index in source JSON payload">Index [${safeOffset}]</span>`;
  } else if (format === 'JSONL' || format === 'LOG') {
    return `<span class="tag-offset" title="Record index in source stream (empty lines excluded)">Record ${safeOffset}</span>`;
  }
  return `<span class="tag-offset" title="Raw source record stream offset">Offset ${safeOffset}</span>`;
}

function middleTruncate(str, frontLen = 10, backLen = 8) {
  if (!str) return '—';
  if (str.length <= frontLen + backLen + 3) return str;
  return `${str.substring(0, frontLen)}…${str.substring(str.length - backLen)}`;
}

async function loadEvidenceRecords() {
  if (!state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.evidence;
  const tbody = document.getElementById('evidence-records-tbody');
  if (!tbody) return;

  const reqId = ++state.evidencePagination.requestId;
  tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Loading normalized evidence records...</td></tr>';

  const { offset, limit, source_id, event_type, user_id, device_id } = state.evidencePagination;
  let query = `/evidence?investigation_id=${currentInvId}&limit=${limit}&offset=${offset}`;
  if (source_id) query += `&source_id=${encodeURIComponent(source_id)}`;
  if (event_type) query += `&event_type=${encodeURIComponent(event_type)}`;
  if (user_id) query += `&user_id=${encodeURIComponent(user_id)}`;
  if (device_id) query += `&device_id=${encodeURIComponent(device_id)}`;

  try {
    const res = await apiRequest(query);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.evidence || reqId !== state.evidencePagination.requestId) return;

    state.evidencePagination.total = res.total || 0;
    renderEvidenceRecordsTable(res.items || [], res.total || 0);
    updateEvidencePaginationControls(res.total || 0, res.offset || 0, res.limit || 25);
  } catch (err) {
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.evidence || reqId !== state.evidencePagination.requestId) return;
    tbody.innerHTML = `<tr><td colspan="7" class="text-danger text-center">Error loading evidence records: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function renderEvidenceRecordsTable(items, total) {
  const tbody = document.getElementById('evidence-records-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  state.currentEvidenceItems = items || [];

  if (!items || items.length === 0) {
    renderEvidenceInspector(null);
    if (total === 0) {
      const hasFilters = state.evidencePagination.source_id ||
                         state.evidencePagination.event_type ||
                         state.evidencePagination.user_id ||
                         state.evidencePagination.device_id;
      if (hasFilters) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No evidence records match the current filter criteria.</td></tr>';
      } else {
        const totalSources = state.sourcesCache.size;
        let anyNormalized = false;
        state.sourcesCache.forEach(s => {
          if (s.normalized_records > 0) anyNormalized = true;
        });
        if (totalSources > 0 && !anyNormalized) {
          tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Evidence sources are staged but unnormalized. Run Stage 1 (Normalize) to populate normalized events.</td></tr>';
        } else {
          tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No evidence records found in this investigation. Import and normalize evidence to explore events.</td></tr>';
        }
      }
    } else {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No records on this page.</td></tr>';
    }
    return;
  }

  // Stable selection: preserve current selection if still in view, otherwise auto-select first row
  let activeIdToSelect = null;
  if (state.selectedEvidenceId && items.some(ev => ev.id === state.selectedEvidenceId)) {
    activeIdToSelect = state.selectedEvidenceId;
  } else if (items.length > 0) {
    activeIdToSelect = items[0].id;
  }
  state.selectedEvidenceId = activeIdToSelect;

  items.forEach(ev => {
    const isSelected = (ev.id === activeIdToSelect);
    const tr = document.createElement('tr');
    tr.className = `evidence-row ${isSelected ? 'row-selected' : ''}`;
    tr.setAttribute('data-evidence-id', ev.id);
    tr.setAttribute('tabindex', '0');
    tr.setAttribute('role', 'row');
    tr.setAttribute('aria-selected', isSelected ? 'true' : 'false');

    const src = state.sourcesCache.get(ev.source_id);
    const srcFilename = src ? src.filename : 'Evidence Source';
    const offsetBadge = formatOffsetBadge(ev.source_id, ev.raw_record_offset);

    // Format Key Entities
    const entities = [];
    if (ev.process_name) entities.push(`<span class="font-mono" style="font-size: 11px;">proc: ${escapeHtml(ev.process_name)}</span>`);
    if (ev.ip_address) entities.push(`<span class="font-mono" style="font-size: 11px;">ip: ${escapeHtml(ev.ip_address)}</span>`);
    if (ev.file_path) entities.push(`<span class="font-mono" style="font-size: 11px;">file: ${escapeHtml(ev.file_path.split(/[/\\]/).pop())}</span>`);
    const entitiesHtml = entities.length > 0 ? entities.join('<br>') : '<span class="text-muted">—</span>';

    // Format User / Device
    let userDeviceHtml = '<span class="text-muted">—</span>';
    if (ev.user_id || ev.device_id) {
      userDeviceHtml = `
        <div style="font-size: 11px;">
          ${ev.user_id ? `<strong>${escapeHtml(ev.user_id)}</strong>` : '<span class="text-muted">No user</span>'}
          ${ev.device_id ? `<br><span class="text-muted text-sm">${escapeHtml(ev.device_id)}</span>` : ''}
        </div>
      `;
    }

    // Format Action / Status
    let actionStatusHtml = '<span class="text-muted">—</span>';
    if (ev.action || ev.status) {
      actionStatusHtml = `
        <div style="font-size: 11px;">
          ${ev.action ? `<span>${escapeHtml(ev.action)}</span>` : ''}
          ${ev.status ? `<br><span class="badge badge-mono">${escapeHtml(ev.status)}</span>` : ''}
        </div>
      `;
    }

    tr.innerHTML = `
      <td class="text-sm font-mono" style="white-space: nowrap;">${new Date(ev.timestamp).toLocaleString()}</td>
      <td><span class="badge badge-mono">${escapeHtml(ev.event_type)}</span></td>
      <td>
        <div style="font-size: 11px;">
          <strong title="${escapeHtml(srcFilename)}">${escapeHtml(srcFilename)}</strong>
          <div style="margin-top: 2px;">${offsetBadge}</div>
        </div>
      </td>
      <td>${userDeviceHtml}</td>
      <td>${actionStatusHtml}</td>
      <td>${entitiesHtml}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="viewEvidenceDetailModal('${escapeHtml(ev.id)}')" title="Inspect complete normalized attributes and raw record payload">Inspect</button>
      </td>
    `;

    // Row selection interactions
    tr.addEventListener('click', (e) => {
      if (e.target.closest('button') || e.target.closest('a') || e.target.closest('input')) return;
      selectEvidenceRecord(ev.id);
    });

    tr.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        selectEvidenceRecord(ev.id);
      }
    });

    tbody.appendChild(tr);
  });

  // Render initial inspector state
  if (activeIdToSelect) {
    const selectedItem = items.find(i => i.id === activeIdToSelect);
    if (selectedItem) {
      renderEvidenceInspector(selectedItem, null, [], true, null);
      loadEvidenceInspector(activeIdToSelect);
    }
  } else {
    renderEvidenceInspector(null);
  }
}

function selectEvidenceRecord(evidenceId) {
  state.selectedEvidenceId = evidenceId;

  // Update table row styling & aria attributes
  const tbody = document.getElementById('evidence-records-tbody');
  if (tbody) {
    tbody.querySelectorAll('tr.evidence-row').forEach(row => {
      const rowId = row.getAttribute('data-evidence-id');
      if (evidenceId && rowId === evidenceId) {
        row.classList.add('row-selected');
        row.setAttribute('aria-selected', 'true');
      } else {
        row.classList.remove('row-selected');
        row.setAttribute('aria-selected', 'false');
      }
    });
  }

  if (!evidenceId) {
    renderEvidenceInspector(null);
    return;
  }

  // Fast optimistic render from memory while full details and findings load
  const cachedItem = (state.currentEvidenceItems || []).find(i => i.id === evidenceId);
  if (cachedItem) {
    renderEvidenceInspector(cachedItem, null, [], true, null);
  }

  loadEvidenceInspector(evidenceId);
}

function selectNextEvidenceRow() {
  const items = state.currentEvidenceItems || [];
  if (items.length === 0) return;
  if (!state.selectedEvidenceId) {
    selectEvidenceRecord(items[0].id);
    scrollSelectedRowIntoView(items[0].id);
    return;
  }
  const currIdx = items.findIndex(i => i.id === state.selectedEvidenceId);
  if (currIdx >= 0 && currIdx < items.length - 1) {
    const nextEv = items[currIdx + 1];
    selectEvidenceRecord(nextEv.id);
    scrollSelectedRowIntoView(nextEv.id);
  }
}

function selectPreviousEvidenceRow() {
  const items = state.currentEvidenceItems || [];
  if (items.length === 0) return;
  if (!state.selectedEvidenceId) {
    selectEvidenceRecord(items[0].id);
    scrollSelectedRowIntoView(items[0].id);
    return;
  }
  const currIdx = items.findIndex(i => i.id === state.selectedEvidenceId);
  if (currIdx > 0) {
    const prevEv = items[currIdx - 1];
    selectEvidenceRecord(prevEv.id);
    scrollSelectedRowIntoView(prevEv.id);
  }
}

function scrollSelectedRowIntoView(evidenceId) {
  const tbody = document.getElementById('evidence-records-tbody');
  if (!tbody) return;
  const row = tbody.querySelector(`tr[data-evidence-id="${evidenceId}"]`);
  if (row) {
    row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    row.focus({ preventScroll: true });
  }
}

async function loadEvidenceInspector(evidenceId) {
  if (!evidenceId || !state.activeInvestigationId) return;
  const currentInvId = state.activeInvestigationId;
  const invVersion = state.investigationVersion;
  const seq = ++state.requestSeq.inspector;

  try {
    const item = await apiRequest(`/evidence/${evidenceId}?investigation_id=${encodeURIComponent(currentInvId)}`);
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.inspector || state.selectedEvidenceId !== evidenceId) return;

    // Check findings referencing this evidence
    let relatedFindings = [];
    try {
      const findingsRes = await apiRequest(`/detection/findings?investigation_id=${encodeURIComponent(currentInvId)}&limit=100`);
      if (invVersion === state.investigationVersion && seq === state.requestSeq.inspector) {
        relatedFindings = (findingsRes.items || []).filter(f => f.evidence_ids && f.evidence_ids.includes(evidenceId));
      }
    } catch {
      // Non-fatal, show without findings
    }

    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.inspector || state.selectedEvidenceId !== evidenceId) return;
    renderEvidenceInspector(item, item, relatedFindings, false, null);
  } catch (err) {
    if (invVersion !== state.investigationVersion || seq !== state.requestSeq.inspector || state.selectedEvidenceId !== evidenceId) return;
    renderEvidenceInspector(null, null, [], false, err.message);
  }
}

function renderEvidenceInspector(ev, fullDetails = null, relatedFindings = [], isLoading = false, error = null) {
  const quickBadge = document.getElementById('inspector-quick-badge');
  const content = document.getElementById('evidence-inspector-content');
  if (!content) return;

  if (error) {
    if (quickBadge) quickBadge.style.display = 'none';
    content.innerHTML = `<div class="alert alert-danger" style="margin: 16px;">Failed to load evidence details: ${escapeHtml(error)}</div>`;
    return;
  }

  if (!ev) {
    if (quickBadge) quickBadge.style.display = 'none';
    content.innerHTML = `
      <div class="inspector-empty-state" style="padding: 32px 16px; text-align: center; color: var(--text-secondary);">
        <div style="font-size: 24px; margin-bottom: 8px; opacity: 0.5;">🔍</div>
        <div style="font-weight: 600; margin-bottom: 4px; color: var(--text-primary);">No Event Selected</div>
        <div class="text-sm text-muted">
          Select an evidence event from the table or press <kbd class="kbd-hint">J</kbd> / <kbd class="kbd-hint">K</kbd> to inspect normalized attributes, forensic provenance, and threat context.
        </div>
      </div>
    `;
    return;
  }

  const item = fullDetails || ev;
  if (quickBadge) {
    quickBadge.textContent = item.event_type || 'EVENT';
    quickBadge.style.display = 'inline-block';
  }

  const src = state.sourcesCache.get(item.source_id);
  const srcFilename = src ? src.filename : 'Evidence Source';
  const srcFormat = src ? (src.file_format || 'RAW') : (item.source_type || 'RAW');
  const srcDigest = src ? (src.sha256_hash || '') : '';
  const offsetBadge = formatOffsetBadge(item.source_id, item.raw_record_offset);
  const rawAttrs = item.attributes || {};

  // Formatted Timestamps
  const isoTime = item.timestamp ? (new Date(item.timestamp).toISOString()) : '—';
  const localTime = item.timestamp ? (new Date(item.timestamp).toLocaleString()) : '—';

  // Command line if present
  const cmdLine = rawAttrs.command_line || rawAttrs.cmdline || rawAttrs.command || null;

  // Hash value display (prominently labeled CLAIMED UNVERIFIED)
  let hashDisplayHtml = '';
  if (item.file_hash) {
    hashDisplayHtml = `
      <div class="inspector-kv" style="grid-column: 1 / -1;">
        <div class="inspector-k" style="display: flex; align-items: center; justify-content: space-between;">
          <span>Log-Extracted File Hash</span>
          <span class="badge badge-mono text-xs" style="background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.3);">
            CLAIMED (UNVERIFIED)
          </span>
        </div>
        <div class="inspector-v" style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-top: 4px;">
          <span class="font-mono text-xs" style="word-break: break-all;" title="${escapeHtml(item.file_hash)}">
            ${middleTruncate(item.file_hash, 12, 10)}
          </span>
          <button class="btn btn-secondary btn-sm" onclick="copyDigest('${escapeHtml(item.file_hash)}', this)" title="Copy log-extracted hash">Copy</button>
        </div>
        <div class="text-xs text-muted" style="margin-top: 4px;">
          Hash value parsed directly from log event stream. Not independently verified against physical disk artifacts.
        </div>
      </div>
    `;
  } else {
    hashDisplayHtml = `
      <div class="inspector-kv" style="grid-column: 1 / -1;">
        <div class="inspector-k">Log-Extracted File Hash</div>
        <div class="inspector-v text-muted text-sm">No cryptographic digest recorded in this event payload.</div>
      </div>
    `;
  }

  // Data Quality Notice
  let dataQualityHtml = '';
  if (rawAttrs._data_quality_warning) {
    dataQualityHtml = `
      <div class="alert alert-warning text-xs" style="margin-bottom: 12px; padding: 8px 10px;">
        <strong>Data Quality Notice:</strong> Raw event deserialization required fallback parsing.
      </div>
    `;
  } else if (rawAttrs.hash_metadata && !rawAttrs.hash_metadata.is_valid && rawAttrs.hash_metadata.status !== 'MISSING') {
    dataQualityHtml = `
      <div class="alert alert-warning text-xs" style="margin-bottom: 12px; padding: 8px 10px;">
        <strong>Non-Standard Hash Notice:</strong> ${escapeHtml(rawAttrs.hash_metadata.status || 'Format Anomaly')}
      </div>
    `;
  }

  // Related Findings
  let findingsHtml = '';
  if (relatedFindings && relatedFindings.length > 0) {
    findingsHtml = relatedFindings.map(f => `
      <div class="inspector-finding-card" style="padding: 10px; background: var(--surface-bg-card); border: 1px solid var(--border-subtle); border-radius: 4px; margin-bottom: 8px;">
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 4px;">
          <strong class="font-mono text-xs">${escapeHtml(f.rule_id || formatEnum(f.finding_type))}</strong>
          <span class="badge ${f.severity >= 0.7 ? 'badge-critical' : f.severity >= 0.4 ? 'badge-high' : 'badge-mono'} text-xs">
            Sev ${f.severity.toFixed(2)}
          </span>
        </div>
        <div class="text-xs text-muted" style="margin-bottom: 6px;">${escapeHtml(f.description || '')}</div>
        ${f.mitre_tactic ? `<div class="badge badge-mono text-xs" style="margin-bottom: 6px;">${escapeHtml(f.mitre_tactic)} / ${escapeHtml(f.mitre_technique || '')}</div>` : ''}
        <div>
          <button class="btn btn-secondary btn-sm" style="font-size: 11px; padding: 2px 8px;" onclick="viewFindingProofModal('${escapeHtml(f.id)}')">Inspect Finding Proof</button>
        </div>
      </div>
    `).join('');
  } else {
    findingsHtml = `<div class="text-xs text-muted">No detection rules or ML anomalies flagged this specific evidence record.</div>`;
  }

  content.innerHTML = `
    ${dataQualityHtml}

    <!-- Core Identity -->
    <div class="inspector-section">
      <div class="inspector-section-title">Core Event Identity</div>
      <div class="inspector-kv-grid">
        <div class="inspector-kv" style="grid-column: 1 / -1;">
          <div class="inspector-k">Evidence ID</div>
          <div class="inspector-v font-mono text-xs" style="word-break: break-all;">${escapeHtml(item.id)}</div>
        </div>
        <div class="inspector-kv">
          <div class="inspector-k">Event Type</div>
          <div class="inspector-v"><span class="badge badge-mono">${escapeHtml(item.event_type)}</span></div>
        </div>
        <div class="inspector-kv">
          <div class="inspector-k">Source Type</div>
          <div class="inspector-v"><span class="badge badge-mono text-xs">${escapeHtml(item.source_type || 'RAW')}</span></div>
        </div>
        <div class="inspector-kv" style="grid-column: 1 / -1;">
          <div class="inspector-k">Timestamp</div>
          <div class="inspector-v font-mono text-xs">${escapeHtml(isoTime)}</div>
          <div class="text-xs text-muted" style="margin-top: 2px;">${escapeHtml(localTime)}</div>
        </div>
      </div>
    </div>

    <!-- Source Provenance -->
    <div class="inspector-section">
      <div class="inspector-section-title">Source Provenance</div>
      <div class="inspector-kv-grid">
        <div class="inspector-kv" style="grid-column: 1 / -1;">
          <div class="inspector-k">Source File</div>
          <div class="inspector-v">
            <strong>${escapeHtml(srcFilename)}</strong>
            <span class="badge badge-mono text-xs" style="margin-left: 6px;">${escapeHtml(srcFormat)}</span>
          </div>
        </div>
        <div class="inspector-kv" style="grid-column: 1 / -1;">
          <div class="inspector-k">Source File SHA-256 (Recorded at Ingestion)</div>
          <div class="inspector-v" style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
            <span class="font-mono text-xs" style="word-break: break-all;" title="${escapeHtml(srcDigest)}">
              ${middleTruncate(srcDigest, 12, 10)}
            </span>
            ${srcDigest ? `<button class="btn btn-secondary btn-sm" onclick="copyDigest('${escapeHtml(srcDigest)}', this)" title="Copy full source SHA-256 digest">Copy</button>` : ''}
          </div>
          <div class="text-xs text-muted" style="margin-top: 2px;">
            Cryptographic SHA-256 digest recorded at initial file ingestion.
          </div>
        </div>
        <div class="inspector-kv" style="grid-column: 1 / -1;">
          <div class="inspector-k">Source Stream Offset</div>
          <div class="inspector-v" style="margin-top: 2px;">${offsetBadge}</div>
        </div>
      </div>
    </div>

    <!-- Common Event Schema Entities -->
    <div class="inspector-section">
      <div class="inspector-section-title">CES Normalized Entities</div>
      <div class="inspector-kv-grid">
        <div class="inspector-kv">
          <div class="inspector-k">User ID</div>
          <div class="inspector-v font-mono text-xs">${item.user_id ? escapeHtml(item.user_id) : '<span class="text-muted">—</span>'}</div>
        </div>
        <div class="inspector-kv">
          <div class="inspector-k">Device ID</div>
          <div class="inspector-v font-mono text-xs">${item.device_id ? escapeHtml(item.device_id) : '<span class="text-muted">—</span>'}</div>
        </div>
        <div class="inspector-kv">
          <div class="inspector-k">Process Name</div>
          <div class="inspector-v font-mono text-xs">${item.process_name ? escapeHtml(item.process_name) : '<span class="text-muted">—</span>'}</div>
        </div>
        <div class="inspector-kv">
          <div class="inspector-k">Process ID</div>
          <div class="inspector-v font-mono text-xs">${(item.process_id !== null && item.process_id !== undefined) ? item.process_id : '<span class="text-muted">—</span>'}</div>
        </div>
        ${item.parent_process_name ? `
          <div class="inspector-kv" style="grid-column: 1 / -1;">
            <div class="inspector-k">Parent Process</div>
            <div class="inspector-v font-mono text-xs">${escapeHtml(item.parent_process_name)}</div>
          </div>
        ` : ''}
        ${cmdLine ? `
          <div class="inspector-kv" style="grid-column: 1 / -1;">
            <div class="inspector-k">Command Line</div>
            <div class="inspector-v font-mono text-xs" style="white-space: pre-wrap; word-break: break-all; background: var(--surface-bg-card); padding: 6px; border-radius: 4px; border: 1px solid var(--border-subtle);">${escapeHtml(cmdLine)}</div>
          </div>
        ` : ''}
        <div class="inspector-kv">
          <div class="inspector-k">Network IP / Port</div>
          <div class="inspector-v font-mono text-xs">
            ${item.ip_address ? `${escapeHtml(item.ip_address)}${item.port ? `:${item.port}` : ''}` : '<span class="text-muted">—</span>'}
          </div>
        </div>
        <div class="inspector-kv">
          <div class="inspector-k">Protocol</div>
          <div class="inspector-v font-mono text-xs">${item.protocol ? escapeHtml(item.protocol) : '<span class="text-muted">—</span>'}</div>
        </div>
        ${item.file_path ? `
          <div class="inspector-kv" style="grid-column: 1 / -1;">
            <div class="inspector-k">File Path</div>
            <div class="inspector-v font-mono text-xs" style="word-break: break-all;">${escapeHtml(item.file_path)}</div>
          </div>
        ` : ''}
        <div class="inspector-kv">
          <div class="inspector-k">Action</div>
          <div class="inspector-v text-xs">${item.action ? escapeHtml(item.action) : '<span class="text-muted">—</span>'}</div>
        </div>
        <div class="inspector-kv">
          <div class="inspector-k">Status</div>
          <div class="inspector-v text-xs">${item.status ? `<span class="badge badge-mono">${escapeHtml(item.status)}</span>` : '<span class="text-muted">—</span>'}</div>
        </div>
      </div>
    </div>

    <!-- Integrity & Extracted Log Metadata -->
    <div class="inspector-section">
      <div class="inspector-section-title">Integrity &amp; Metadata</div>
      <div class="inspector-kv-grid">
        ${hashDisplayHtml}
      </div>
    </div>

    <!-- Threat Context & Related Findings -->
    <div class="inspector-section">
      <div class="inspector-section-title">Related Findings &amp; Threat Context (${relatedFindings.length})</div>
      <div>${findingsHtml}</div>
    </div>

    <!-- Actions & Shortcuts -->
    <div style="margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border-subtle); display: flex; flex-direction: column; gap: 8px;">
      <button class="btn btn-secondary btn-sm" style="width: 100%; text-align: center;" onclick="viewEvidenceDetailModal('${escapeHtml(item.id)}')">
        Inspect Complete Raw JSON Payload
      </button>
      <div class="text-xs text-muted" style="text-align: center; margin-top: 4px;">
        Shortcuts: <kbd class="kbd-hint">J</kbd> Next <kbd class="kbd-hint">K</kbd> Prev <kbd class="kbd-hint">Esc</kbd> Close Inspector
      </div>
    </div>
  `;
}

function updateEvidencePaginationControls(total, offset, limit) {
  const pageInfo = document.getElementById('evidence-page-info');
  const recordSummary = document.getElementById('evidence-record-summary');
  const btnPrev = document.getElementById('btn-evidence-prev');
  const btnNext = document.getElementById('btn-evidence-next');

  if (total === 0) {
    if (pageInfo) pageInfo.textContent = 'Page 1 of 1';
    if (recordSummary) recordSummary.textContent = 'Showing 0 records';
    if (btnPrev) btnPrev.disabled = true;
    if (btnNext) btnNext.disabled = true;
    return;
  }

  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(total / limit) || 1;
  const startRecord = offset + 1;
  const endRecord = Math.min(offset + limit, total);

  if (pageInfo) pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
  if (recordSummary) recordSummary.textContent = `Showing ${startRecord}–${endRecord} of ${total} records`;
  if (btnPrev) btnPrev.disabled = (currentPage <= 1);
  if (btnNext) btnNext.disabled = (currentPage >= totalPages);
}

window.viewEvidenceDetailModal = async function(evidenceId) {
  const titleEl = document.getElementById('modal-detail-title');
  const tierBadge = document.getElementById('modal-detail-tier-badge');
  const explainPanel = document.getElementById('modal-explainability-panel');
  const provPanel = document.getElementById('modal-provenance-panel');
  const genericPanel = document.getElementById('modal-generic-panel');
  const proofPanel = document.getElementById('modal-finding-proof-panel');
  const evDetailPanel = document.getElementById('modal-evidence-detail-panel');
  const evContent = document.getElementById('modal-evidence-detail-content');

  // Reset panels
  if (explainPanel) explainPanel.style.display = 'none';
  if (provPanel) provPanel.style.display = 'none';
  if (genericPanel) genericPanel.style.display = 'none';
  if (proofPanel) proofPanel.style.display = 'none';
  if (tierBadge) tierBadge.style.display = 'none';

  titleEl.textContent = 'Forensic Evidence Record Inspection';
  if (evDetailPanel) evDetailPanel.style.display = 'block';
  if (evContent) evContent.innerHTML = '<div class="text-center text-muted" style="padding: 24px;">Loading evidence record attributes...</div>';

  if (window.openModal) window.openModal('modal-detail');

  try {
    const invId = state.activeInvestigationId;
    const item = await apiRequest(`/evidence/${evidenceId}${invId ? `?investigation_id=${encodeURIComponent(invId)}` : ''}`);
    const src = state.sourcesCache.get(item.source_id);
    const srcFilename = src ? src.filename : 'Unknown Evidence Source';
    const srcFormat = src ? src.file_format : (item.source_type || 'RAW');
    const srcHash = src ? src.sha256_hash : 'Not recorded';
    const srcSize = src ? formatBytes(src.file_size_bytes) : '—';
    const offsetBadge = formatOffsetBadge(item.source_id, item.raw_record_offset);

    titleEl.textContent = `Evidence Record: ${item.event_type}`;

    const rawAttributes = item.attributes || {};
    const rawJsonStr = JSON.stringify(rawAttributes, null, 2);

    let dataQualityBanner = '';
    if (rawAttributes._data_quality_warning) {
      dataQualityBanner = `
        <div class="alert alert-warning" style="margin-bottom: 16px; border-left: 4px solid #f59e0b; background: rgba(245, 158, 11, 0.1); padding: 12px; border-radius: 4px;">
          <div style="font-weight: 600; color: #f59e0b; margin-bottom: 4px;">Data Quality Notice — Deserialization Fallback</div>
          <div style="font-size: 12px;">This record was loaded via defensive recovery to preserve raw database attributes without silent truncation.</div>
          <div class="font-mono text-sm" style="margin-top: 4px; color: #94a3b8;">${escapeHtml(rawAttributes._data_quality_warning.error_detail || '')}</div>
        </div>
      `;
    } else if (rawAttributes.hash_metadata && !rawAttributes.hash_metadata.is_valid && rawAttributes.hash_metadata.status !== 'MISSING') {
      dataQualityBanner = `
        <div class="alert alert-warning" style="margin-bottom: 16px; border-left: 4px solid #f59e0b; background: rgba(245, 158, 11, 0.1); padding: 12px; border-radius: 4px;">
          <div style="font-weight: 600; color: #f59e0b; margin-bottom: 4px;">Non-Standard Hash Notice — ${escapeHtml(rawAttributes.hash_metadata.status)}</div>
          <div style="font-size: 12px;">Supplied hash does not conform to standard verified cryptographic lengths. Raw string is preserved in full for forensic traceability.</div>
          <div class="font-mono text-sm" style="margin-top: 4px; color: #94a3b8;">${escapeHtml(rawAttributes.hash_metadata.error || '')}</div>
        </div>
      `;
    }

    let hashBadgeHtml = '';
    if (rawAttributes.hash_metadata) {
      const hm = rawAttributes.hash_metadata;
      if (hm.status && hm.status !== 'VALID' && hm.status !== 'MISSING') {
        hashBadgeHtml = ` <span class="badge badge-warning text-xs" style="color: #f59e0b;">${escapeHtml(hm.status)}</span>`;
      } else if (hm.verification_status === 'UNVERIFIED') {
        hashBadgeHtml = ` <span class="badge badge-mono text-xs" title="Log-extracted claimed hash; not independently byte-verified against file on disk">CLAIMED (UNVERIFIED)</span>`;
      }
    }

    evContent.innerHTML = `
      <div class="proof-container">
        ${dataQualityBanner}
        <!-- Provenance Section -->
        <div class="proof-section">
          <div class="proof-section-header">
            <span class="proof-section-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              Evidence Integrity &amp; Provenance Traceability
            </span>
          </div>
          <div class="proof-grid">
            <div class="proof-item">
              <span class="proof-item-label">Investigation Container</span>
              <span class="proof-item-value">${escapeHtml(state.summary?.investigation?.case_number || 'ACTIVE_CASE')} (${escapeHtml(item.investigation_id)})</span>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">Source File</span>
              <span class="proof-item-value"><strong>${escapeHtml(srcFilename)}</strong> (${escapeHtml(srcFormat)})</span>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">File SHA-256 Integrity Hash</span>
              <span class="proof-item-value font-mono text-sm" style="word-break: break-all;">${escapeHtml(srcHash)}</span>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">Source Record Offset</span>
              <div class="proof-item-value">${offsetBadge}</div>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">File Size</span>
              <span class="proof-item-value">${escapeHtml(srcSize)}</span>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">Normalized At</span>
              <span class="proof-item-value text-sm">${new Date(item.normalized_at || item.created_at || Date.now()).toLocaleString()}</span>
            </div>
          </div>
        </div>

        <!-- CES Normalized Schema Fields -->
        <div class="proof-section">
          <div class="proof-section-header">
            <span class="proof-section-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="9" x2="15" y2="9"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="11" y2="17"/></svg>
              Common Evidence Schema (CES) Fields
            </span>
          </div>
          <div class="ces-fields-container">
            <div class="ces-card">
              <span class="ces-card-label">Event Timestamp</span>
              <span class="ces-card-value font-mono">${new Date(item.timestamp).toLocaleString()}</span>
            </div>
            <div class="ces-card">
              <span class="ces-card-label">Event Type</span>
              <span class="ces-card-value"><span class="badge badge-mono">${escapeHtml(item.event_type)}</span></span>
            </div>
            <div class="ces-card">
              <span class="ces-card-label">Action &amp; Status</span>
              <span class="ces-card-value">${escapeHtml(item.action || '—')} / ${escapeHtml(item.status || '—')}</span>
            </div>
            <div class="ces-card">
              <span class="ces-card-label">User ID &amp; Session</span>
              <span class="ces-card-value">${escapeHtml(item.user_id || '—')} ${item.session_id ? `(${escapeHtml(item.session_id)})` : ''}</span>
            </div>
            <div class="ces-card">
              <span class="ces-card-label">Device ID</span>
              <span class="ces-card-value">${escapeHtml(item.device_id || '—')}</span>
            </div>
            <div class="ces-card">
              <span class="ces-card-label">Process (PID / Name)</span>
              <span class="ces-card-value">${item.process_id ? `[${item.process_id}] ` : ''}${escapeHtml(item.process_name || '—')}${item.parent_process_name ? ` (parent: ${escapeHtml(item.parent_process_name)})` : ''}</span>
            </div>
            <div class="ces-card">
              <span class="ces-card-label">Network (IP / Port / Protocol)</span>
              <span class="ces-card-value">${escapeHtml(item.ip_address || '—')}${item.port ? `:${item.port}` : ''} ${item.protocol ? `(${escapeHtml(item.protocol)})` : ''}</span>
            </div>
            <div class="ces-card">
              <span class="ces-card-label">File Path &amp; Hash</span>
              <span class="ces-card-value">${escapeHtml(item.file_path || '—')}${item.file_hash ? `<br><span class="font-mono text-sm">${escapeHtml(item.file_hash)}</span>${hashBadgeHtml}` : ''}</span>
            </div>
          </div>
        </div>

        <!-- Raw Source Record Attributes -->
        <div class="proof-section">
          <div class="proof-section-header">
            <span class="proof-section-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
              Raw Source Record Attributes (_raw_fields)
            </span>
          </div>
          <div class="raw-json-viewer">
            <button class="btn btn-secondary btn-sm btn-copy-json" onclick="copyRawJson(this)">Copy JSON</button>
            <pre id="raw-json-pre">${escapeHtml(rawJsonStr)}</pre>
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    evContent.innerHTML = `<div class="alert alert-danger">Error retrieving evidence details: ${escapeHtml(err.message)}</div>`;
  }
};

window.viewFindingProofModal = async function(findingId) {
  const titleEl = document.getElementById('modal-detail-title');
  const tierBadge = document.getElementById('modal-detail-tier-badge');
  const explainPanel = document.getElementById('modal-explainability-panel');
  const provPanel = document.getElementById('modal-provenance-panel');
  const genericPanel = document.getElementById('modal-generic-panel');
  const proofPanel = document.getElementById('modal-finding-proof-panel');
  const evDetailPanel = document.getElementById('modal-evidence-detail-panel');
  const proofContent = document.getElementById('modal-finding-proof-content');

  // Reset panels
  if (explainPanel) explainPanel.style.display = 'none';
  if (provPanel) provPanel.style.display = 'none';
  if (genericPanel) genericPanel.style.display = 'none';
  if (evDetailPanel) evDetailPanel.style.display = 'none';
  if (tierBadge) tierBadge.style.display = 'none';

  titleEl.textContent = 'Finding Proof & Traceability';
  if (proofPanel) proofPanel.style.display = 'block';
  if (proofContent) proofContent.innerHTML = '<div class="text-center text-muted" style="padding: 24px;">Resolving finding proof and evidence chain...</div>';

  if (window.openModal) window.openModal('modal-detail');

  try {
    const invId = state.activeInvestigationId;
    const finding = await apiRequest(`/detection/findings/${findingId}${invId ? `?investigation_id=${encodeURIComponent(invId)}` : ''}`);
    titleEl.textContent = `Finding Proof: ${finding.rule_id || formatEnum(finding.finding_type)}`;

    const evidenceIds = finding.evidence_ids || [];
    const evIdSet = new Set(evidenceIds.map(String));

    // Parallel fetch: Supporting Evidence, Priority Results, Correlations & Activities
    let evError = null;
    let prioError = null;
    let corrError = null;
    let actError = null;

    const fetchEvidencePromise = (evidenceIds.length > 0)
      ? apiRequest(`/evidence?investigation_id=${invId}&ids=${evidenceIds.join(',')}&limit=100`)
          .catch(err => {
            evError = err.message || 'Failed to retrieve supporting evidence records';
            return { items: [], total: 0 };
          })
      : Promise.resolve({ items: [], total: 0 });

    const fetchPrioPromise = apiRequest(`/prioritization/results?investigation_id=${invId}&limit=100`)
      .catch(err => {
        prioError = err.message || 'Failed to retrieve prioritization results';
        return { items: [] };
      });

    const fetchCorrelationsPromise = apiRequest(`/correlation/relationships?investigation_id=${invId}&limit=100`)
      .catch(err => {
        corrError = err.message || 'Failed to retrieve correlation relationships';
        return { items: [] };
      });

    const fetchActivitiesPromise = apiRequest(`/activities?investigation_id=${invId}&limit=100`)
      .catch(err => {
        actError = err.message || 'Failed to retrieve clustered activities';
        return { items: [] };
      });

    const [evRes, prioRes, corrRes, actRes] = await Promise.all([
      fetchEvidencePromise,
      fetchPrioPromise,
      fetchCorrelationsPromise,
      fetchActivitiesPromise,
    ]);

    // Check for unresolved evidence references
    const resolvedEvItems = evRes.items || [];
    const resolvedMap = new Map(resolvedEvItems.map(it => [String(it.id), it]));
    const missingEvidenceIds = evidenceIds.filter(id => !resolvedMap.has(String(id)));

    // Filter correlations touching this finding's supporting evidence
    const relatedCorrelations = (corrRes.items || []).filter(rel =>
      evIdSet.has(String(rel.source_evidence_id)) || evIdSet.has(String(rel.target_evidence_id))
    );

    // Filter activities linking this finding or its evidence
    const relatedActivities = (actRes.items || []).filter(act => {
      const hasFinding = Array.isArray(act.finding_ids) && act.finding_ids.map(String).includes(String(finding.id));
      const hasEvidence = Array.isArray(act.evidence_ids) && act.evidence_ids.some(eid => evIdSet.has(String(eid)));
      return hasFinding || hasEvidence;
    });

    // Check for prioritization on supporting evidence artifacts or linked activities
    const actIdSet = new Set(relatedActivities.map(a => String(a.id)));
    const matchingPriorities = (prioRes.items || []).filter(r =>
      (r.target_type === 'ARTIFACT' && evIdSet.has(String(r.target_id))) ||
      (r.target_type === 'ACTIVITY' && actIdSet.has(String(r.target_id)))
    );

    // Render HTML: Supporting Evidence
    let supportingEvidenceHtml = '';
    if (evError) {
      supportingEvidenceHtml = `<div class="alert alert-danger" style="margin-bottom: 10px;">⚠️ API Error: Failed to retrieve supporting evidence: ${escapeHtml(evError)}</div>`;
    } else if (evidenceIds.length === 0) {
      supportingEvidenceHtml = '<div class="alert alert-info">No supporting evidence associations recorded for this finding.</div>';
    } else {
      let missingWarningHtml = '';
      if (missingEvidenceIds.length > 0) {
        missingWarningHtml = `
          <div class="alert alert-warning" style="margin-bottom: 10px;">
            ⚠️ Notice: ${missingEvidenceIds.length} referenced evidence record(s) could not be resolved from storage: ${escapeHtml(missingEvidenceIds.join(', '))}
          </div>
        `;
      }

      let evCardsHtml = '';
      resolvedEvItems.forEach(ev => {
        const src = state.sourcesCache.get(ev.source_id);
        const srcFilename = src ? src.filename : 'Evidence Source';
        const offsetBadge = formatOffsetBadge(ev.source_id, ev.raw_record_offset);

        evCardsHtml += `
          <div class="supporting-evidence-card">
            <div class="supporting-evidence-meta">
              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <span class="badge badge-mono">${escapeHtml(ev.event_type)}</span>
                <span class="font-mono text-sm">${new Date(ev.timestamp).toLocaleString()}</span>
                <strong>${escapeHtml(srcFilename)}</strong>
                ${offsetBadge}
              </div>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                ${ev.user_id ? `<span>User: <strong>${escapeHtml(ev.user_id)}</strong> &nbsp;</span>` : ''}
                ${ev.device_id ? `<span>Device: ${escapeHtml(ev.device_id)} &nbsp;</span>` : ''}
                ${ev.process_name ? `<span>Process: <code class="font-mono">${escapeHtml(ev.process_name)}</code> &nbsp;</span>` : ''}
                ${ev.ip_address ? `<span>IP: <code class="font-mono">${escapeHtml(ev.ip_address)}</code> &nbsp;</span>` : ''}
                ${ev.action ? `<span>Action: ${escapeHtml(ev.action)} &nbsp;</span>` : ''}
                ${ev.status ? `<span class="badge badge-mono">${escapeHtml(ev.status)}</span>` : ''}
              </div>
            </div>
            <div>
              <button class="btn btn-secondary btn-sm" onclick="jumpToEvidenceRecord('${escapeHtml(ev.source_id)}', '${escapeHtml(ev.id)}')" title="Navigate directly to this event in the Evidence Explorer">
                View in Explorer &rarr;
              </button>
            </div>
          </div>
        `;
      });

      supportingEvidenceHtml = missingWarningHtml + evCardsHtml;
    }

    // Render HTML: Observed Evidence Associations & Activities
    let associationsHtml = '';
    if (corrError) {
      associationsHtml = `<div class="alert alert-danger" style="font-size: 11px; padding: 6px 10px; margin-bottom: 8px;">⚠️ API Error: Failed to retrieve correlation relationships: ${escapeHtml(corrError)}</div>`;
    } else if (relatedCorrelations.length === 0) {
      associationsHtml = '<div class="text-sm text-muted">No observed correlation relationships connecting this finding\'s supporting evidence.</div>';
    } else {
      associationsHtml = `
        <div class="text-sm text-muted" style="margin-bottom: 8px;">
          Multi-dimensional relationships observed between supporting evidence records. Represents observed statistical and structural associations (e.g. temporal proximity, shared identity pivots), not validated causation.
        </div>
        <div style="display: flex; flex-direction: column; gap: 4px;">
          ${relatedCorrelations.map(rel => `
            <div style="padding: 6px 10px; background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: 4px; font-size: 11px; display: flex; justify-content: space-between; align-items: center;">
              <span><span class="badge badge-mono">${escapeHtml(rel.relationship_type)}</span> (weight: ${rel.weight.toFixed(2)})</span>
              <span class="font-mono text-muted text-sm">${escapeHtml(compactId(rel.source_evidence_id))} &harr; ${escapeHtml(compactId(rel.target_evidence_id))}</span>
            </div>
          `).join('')}
        </div>
      `;
    }

    let activitiesHtml = '';
    if (actError) {
      activitiesHtml = `<div class="alert alert-danger" style="font-size: 11px; padding: 6px 10px; margin-bottom: 8px;">⚠️ API Error: Failed to retrieve clustered activities: ${escapeHtml(actError)}</div>`;
    } else if (relatedActivities.length === 0) {
      activitiesHtml = '<div class="text-sm text-muted">No clustered activity threads incorporate this finding or its supporting evidence.</div>';
    } else {
      activitiesHtml = `
        <div style="display: flex; flex-direction: column; gap: 4px;">
          ${relatedActivities.map(act => `
            <div style="padding: 6px 10px; background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: 4px; font-size: 11px; display: flex; justify-content: space-between; align-items: center;">
              <span><strong>${escapeHtml(act.title)}</strong> &nbsp;<span class="badge badge-mono">${formatEnum(act.activity_type)}</span></span>
              <span class="badge badge-open">${escapeHtml(act.status)}</span>
            </div>
          `).join('')}
        </div>
      `;
    }

    // Render HTML: Explainable Prioritization Breakdown
    let prioHtml = '';
    if (prioError) {
      prioHtml = `<div class="alert alert-danger" style="font-size: 11px; padding: 6px 10px;">⚠️ API Error: Failed to retrieve prioritization triage: ${escapeHtml(prioError)}</div>`;
    } else if (matchingPriorities.length > 0) {
      prioHtml = matchingPriorities.map(prioResult => {
        const breakdown = prioResult.factor_breakdown || {};
        const factors = breakdown.factors || [];
        return `
          <div style="margin-bottom: 12px; padding: 10px; background: var(--bg-secondary); border-radius: 6px; border: 1px solid var(--border-subtle);">
            <div style="display: flex; gap: 14px; align-items: center; margin-bottom: 8px;">
              <div class="score-badge-container">
                <span class="score-title">${prioResult.target_type === 'ARTIFACT' ? 'Evidence Priority' : 'Activity Priority'}</span>
                <div class="score-display">
                  <span class="score-num font-mono">${prioResult.priority_score.toFixed(1)}</span>
                  <span class="score-max">/ 100</span>
                </div>
              </div>
              <div style="flex: 1;">
                <span class="badge ${getTierBadgeClass(prioResult.priority_tier)}" style="margin-bottom: 4px;">${prioResult.priority_tier}</span>
                <p class="text-sm" style="color: var(--text-secondary); margin: 0;">${escapeHtml(prioResult.explanation_text || '')}</p>
              </div>
            </div>
            ${factors.length > 0 ? `
              <div class="factor-grid">
                ${factors.map(f => `
                  <div class="factor-card">
                    <strong class="factor-name" style="text-transform: none; color: var(--text-primary); font-size: 11px; font-weight: 600; display: block; margin-bottom: 2px;">${escapeHtml(f.name.replace(/_/g, ' '))}</strong>
                    <span class="factor-val" style="color: var(--prio-high); font-size: 12px; font-weight: 600; display: block;">Contribution: ${(f.contribution >= 0 ? '+' : '') + f.contribution.toFixed(2)}</span>
                    <span class="text-muted" style="font-size: 11px; display: block;">Weight: ${(f.weight * 100).toFixed(0)}%</span>
                    <span class="text-muted" style="font-size: 11px; display: block;">Value: ${typeof f.normalized_value === 'number' ? f.normalized_value.toFixed(4) : f.normalized_value}</span>
                  </div>
                `).join('')}
              </div>
            ` : ''}
          </div>
        `;
      }).join('');
    } else {
      prioHtml = '<div class="text-sm text-muted">Prioritization score unavailable: neither the supporting evidence artifacts nor linked activities have been prioritized yet. (Run Stage 6 for Evidence Triage or Stage 7 for Activity Triage).</div>';
    }

    proofContent.innerHTML = `
      <div class="proof-container">
        <!-- Finding Overview -->
        <div class="proof-section">
          <div class="proof-section-header">
            <span class="proof-section-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              Finding Overview &amp; Detection Metadata
            </span>
          </div>
          <div class="proof-grid">
            <div class="proof-item">
              <span class="proof-item-label">Finding Type</span>
              <span class="proof-item-value"><span class="badge badge-mono">${formatEnum(finding.finding_type)}</span></span>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">Detection Severity</span>
              <span class="proof-item-value font-mono"><strong>${finding.severity.toFixed(2)}</strong> / 1.00</span>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">Rule / Detection ID</span>
              <span class="proof-item-value font-mono"><strong>${escapeHtml(finding.rule_id || 'None')}</strong></span>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">MITRE ATT&amp;CK Mapping</span>
              <span class="proof-item-value">${finding.mitre_tactic ? `<span class="badge badge-mono">${escapeHtml(finding.mitre_tactic)} / ${escapeHtml(finding.mitre_technique || '')}</span>` : '<span class="text-muted">None specified</span>'}</span>
            </div>
            <div class="proof-item">
              <span class="proof-item-label">Detection Timestamp</span>
              <span class="proof-item-value text-sm">${new Date(finding.created_at).toLocaleString()}</span>
            </div>
            <div class="proof-item" style="grid-column: 1 / -1;">
              <span class="proof-item-label">Finding Description</span>
              <p class="text-sm" style="color: var(--text-primary); margin-top: 2px;">${escapeHtml(finding.description || '')}</p>
            </div>
          </div>
        </div>

        <!-- Supporting Evidence -->
        <div class="proof-section">
          <div class="proof-section-header">
            <span class="proof-section-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              Supporting Evidence Traceability (${evError ? 'Query Failed' : evidenceIds.length})
            </span>
          </div>
          <div>${supportingEvidenceHtml}</div>
        </div>

        <!-- Discovered Correlations & Activities -->
        <div class="proof-section">
          <div class="proof-section-header">
            <span class="proof-section-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
              Observed Evidence Associations (${corrError ? 'Query Failed' : relatedCorrelations.length})
            </span>
          </div>
          <div>${associationsHtml}</div>

          <div style="margin-top: 14px; padding-top: 10px; border-top: 1px solid var(--border-subtle);">
            <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 6px;">
              Clustered Activity Memberships (${actError ? 'Query Failed' : relatedActivities.length})
            </div>
            <div>${activitiesHtml}</div>
          </div>
        </div>

        <!-- Explainable Prioritization Breakdown -->
        <div class="proof-section">
          <div class="proof-section-header">
            <span class="proof-section-title">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
              Operational Prioritization Triage (Supporting Evidence &amp; Activities)
            </span>
          </div>
          <div>${prioHtml}</div>
        </div>
      </div>
    `;
  } catch (err) {
    proofContent.innerHTML = `<div class="alert alert-danger">Error retrieving finding proof: ${escapeHtml(err.message)}</div>`;
  }
};

window.jumpToEvidenceRecord = function(sourceId, evidenceId) {
  const modal = document.getElementById('modal-detail');
  if (modal) window.closeModal(modal);

  // Switch to Evidence tab
  const tabBtn = document.getElementById('nav-tab-evidence');
  if (tabBtn) tabBtn.click();

  const srcFilter = document.getElementById('filter-evidence-source');
  if (srcFilter) srcFilter.value = sourceId || '';
  state.evidencePagination.source_id = sourceId || '';
  state.evidencePagination.offset = 0;

  // Immediately select and inspect the target evidence record
  if (evidenceId) {
    selectEvidenceRecord(evidenceId);
  }

  loadEvidenceRecords().then(() => {
    if (evidenceId) {
      scrollSelectedRowIntoView(evidenceId);
    }
  });

  const panel = document.getElementById('evidence-records-panel');
  if (panel) {
    setTimeout(() => {
      panel.scrollIntoView({ behavior: 'smooth' });
    }, 150);
  }
};

window.verifySourceIntegrity = async function(sourceId) {
  const badgeEl = document.getElementById(`verify-badge-${sourceId}`);
  const btnEl = document.getElementById(`btn-verify-source-${sourceId}`);
  if (btnEl) btnEl.disabled = true;
  if (badgeEl) {
    badgeEl.innerHTML = '<span class="text-xs text-muted">Verifying…</span>';
  }

  try {
    const invParam = state.activeInvestigationId ? `?investigation_id=${encodeURIComponent(state.activeInvestigationId)}` : '';
    const res = await apiRequest(`/evidence/sources/${encodeURIComponent(sourceId)}/verify-integrity${invParam}`, {
      method: 'POST'
    });

    state.sourcesIntegrityCache = state.sourcesIntegrityCache || new Map();
    state.sourcesIntegrityCache.set(sourceId, res);

    let badgeClass = 'badge-mono';
    let icon = '●';
    if (res.status === 'VERIFIED') {
      badgeClass = 'badge-open';
      icon = '✓';
    } else if (res.status === 'INTEGRITY_MISMATCH') {
      badgeClass = 'alert-danger';
      icon = '⚠';
    } else {
      badgeClass = 'alert-warning';
      icon = '—';
    }

    if (badgeEl) {
      badgeEl.innerHTML = `<span class="badge ${badgeClass} text-xs" style="cursor: pointer;" title="Click to view cryptographic verification details" onclick="viewSourceIntegrityModal('${escapeHtml(sourceId)}')">${icon} ${escapeHtml(res.status)}</span>`;
    }

    showAlert(`[${res.status}] ${res.message}`, res.status === 'VERIFIED' ? 'success' : (res.status === 'INTEGRITY_MISMATCH' ? 'danger' : 'warning'), 5000);
  } catch (err) {
    if (badgeEl) {
      badgeEl.innerHTML = `<span class="badge alert-danger text-xs" title="${escapeHtml(err.message)}">FAILED</span>`;
    }
    showAlert(`Integrity check failed: ${err.message}`, 'danger');
  } finally {
    if (btnEl) btnEl.disabled = false;
  }
};

window.viewSourceIntegrityModal = function(sourceId) {
  const data = state.sourcesIntegrityCache?.get(sourceId);
  if (!data) return;
  const titleEl = document.getElementById('modal-detail-title');
  const genericContent = document.getElementById('modal-generic-content');
  const genericPanel = document.getElementById('modal-generic-panel');
  const explainPanel = document.getElementById('modal-explainability-panel');
  const provPanel = document.getElementById('modal-provenance-panel');
  const proofPanel = document.getElementById('modal-finding-proof-panel');
  const evDetailPanel = document.getElementById('modal-evidence-detail-panel');
  const tierBadge = document.getElementById('modal-detail-tier-badge');

  if (explainPanel) explainPanel.style.display = 'none';
  if (provPanel) provPanel.style.display = 'none';
  if (proofPanel) proofPanel.style.display = 'none';
  if (evDetailPanel) evDetailPanel.style.display = 'none';
  if (tierBadge) tierBadge.style.display = 'none';

  if (titleEl) titleEl.textContent = `Evidence Source Integrity: ${data.filename}`;
  if (genericPanel) genericPanel.style.display = 'block';

  let statusBadgeClass = 'badge-mono';
  if (data.status === 'VERIFIED') statusBadgeClass = 'badge-open';
  else if (data.status === 'INTEGRITY_MISMATCH') statusBadgeClass = 'alert-danger';
  else statusBadgeClass = 'alert-warning';

  if (genericContent) {
    genericContent.innerHTML = `
      <div style="padding: 10px; display: flex; flex-direction: column; gap: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); padding-bottom: 8px;">
          <span style="font-size: 13px; font-weight: 600;">Verification State</span>
          <span class="badge ${statusBadgeClass}">${escapeHtml(data.status)}</span>
        </div>
        <div style="display: grid; grid-template-columns: 140px 1fr; gap: 8px; font-size: 12px;">
          <span class="text-muted">Filename:</span>
          <strong>${escapeHtml(data.filename)}</strong>

          <span class="text-muted">Recorded Ingestion SHA-256:</span>
          <code class="font-mono text-sm" style="word-break: break-all;">${escapeHtml(data.recorded_sha256)}</code>

          <span class="text-muted">Computed Stored Artifact SHA-256:</span>
          <code class="font-mono text-sm" style="word-break: break-all;">${escapeHtml(data.computed_sha256 || 'Unavailable')}</code>

          <span class="text-muted">Verified At:</span>
          <span>${new Date(data.verified_at).toLocaleString()}</span>
        </div>
        <div class="alert ${data.status === 'VERIFIED' ? 'alert-info' : 'alert-warning'}" style="margin: 0; font-size: 11px;">
          ${escapeHtml(data.message)}
        </div>
        <div style="font-size: 10px; color: var(--text-muted); line-height: 1.4; border-top: 1px solid var(--border-subtle); padding-top: 8px;">
          <strong>Forensic Notice:</strong> ${escapeHtml(data.disclaimer)}
        </div>
      </div>
    `;
  }

  if (window.openModal) window.openModal('modal-detail');
};

window.copyRawJson = function(btn) {
  const pre = document.getElementById('raw-json-pre');
  if (!pre) return;
  const text = pre.textContent;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = orig; }, 2000);
    }).catch(() => {
      fallbackCopy(text, btn);
    });
  } else {
    fallbackCopy(text, btn);
  }
};

window.copyDigest = function(hash, btn) {
  if (!hash) return;
  const doFeedback = () => {
    if (!btn) return;
    const origHtml = btn.innerHTML;
    btn.innerHTML = '<span style="color: var(--prio-success); font-size: 11px; font-weight: 700;">✓</span>';
    setTimeout(() => {
      btn.innerHTML = origHtml;
    }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(hash).then(doFeedback).catch(() => fallbackCopy(hash, btn));
  } else {
    fallbackCopy(hash, btn);
  }
};

function fallbackCopy(text, btn) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  document.body.appendChild(textarea);
  textarea.select();
  try {
    document.execCommand('copy');
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = orig; }, 2000);
  } catch {}
  document.body.removeChild(textarea);
}

// Start application when DOM is ready
document.addEventListener('DOMContentLoaded', initApp);
