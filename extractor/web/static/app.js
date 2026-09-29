/**
 * dynamicState — Memory Snapshot & Runtime State Explorer Frontend
 * Single-Page Application communicating via AgentRuntime REST API.
 */

(function () {
  'use strict';

  // Global Application State
  const state = {
    runtime: null,
    states: [],
    selectedStateId: null,
    memorySummary: null,
    objects: [],
    selectedObjectId: null,
    storageFilter: 'all',
    searchQuery: '',
    candidates: [],
    stateGraphData: { nodes: [], edges: [] },
    activeTab: 'tab-memory-snapshot',
    activeSubtab: 'subtab-dag',
    jsonViewerCache: {},
  };

  // DOM Elements Cache
  const el = {
    // Header & Global Status Bar
    txtRuntimeStatus: document.getElementById('txt-runtime-status'),
    pillRuntimeStatus: document.getElementById('pill-runtime-status'),
    badgeObsMode: document.getElementById('badge-obs-mode'),
    tagPid: document.getElementById('tag-pid'),
    tagArch: document.getElementById('tag-arch'),
    tagEndian: document.getElementById('tag-endian'),
    tagElf: document.getElementById('tag-elf'),
    btnRefresh: document.getElementById('btn-refresh'),
    btnObserveDialog: document.getElementById('btn-observe-dialog'),
    lowImpactBanner: document.getElementById('low-impact-banner'),
    toastContainer: document.getElementById('toast-container'),

    // Main Nav Tabs (6 Tabs)
    navTabs: document.querySelectorAll('.nav-tab'),
    tabPanes: document.querySelectorAll('.tab-pane'),

    // Tab 1: Memory Snapshot Explorer
    msBadgeMode: document.getElementById('ms-badge-mode'),
    msBadgeStatus: document.getElementById('ms-badge-status'),
    msBadgeConsistency: document.getElementById('ms-badge-consistency'),
    msTargetTitle: document.getElementById('ms-target-title'),
    msTargetSubtitle: document.getElementById('ms-target-subtitle'),
    selectSnapshotId: document.getElementById('select-snapshot-id'),

    statStatus: document.getElementById('stat-status'),
    statStatusSub: document.getElementById('stat-status-sub'),
    statCapturedMb: document.getElementById('stat-captured-mb'),
    statCapturedBytes: document.getElementById('stat-captured-bytes'),
    statDuration: document.getElementById('stat-duration'),
    statConsistency: document.getElementById('stat-consistency'),
    statRegionCount: document.getElementById('stat-region-count'),
    statArch: document.getElementById('stat-arch'),
    statPointerEndian: document.getElementById('stat-pointer-endian'),

    breakdownBar: document.getElementById('breakdown-bar'),
    bdHeapVal: document.getElementById('bd-heap-val'),
    bdHeapPct: document.getElementById('bd-heap-pct'),
    bdStackVal: document.getElementById('bd-stack-val'),
    bdStackPct: document.getElementById('bd-stack-pct'),
    bdGlobalVal: document.getElementById('bd-global-val'),
    bdGlobalPct: document.getElementById('bd-global-pct'),
    bdExecVal: document.getElementById('bd-exec-val'),
    bdExecPct: document.getElementById('bd-exec-pct'),
    bdShlibVal: document.getElementById('bd-shlib-val'),
    bdShlibPct: document.getElementById('bd-shlib-pct'),
    bdOtherVal: document.getElementById('bd-other-val'),
    bdOtherPct: document.getElementById('bd-other-pct'),
    bdTotalVal: document.getElementById('bd-total-val'),

    semTotalObjs: document.getElementById('sem-total-objs'),
    semHeapObjs: document.getElementById('sem-heap-objs'),
    semGlobalObjs: document.getElementById('sem-global-objs'),
    semStackObjs: document.getElementById('sem-stack-objs'),
    semRefsCount: document.getElementById('sem-refs-count'),
    semanticTreePreview: document.getElementById('semantic-tree-preview'),
    btnGotoObjects: document.getElementById('btn-goto-objects'),

    qualCompleteness: document.getElementById('qual-completeness'),
    qualCompletenessText: document.getElementById('qual-completeness-text'),
    qualMappingRace: document.getElementById('qual-mapping-race'),
    qualPartials: document.getElementById('qual-partials'),
    qualUnavailFields: document.getElementById('qual-unavail-fields'),
    qualDebugStatus: document.getElementById('qual-debug-status'),
    qualDebugPath: document.getElementById('qual-debug-path'),
    qualBuildId: document.getElementById('qual-build-id'),
    qualModuleCount: document.getElementById('qual-module-count'),

    // Tab 2: Runtime Objects Directory & Inspector
    inputSearchObjects: document.getElementById('input-search-objects'),
    storageFilterPills: document.querySelectorAll('.storage-filter-pills .filter-pill'),
    badgeMemObjectsCount: document.getElementById('badge-mem-objects-count'),
    memGraphTruncatedWarning: document.getElementById('mem-graph-truncated-warning'),
    txtMemTruncatedCount: document.getElementById('txt-mem-truncated-count'),
    listMemoryObjects: document.getElementById('list-memory-objects'),

    memObjTitle: document.getElementById('mem-obj-title'),
    memObjSubtitle: document.getElementById('mem-obj-subtitle'),
    memObjTypeBadge: document.getElementById('mem-obj-type-badge'),
    memObjStorageBadge: document.getElementById('mem-obj-storage-badge'),
    btnJumpTopology: document.getElementById('btn-jump-topology'),
    btnViewObjJson: document.getElementById('btn-view-obj-json'),
    tableSemanticFields: document.querySelector('#table-semantic-fields tbody'),

    memTechAddr: document.getElementById('mem-tech-addr'),
    memTechStorage: document.getElementById('mem-tech-storage'),
    memTechType: document.getElementById('mem-tech-type'),
    memTechId: document.getElementById('mem-tech-id'),

    // Tab 3: Topology SVG Graph
    svgTopologyGraph: document.getElementById('topology-graph-svg'),
    btnResetTopology: document.getElementById('btn-reset-topology'),

    // Tab 4: History / State Diff
    subnavPills: document.querySelectorAll('.subnav-pill'),
    subtabContents: document.querySelectorAll('.subtab-content'),

    badgeStatesCount: document.getElementById('badge-states-count'),
    inputSearchStates: document.getElementById('input-search-states'),
    listStates: document.getElementById('list-states'),
    svgStateGraph: document.getElementById('state-graph-svg'),
    btnResetGraph: document.getElementById('btn-reset-graph'),
    cardStateDetail: document.getElementById('card-state-detail'),
    detailStateId: document.getElementById('detail-state-id'),
    detailStateBadge: document.getElementById('detail-state-badge'),
    detailStateHash: document.getElementById('detail-state-hash'),
    detailParentState: document.getElementById('detail-parent-state'),
    detailCreatedAt: document.getElementById('detail-created-at'),
    detailObservations: document.getElementById('detail-observations'),
    btnViewStateJson: document.getElementById('btn-view-state-json'),
    btnInspectStateObjects: document.getElementById('btn-inspect-state-objects'),
    btnStateDiffParent: document.getElementById('btn-state-diff-parent'),
    btnStateMutate: document.getElementById('btn-state-mutate'),

    inputDiffA: document.getElementById('input-diff-a'),
    inputDiffB: document.getElementById('input-diff-b'),
    btnRunDiff: document.getElementById('btn-run-diff'),
    diffResults: document.getElementById('diff-results'),
    diffValChanges: document.getElementById('diff-val-changes'),
    diffRefChanges: document.getElementById('diff-ref-changes'),
    diffObjCreated: document.getElementById('diff-obj-created'),
    diffObjRemoved: document.getElementById('diff-obj-removed'),
    tableDiffChanges: document.querySelector('#table-diff-changes tbody'),

    // Tab 5: Advanced Exploration (Mutations & Autonomous Loop)
    inputFilterCandField: document.getElementById('input-filter-cand-field'),
    tableCandidates: document.querySelector('#table-candidates tbody'),
    cardExecutionResult: document.getElementById('card-execution-result'),
    execTransId: document.getElementById('exec-trans-id'),
    execStatusBadge: document.getElementById('exec-status-badge'),
    execStatusText: document.getElementById('exec-status-text'),
    execChildState: document.getElementById('exec-child-state'),
    execChildHash: document.getElementById('exec-child-hash'),
    listExecChangedFields: document.getElementById('list-exec-changed-fields'),
    btnViewTransJson: document.getElementById('btn-view-trans-json'),

    formExplore: document.getElementById('form-explore'),
    expMaxSteps: document.getElementById('exp-max-steps'),
    expTimeout: document.getElementById('exp-timeout'),
    expMaxStates: document.getElementById('exp-max-states'),
    btnStartExplore: document.getElementById('btn-start-explore'),
    cardExploreResults: document.getElementById('card-explore-results'),
    expResSteps: document.getElementById('exp-res-steps'),
    expResStates: document.getElementById('exp-res-states'),
    expResTransitions: document.getElementById('exp-res-transitions'),
    expResCrashes: document.getElementById('exp-res-crashes'),
    expResTimeouts: document.getElementById('exp-res-timeouts'),
    exploreIsolationBanner: document.getElementById('explore-isolation-banner'),
    exploreIsolationTitle: document.getElementById('explore-isolation-title'),
    exploreIsolationMsg: document.getElementById('explore-isolation-msg'),
    exploreIsolationAlternatives: document.getElementById('explore-isolation-alternatives'),
    exploreAlternativesList: document.getElementById('explore-alternatives-list'),

    // Tab 5 Checkpoint & Determinism Card
    expCpBackend: document.getElementById('exp-cp-backend'),
    expCpSemantics: document.getElementById('exp-cp-semantics'),
    expCpScope: document.getElementById('exp-cp-scope'),
    expCpDeterminism: document.getElementById('exp-cp-determinism'),
    expCpBranchIsolation: document.getElementById('exp-cp-branch-isolation'),
    btnVerifyDeterminism: document.getElementById('btn-verify-determinism'),
    boxDeterminismResult: document.getElementById('box-determinism-result'),
    detResultTitle: document.getElementById('det-result-title'),
    detResultDetails: document.getElementById('det-result-details'),

    // Tab 6: System & Provenance
    ovStatus: document.getElementById('ov-status'),
    ovPid: document.getElementById('ov-pid'),
    ovThreads: document.getElementById('ov-threads'),
    ovMode: document.getElementById('ov-mode'),
    ovRestoreBackend: document.getElementById('ov-restore-backend'),
    ovCheckpointSemantics: document.getElementById('ov-checkpoint-semantics'),
    ovThreadScope: document.getElementById('ov-thread-scope'),
    ovDeterminismStatus: document.getElementById('ov-determinism-status'),
    ovBranchIsolation: document.getElementById('ov-branch-isolation'),
    ovBinary: document.getElementById('ov-binary'),
    ovDebugImage: document.getElementById('ov-debug-image'),
    ovDebugStatus: document.getElementById('ov-debug-status'),
    ovArch: document.getElementById('ov-arch'),
    ovEndian: document.getElementById('ov-endian'),
    ovElf: document.getElementById('ov-elf'),
    ovBuildId: document.getElementById('ov-build-id'),
    ovModulesCount: document.getElementById('ov-modules-count'),
    ovCheckpoint: document.getElementById('ov-checkpoint'),
    ovStatesCount: document.getElementById('ov-states-count'),
    ovTransCount: document.getElementById('ov-trans-count'),
    ovCandidatesCount: document.getElementById('ov-candidates-count'),
    ovLimits: document.getElementById('ov-limits'),
    tableModules: document.querySelector('#table-modules tbody'),

    // Modals
    modalObserve: document.getElementById('modal-observe'),
    btnCloseObserveModal: document.getElementById('btn-close-observe-modal'),
    btnCancelObserve: document.getElementById('btn-cancel-observe'),
    formObserve: document.getElementById('form-observe'),
    obsPid: document.getElementById('obs-pid'),
    obsDebugImage: document.getElementById('obs-debug-image'),
    obsPolicy: document.getElementById('obs-policy'),

    modalJson: document.getElementById('modal-json'),
    modalJsonTitle: document.getElementById('modal-json-title'),
    modalJsonContent: document.getElementById('modal-json-content'),
    btnCloseJsonModal: document.getElementById('btn-close-json-modal'),
    btnCopyJson: document.getElementById('btn-copy-json'),
  };

  // --------------------------------------------------------------------------
  // API Helpers
  // --------------------------------------------------------------------------

  async function apiGet(endpoint) {
    try {
      const res = await fetch(endpoint);
      return await res.json();
    } catch (err) {
      console.error(`API GET ${endpoint} error:`, err);
      return { success: false, error: { code: 'NETWORK_ERROR', message: String(err) } };
    }
  }

  async function apiPost(endpoint, body = {}) {
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      return await res.json();
    } catch (err) {
      console.error(`API POST ${endpoint} error:`, err);
      return { success: false, error: { code: 'NETWORK_ERROR', message: String(err) } };
    }
  }

  function showToast(message, type = 'info') {
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    const icon = type === 'success' ? '✓' : type === 'error' ? '⚠️' : 'ℹ';
    t.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
    el.toastContainer.appendChild(t);
    setTimeout(() => {
      t.style.opacity = '0';
      setTimeout(() => t.remove(), 250);
    }, 3500);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0.00 MB';
    const mb = bytes / (1024 * 1024);
    if (mb < 0.01) {
      return (bytes / 1024).toFixed(1) + ' KB';
    }
    return mb.toFixed(2) + ' MB';
  }

  function getBaseName(path) {
    if (!path) return 'N/A';
    const parts = path.split('/');
    return parts[parts.length - 1] || path;
  }

  // --------------------------------------------------------------------------
  // Navigation & Subtab Switching
  // --------------------------------------------------------------------------

  function initTabs() {
    el.navTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const targetTab = tab.getAttribute('data-tab');
        switchTab(targetTab);
      });
    });

    el.subnavPills.forEach((pill) => {
      pill.addEventListener('click', () => {
        const targetSubtab = pill.getAttribute('data-subtab');
        switchSubtab(targetSubtab, pill);
      });
    });
  }

  function switchTab(tabId) {
    state.activeTab = tabId;
    el.navTabs.forEach((t) => {
      t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
    });
    el.tabPanes.forEach((p) => {
      p.classList.toggle('active', p.id === tabId);
    });

    if (tabId === 'tab-object-graph') {
      renderObjectTopology();
    } else if (tabId === 'tab-runtime-objects') {
      renderMemoryObjectsList();
    } else if (tabId === 'tab-history-diff') {
      renderStateGraph();
    }
  }

  function switchSubtab(subtabId, triggerPill) {
    state.activeSubtab = subtabId;
    const parentContainer = triggerPill.closest('.tab-pane') || document;
    parentContainer.querySelectorAll('.subnav-pill').forEach((p) => {
      p.classList.toggle('active', p.getAttribute('data-subtab') === subtabId);
    });
    parentContainer.querySelectorAll('.subtab-content').forEach((c) => {
      c.classList.toggle('active', c.id === subtabId);
    });

    if (subtabId === 'subtab-dag') {
      renderStateGraph();
    } else if (subtabId === 'subtab-mutations') {
      loadCandidates();
    }
  }

  // --------------------------------------------------------------------------
  // Runtime Overview & State Loading
  // --------------------------------------------------------------------------

  async function loadRuntimeOverview() {
    const res = await apiGet('/api/runtime');
    if (!res.success) {
      showToast(res.error ? res.error.message : 'Failed to fetch runtime info', 'error');
      return;
    }

    const data = res.data;
    state.runtime = data;
    state.jsonViewerCache['runtime'] = data;

    // Header pills & badges
    const status = data.status || 'DISCONNECTED';
    el.txtRuntimeStatus.textContent = status;
    el.pillRuntimeStatus.className = 'status-pill ' + status.toLowerCase();

    const mode = data.mode || 'CONSISTENT';
    el.badgeObsMode.textContent = mode;
    el.badgeObsMode.className = 'mode-badge' + (mode === 'LOW_IMPACT' ? ' low-impact' : '');

    // Show/hide low-impact banner & branch isolation banner
    const branchIso = data.branch_isolation || {};
    const threadCount = data.threads || 1;
    const isIsoSupported = branchIso.status === 'SUPPORTED';

    if (mode === 'LOW_IMPACT') {
      el.lowImpactBanner.style.display = 'flex';
      if (el.exploreIsolationBanner) el.exploreIsolationBanner.style.display = 'none';
      el.btnStartExplore.disabled = true;
      el.btnStartExplore.title = 'Exploration unsupported in LOW_IMPACT mode';
    } else {
      el.lowImpactBanner.style.display = 'none';

      if (el.exploreIsolationBanner) {
        el.exploreIsolationBanner.style.display = 'block';
        if (!isIsoSupported) {
          el.exploreIsolationBanner.className = 'alert-banner alert-warning';
          if (el.exploreIsolationTitle) el.exploreIsolationTitle.textContent = `Branch Isolation Unavailable (${threadCount} Active Threads)`;
          if (el.exploreIsolationMsg) {
            el.exploreIsolationMsg.textContent = branchIso.reason || 
              `Target process has ${threadCount} threads. Branch isolation is unavailable, preventing independent mutation evaluation from the parent state.`;
          }
          if (el.exploreIsolationAlternatives && el.exploreAlternativesList) {
            el.exploreIsolationAlternatives.style.display = 'block';
            const alts = branchIso.safe_alternatives || ['OBSERVE', 'SNAPSHOT', 'LIST_OBJECTS', 'INSPECT_OBJECT', 'LIST_MUTATION_CANDIDATES'];
            el.exploreAlternativesList.innerHTML = alts.map(a => `<span class="badge badge-info" style="cursor: pointer;" onclick="handleAlternativeAction('${a}')">${a}</span>`).join(' ');
          }
          el.btnStartExplore.disabled = true;
          el.btnStartExplore.title = 'Autonomous exploration disabled: Branch isolation unavailable for multithreaded inferior';
        } else {
          el.exploreIsolationBanner.className = 'alert-banner alert-success';
          const backendName = branchIso.restore_backend || 'RESTART';
          if (el.exploreIsolationTitle) el.exploreIsolationTitle.textContent = `Branch Isolation Active (${backendName} Backend, ${threadCount} Thread${threadCount > 1 ? 's' : ''})`;
          if (el.exploreIsolationMsg) {
            el.exploreIsolationMsg.textContent = `Independent sibling mutation execution is fully verified and supported via ${backendName} restore.`;
          }
          if (el.exploreIsolationAlternatives) el.exploreIsolationAlternatives.style.display = 'none';
          el.btnStartExplore.disabled = false;
          el.btnStartExplore.title = '';
        }
      } else {
        el.btnStartExplore.disabled = false;
        el.btnStartExplore.title = '';
      }
    }

    el.tagPid.textContent = data.pid ? `PID: ${data.pid}` : 'PID: N/A';
    el.tagArch.textContent = `Arch: ${data.architecture || 'UNKNOWN'}`;
    el.tagEndian.textContent = `Endian: ${data.endianness || 'UNKNOWN'}`;
    el.tagElf.textContent = `ELF: ${data.elf_class || 'UNKNOWN'}`;

    // Tab 5: Checkpoint & Determinism Card
    const cpRestore = data.checkpoint_restore || {};
    const backendName = cpRestore.backend || branchIso.restore_backend || (threadCount > 1 ? 'RESTART' : 'GDB_CHECKPOINT');
    const semantics = cpRestore.semantics || branchIso.semantics || (backendName === 'RESTART' ? 'RESTART_TO_OBSERVATION_POINT' : 'MEMORY_CHECKPOINT');
    const scope = cpRestore.scope || branchIso.scope || (threadCount > 1 ? 'MULTITHREAD' : 'SINGLE_THREAD');
    const detStatus = cpRestore.determinism_status || branchIso.determinism_status || 'UNKNOWN';
    const branchStatus = branchIso.status || (isIsoSupported ? 'SUPPORTED' : 'UNAVAILABLE');

    if (el.expCpBackend) el.expCpBackend.textContent = backendName;
    if (el.expCpSemantics) el.expCpSemantics.textContent = semantics;
    if (el.expCpScope) el.expCpScope.textContent = scope;
    if (el.expCpDeterminism) {
      let detClass = 'badge-neutral';
      if (detStatus === 'VERIFIED') detClass = 'badge-success';
      else if (detStatus === 'FAILED' || detStatus === 'NON_DETERMINISTIC') detClass = 'badge-danger';
      el.expCpDeterminism.innerHTML = `<span class="badge ${detClass}">${detStatus}</span>`;
    }
    if (el.expCpBranchIsolation) {
      let isoClass = 'badge-neutral';
      if (branchStatus === 'SUPPORTED') isoClass = 'badge-success';
      else if (branchStatus === 'CONDITIONAL') isoClass = 'badge-warning';
      else if (branchStatus === 'UNAVAILABLE') isoClass = 'badge-danger';
      el.expCpBranchIsolation.innerHTML = `<span class="badge ${isoClass}">${branchStatus}</span>`;
    }

    // Tab 6: System Overview Cards
    el.ovStatus.textContent = status;
    el.ovPid.textContent = data.pid || 'None';
    if (el.ovThreads) el.ovThreads.textContent = threadCount;
    el.ovMode.innerHTML = `<span class="badge ${mode === 'LOW_IMPACT' ? 'badge-warning' : 'badge-info'}">${mode}</span>`;
    if (el.ovRestoreBackend) el.ovRestoreBackend.textContent = backendName;
    if (el.ovCheckpointSemantics) el.ovCheckpointSemantics.textContent = semantics;
    if (el.ovThreadScope) el.ovThreadScope.textContent = scope;
    if (el.ovDeterminismStatus) {
      let detClass = 'badge-neutral';
      if (detStatus === 'VERIFIED') detClass = 'badge-success';
      else if (detStatus === 'FAILED' || detStatus === 'NON_DETERMINISTIC') detClass = 'badge-danger';
      el.ovDeterminismStatus.innerHTML = `<span class="badge ${detClass}">${detStatus}</span>`;
    }
    if (el.ovBranchIsolation) {
      el.ovBranchIsolation.innerHTML = `<span class="badge ${isIsoSupported ? 'badge-success' : 'badge-warning'}">${branchStatus}</span>`;
    }
    el.ovBinary.textContent = data.executable || 'None';
    el.ovDebugImage.textContent = data.debug_image || 'None';
    el.ovDebugStatus.innerHTML = `<span class="badge ${data.debug_image_status === 'VERIFIED' ? 'badge-success' : 'badge-neutral'}">${data.debug_image_status || 'NOT_AVAILABLE'}</span>`;

    el.ovArch.textContent = data.architecture || 'UNKNOWN';
    el.ovEndian.textContent = data.endianness || 'UNKNOWN';
    el.ovElf.textContent = data.elf_class || 'UNKNOWN';
    el.ovBuildId.textContent = data.build_id || 'None';
    el.ovModulesCount.textContent = data.module_count || 0;
    el.ovCheckpoint.textContent = data.current_checkpoint || 'None';

    el.ovStatesCount.textContent = data.state_count || 0;
    el.ovTransCount.textContent = data.transition_count || 0;

    const limits = data.safety_limits || {};
    el.ovLimits.innerHTML = `
      <span class="tag">Max steps: ${limits.max_steps || 50}</span>
      <span class="tag">Timeout: ${limits.max_timeout_ms || 5000}ms</span>
      <span class="tag">Max candidates: ${limits.max_candidates || 50}</span>
      <span class="tag">Max corpus states: ${limits.max_corpus_states || 100}</span>
    `;

    // Load modules table
    loadModules();
  }

  async function loadModules() {
    const res = await apiGet('/api/modules');
    if (!res.success) {
      el.tableModules.innerHTML = `<tr><td colspan="10" class="text-muted text-center">${escapeHtml(res.error.message)}</td></tr>`;
      return;
    }

    const modules = res.data.modules || [];
    state.jsonViewerCache['modules'] = modules;
    if (modules.length === 0) {
      el.tableModules.innerHTML = `<tr><td colspan="10" class="text-muted text-center">No modules discovered</td></tr>`;
      return;
    }

    let rowsHtml = '';
    modules.forEach((mod) => {
      const isMain = mod.is_main_executable;
      const biasStatus = mod.load_bias_status || 'UNRESOLVED';
      const baseHex = mod.runtime_base ? '0x' + mod.runtime_base.toString(16) : 'N/A';
      const endHex = mod.runtime_end ? '0x' + mod.runtime_end.toString(16) : 'N/A';
      const biasHex = mod.load_bias !== null && mod.load_bias !== undefined ? '0x' + mod.load_bias.toString(16) : 'N/A';

      rowsHtml += `
        <tr>
          <td>${isMain ? '<span class="badge badge-info">MAIN</span>' : ''}</td>
          <td class="mono break-all">${escapeHtml(mod.path || '')}</td>
          <td class="mono">${baseHex}</td>
          <td class="mono">${endHex}</td>
          <td class="mono">${biasHex}</td>
          <td><span class="badge ${biasStatus === 'RESOLVED' ? 'badge-success' : 'badge-neutral'}">${biasStatus}</span></td>
          <td class="mono break-all">${escapeHtml(mod.build_id || 'N/A')}</td>
          <td class="mono">${escapeHtml(mod.architecture || 'UNKNOWN')}</td>
          <td class="mono">${escapeHtml(mod.endianness || 'UNKNOWN')}</td>
          <td class="mono">${escapeHtml(mod.elf_class || 'UNKNOWN')}</td>
        </tr>
      `;
    });
    el.tableModules.innerHTML = rowsHtml;
  }

  async function loadStatesAndGraph() {
    const [statesRes, graphRes] = await Promise.all([
      apiGet('/api/states'),
      apiGet('/api/state-graph'),
    ]);

    if (statesRes.success) {
      state.states = statesRes.data || [];
      el.badgeStatesCount.textContent = state.states.length;
      renderStatesList(state.states);
      updateStateSelectors(state.states);

      if (!state.selectedStateId && state.states.length > 0) {
        selectState(state.states[0].state_id);
      }
    }

    if (graphRes.success) {
      state.stateGraphData = graphRes.data || { nodes: [], edges: [] };
      state.jsonViewerCache['state-graph'] = state.stateGraphData;
      renderStateGraph();
    }
  }

  function updateStateSelectors(statesList) {
    const options = ['<option value="">(Select Snapshot / State)</option>'];
    statesList.forEach((s) => {
      const shortHash = (s.state_hash || '').substring(0, 8);
      const isSeed = !s.metadata || !s.metadata.parent_state_id;
      const tag = isSeed ? '[Seed]' : '';
      options.push(`<option value="${s.state_id}">${s.state_id} ${tag} (${shortHash})</option>`);
    });
    el.selectSnapshotId.innerHTML = options.join('');

    if (state.selectedStateId) {
      el.selectSnapshotId.value = state.selectedStateId;
    }
  }

  function renderStatesList(statesList) {
    if (!statesList || statesList.length === 0) {
      el.listStates.innerHTML = `<div class="text-muted text-center p-3">No states recorded in corpus</div>`;
      return;
    }

    let html = '';
    statesList.forEach((s) => {
      const isSelected = s.state_id === state.selectedStateId;
      const shortHash = (s.state_hash || '').substring(0, 8);
      const isSeed = !s.metadata || !s.metadata.parent_state_id;

      html += `
        <div class="state-list-item ${isSelected ? 'selected' : ''}" data-state-id="${s.state_id}">
          <div class="state-item-header">
            <span class="state-item-id">${s.state_id}</span>
            <span class="badge ${isSeed ? 'badge-info' : 'badge-neutral'}">${isSeed ? 'SEED' : 'CHILD'}</span>
          </div>
          <div class="state-item-hash">hash: ${shortHash}...</div>
        </div>
      `;
    });
    el.listStates.innerHTML = html;

    el.listStates.querySelectorAll('.state-list-item').forEach((item) => {
      item.addEventListener('click', () => {
        const sid = item.getAttribute('data-state-id');
        selectState(sid);
      });
    });
  }

  async function selectState(stateId) {
    if (!stateId) return;
    state.selectedStateId = stateId;

    if (el.selectSnapshotId.value !== stateId) {
      el.selectSnapshotId.value = stateId;
    }

    el.listStates.querySelectorAll('.state-list-item').forEach((item) => {
      item.classList.toggle('selected', item.getAttribute('data-state-id') === stateId);
    });

    renderStateGraph();

    // 1. Load Memory Snapshot Summary (Primary Tab 1)
    await loadMemorySummary(stateId);

    // 2. Load objects for Tab 2 & Tab 3
    await loadObjectsForState(stateId);

    // 3. Load state details for Tab 4
    const res = await apiGet(`/api/states/${stateId}`);
    if (res.success) {
      const s = res.data;
      state.jsonViewerCache['state'] = s;
      state.jsonViewerCache[`state_${stateId}`] = s;

      el.cardStateDetail.style.display = 'block';
      el.detailStateId.textContent = stateId;
      el.detailStateHash.textContent = s.state_hash || 'UNKNOWN';

      const parentState = s.parent_state || 'None (Seed)';
      el.detailParentState.textContent = parentState;
      el.detailCreatedAt.textContent = s.timestamp || 'N/A';
      el.detailObservations.textContent = (s.observations && s.observations.length) || 1;

      if (s.parent_state) {
        el.btnStateDiffParent.disabled = false;
        el.inputDiffA.value = s.parent_state;
        el.inputDiffB.value = stateId;
      } else {
        el.btnStateDiffParent.disabled = true;
      }
    }
  }

  // --------------------------------------------------------------------------
  // Tab 1: Memory Snapshot Summary Renderer
  // --------------------------------------------------------------------------

  async function loadMemorySummary(stateId) {
    const res = await apiGet(`/api/states/${stateId}/memory-summary`);
    if (!res.success) {
      showToast(res.error ? res.error.message : 'Failed to fetch memory summary', 'warning');
      return;
    }

    const summary = res.data;
    state.memorySummary = summary;
    state.jsonViewerCache['memory-summary'] = summary;

    renderMemorySummary(summary);
  }

  function renderMemorySummary(summary) {
    const mode = summary.capture_mode || 'CONSISTENT';
    const status = summary.status || 'COMPLETE';
    const q = summary.quality || {};
    const bd = summary.breakdown || {};
    const objs = summary.objects || {};

    // Header identity
    el.msBadgeMode.textContent = mode;
    el.msBadgeMode.className = 'badge ' + (mode === 'LOW_IMPACT' ? 'badge-warning' : 'badge-info');

    el.msBadgeStatus.textContent = status;
    el.msBadgeStatus.className = 'badge ' + (status === 'COMPLETE' ? 'badge-success' : 'badge-warning');

    el.msBadgeConsistency.textContent = mode === 'LOW_IMPACT' ? 'NON_ATOMIC (READV)' : 'CONSISTENT (STOPPED)';

    const binName = state.runtime ? getBaseName(state.runtime.executable) : 'Target';
    el.msTargetTitle.textContent = state.runtime && state.runtime.pid ? `${binName} (PID ${state.runtime.pid})` : binName;
    el.msTargetSubtitle.textContent = state.runtime ? state.runtime.executable || 'No executable path' : '';

    // 1. Capture Status Cards
    el.statStatus.textContent = status;
    el.statStatus.className = 'metric-val ' + (status === 'COMPLETE' ? 'text-success' : 'text-warning');
    el.statStatusSub.textContent = q.mapping_race_detected ? '⚠️ Mapping race detected' : (q.partial_read_count > 0 ? `${q.partial_read_count} partial reads` : 'Complete readv capture');

    el.statCapturedMb.textContent = formatBytes(summary.captured_bytes);
    el.statCapturedBytes.textContent = `${(summary.captured_bytes || 0).toLocaleString()} bytes`;

    el.statDuration.textContent = summary.duration_ms !== null && summary.duration_ms !== undefined ? `${summary.duration_ms} ms` : 'N/A (Stopped)';
    el.statConsistency.textContent = `Consistency: ${mode === 'LOW_IMPACT' ? 'NON_ATOMIC' : 'CONSISTENT'}`;

    el.statRegionCount.textContent = summary.region_count || 0;
    el.statArch.textContent = q.architecture || 'UNKNOWN';
    el.statPointerEndian.textContent = `Pointer: ${q.pointer_width || 'UNKNOWN'} · Endian: ${q.endianness || 'UNKNOWN'}`;

    // 2. Memory Breakdown (Proportional Bar & Cards)
    const totalBytes = bd.total_captured_bytes || 1;
    const calcPct = (bytes) => ((bytes / totalBytes) * 100).toFixed(1);

    const heapPct = calcPct(bd.heap_bytes || 0);
    const stackPct = calcPct(bd.stack_bytes || 0);
    const globalPct = calcPct(bd.global_bytes || 0);
    const execPct = calcPct(bd.executable_bytes || 0);
    const shlibPct = calcPct(bd.shared_library_bytes || 0);
    const otherPct = calcPct(bd.other_bytes || 0);

    // Update stacked bar segments
    el.breakdownBar.innerHTML = `
      <div class="breakdown-segment seg-heap" style="width: ${heapPct}%;" title="Heap: ${formatBytes(bd.heap_bytes)} (${heapPct}%)"></div>
      <div class="breakdown-segment seg-stack" style="width: ${stackPct}%;" title="Stack: ${formatBytes(bd.stack_bytes)} (${stackPct}%)"></div>
      <div class="breakdown-segment seg-global" style="width: ${globalPct}%;" title="Global: ${formatBytes(bd.global_bytes)} (${globalPct}%)"></div>
      <div class="breakdown-segment seg-exec" style="width: ${execPct}%;" title="Executable: ${formatBytes(bd.executable_bytes)} (${execPct}%)"></div>
      <div class="breakdown-segment seg-shlib" style="width: ${shlibPct}%;" title="Shared Libs: ${formatBytes(bd.shared_library_bytes)} (${shlibPct}%)"></div>
      <div class="breakdown-segment seg-other" style="width: ${otherPct}%;" title="Other: ${formatBytes(bd.other_bytes)} (${otherPct}%)"></div>
    `;

    // Update breakdown values
    el.bdHeapVal.textContent = formatBytes(bd.heap_bytes);
    el.bdHeapPct.textContent = `${heapPct}%`;

    el.bdStackVal.textContent = formatBytes(bd.stack_bytes);
    el.bdStackPct.textContent = `${stackPct}%`;

    el.bdGlobalVal.textContent = formatBytes(bd.global_bytes);
    el.bdGlobalPct.textContent = `${globalPct}%`;

    el.bdExecVal.textContent = formatBytes(bd.executable_bytes);
    el.bdExecPct.textContent = `${execPct}%`;

    el.bdShlibVal.textContent = formatBytes(bd.shared_library_bytes);
    el.bdShlibPct.textContent = `${shlibPct}%`;

    el.bdOtherVal.textContent = formatBytes(bd.other_bytes);
    el.bdOtherPct.textContent = `${otherPct}%`;

    el.bdTotalVal.textContent = formatBytes(bd.total_captured_bytes);

    // 3. Semantic Runtime Objects Preview & Tree
    el.semTotalObjs.textContent = objs.total_objects || 0;
    el.semHeapObjs.textContent = objs.heap_objects || 0;
    el.semGlobalObjs.textContent = objs.global_objects || 0;
    el.semStackObjs.textContent = objs.stack_objects || 0;
    el.semRefsCount.textContent = objs.total_references || 0;

    renderSemanticTreePreview(objs.hierarchy_preview || []);

    // 4. Snapshot Quality & Provenance
    el.qualCompleteness.textContent = `${q.completeness_pct || 100}%`;
    el.qualCompleteness.className = 'metric-val ' + (q.completeness === 'COMPLETE' ? 'text-success' : 'text-warning');
    el.qualCompletenessText.textContent = q.completeness === 'COMPLETE' ? 'Complete memory acquisition' : 'Partial memory acquisition';

    el.qualMappingRace.textContent = q.mapping_race_detected ? 'DETECTED' : 'CLEAN';
    el.qualMappingRace.className = 'metric-val ' + (q.mapping_race_detected ? 'text-danger' : 'text-success');

    el.qualPartials.textContent = `${q.partial_read_count || 0} / ${q.failed_read_count || 0}`;
    el.qualUnavailFields.textContent = objs.unavailable_fields || 0;

    el.qualDebugStatus.textContent = q.debug_image_status || 'UNKNOWN';
    el.qualDebugStatus.className = 'metric-val ' + (q.debug_image_status === 'VERIFIED' ? 'text-success' : 'text-accent');
    el.qualDebugPath.textContent = state.runtime ? state.runtime.debug_image || 'No external debug image' : 'N/A';

    el.qualBuildId.textContent = q.build_id ? `[${q.build_id.substring(0, 8)}...]` : (q.build_id_status || 'UNAVAILABLE');
    el.qualModuleCount.textContent = `${q.module_count || 1} runtime modules verified`;
  }

  function renderSemanticTreePreview(hierarchyPreview) {
    if (!hierarchyPreview || hierarchyPreview.length === 0) {
      el.semanticTreePreview.innerHTML = '<div class="text-muted text-center p-3">No semantic objects discovered in this snapshot</div>';
      return;
    }

    let treeHtml = `<div class="tree-root-label">Application</div>`;

    hierarchyPreview.forEach((node, index) => {
      const isLast = index === hierarchyPreview.length - 1;
      const branchSymbol = isLast ? '└─' : '├─';
      const childPrefix = isLast ? '&nbsp;&nbsp;&nbsp;' : '│&nbsp;&nbsp;';
      const storage = (node.storage || 'UNKNOWN').toLowerCase();
      const storageClass = storage === 'heap' ? 'badge-storage-heap' : storage === 'global' ? 'badge-storage-global' : 'badge-storage-stack';

      treeHtml += `
        <div class="tree-node-row">
          <span class="tree-branch-line">${branchSymbol}</span>
          <span class="tree-obj-name">${escapeHtml(node.object_id)}</span>
          <span class="tree-obj-type">(${escapeHtml(node.type)})</span>
          <span class="badge ${storageClass}" style="font-size: 0.65rem; padding: 1px 4px;">${storage.toUpperCase()}</span>
          <button class="tree-btn-inspect" data-inspect-id="${node.object_id}">Inspect →</button>
        </div>
      `;

      // Render key fields preview
      (node.key_fields || []).forEach((f, fIdx) => {
        const isFieldLast = fIdx === (node.key_fields.length - 1);
        const fBranch = isFieldLast ? '└─' : '├─';
        const valStr = f.ref ? `──► ${escapeHtml(f.ref)}` : escapeHtml(String(f.value));

        treeHtml += `
          <div class="tree-field-row">
            <span class="tree-branch-line">${childPrefix}${fBranch}</span>
            <span class="tree-field-name">${escapeHtml(f.name)}</span> =
            <span class="tree-field-val">${valStr}</span>
          </div>
        `;
      });
    });

    el.semanticTreePreview.innerHTML = treeHtml;

    // Attach inspect buttons
    el.semanticTreePreview.querySelectorAll('.tree-btn-inspect').forEach((btn) => {
      btn.addEventListener('click', () => {
        const oid = btn.getAttribute('data-inspect-id');
        selectObject(oid);
        switchTab('tab-runtime-objects');
      });
    });
  }

  // --------------------------------------------------------------------------
  // Tab 2: Runtime Objects Directory & Human-Centric Inspector
  // --------------------------------------------------------------------------

  async function loadObjectsForState(stateId) {
    if (!stateId) return;
    const res = await apiGet(`/api/states/${stateId}/objects`);
    if (!res.success) {
      el.listMemoryObjects.innerHTML = `<div class="text-muted text-center p-3">${escapeHtml(res.error.message)}</div>`;
      return;
    }

    const objects = res.data || [];
    state.objects = objects;
    state.jsonViewerCache['objects'] = objects;

    renderMemoryObjectsList();
    renderObjectTopology();

    if (state.selectedObjectId && objects.some((o) => o.object_id === state.selectedObjectId)) {
      selectObject(state.selectedObjectId);
    } else if (objects.length > 0) {
      selectObject(objects[0].object_id);
    }
  }

  function renderMemoryObjectsList() {
    const objects = state.objects || [];
    const query = (state.searchQuery || '').toLowerCase().trim();
    const filter = state.storageFilter || 'all';

    const filtered = objects.filter((o) => {
      const st = (o.storage || 'unknown').toLowerCase();
      if (filter !== 'all' && st !== filter) return false;

      if (!query) return true;
      const matchesId = (o.object_id || '').toLowerCase().includes(query);
      const matchesType = (o.type || '').toLowerCase().includes(query);
      const matchesField = (o.fields || []).some((f) => {
        return (f.name || '').toLowerCase().includes(query) || String(f.value || '').toLowerCase().includes(query);
      });
      return matchesId || matchesType || matchesField;
    });

    el.badgeMemObjectsCount.textContent = `${filtered.length} / ${objects.length}`;

    if (filtered.length === 0) {
      el.listMemoryObjects.innerHTML = `<div class="text-muted text-center p-3">No matching objects found</div>`;
      return;
    }

    let html = '';
    filtered.forEach((o) => {
      const isSelected = o.object_id === state.selectedObjectId;
      const storage = (o.storage || 'unknown').toLowerCase();
      const storageClass = storage === 'heap' ? 'badge-storage-heap' : storage === 'global' ? 'badge-storage-global' : 'badge-storage-stack';
      const fieldCount = (o.fields && o.fields.length) || 0;
      const pointerCount = (o.fields || []).filter((f) => f.object_ref).length;

      html += `
        <div class="mem-obj-item ${isSelected ? 'selected' : ''}" data-object-id="${o.object_id}">
          <div class="mem-obj-top">
            <span class="mem-obj-title-text">${escapeHtml(o.object_id)}</span>
            <span class="badge ${storageClass}">${storage.toUpperCase()}</span>
          </div>
          <div class="mem-obj-meta-row">
            <span class="mem-obj-type">${escapeHtml(o.type || 'Unknown')}</span>
            <span class="text-muted">${fieldCount} flds${pointerCount > 0 ? ` · ${pointerCount} 🔗` : ''}</span>
          </div>
        </div>
      `;
    });
    el.listMemoryObjects.innerHTML = html;

    el.listMemoryObjects.querySelectorAll('.mem-obj-item').forEach((item) => {
      item.addEventListener('click', () => {
        const oid = item.getAttribute('data-object-id');
        selectObject(oid);
      });
    });
  }

  function selectObject(objectId) {
    state.selectedObjectId = objectId;

    el.listMemoryObjects.querySelectorAll('.mem-obj-item').forEach((item) => {
      item.classList.toggle('selected', item.getAttribute('data-object-id') === objectId);
    });

    const obj = state.objects.find((o) => o.object_id === objectId);
    if (!obj) return;
    state.jsonViewerCache[`object_${objectId}`] = obj;

    const storage = (obj.storage || 'UNKNOWN').toUpperCase();
    const storageClass = storage === 'HEAP' ? 'badge-storage-heap' : storage === 'GLOBAL' ? 'badge-storage-global' : 'badge-storage-stack';
    const addrHex = obj.address ? '0x' + Number(obj.address).toString(16) : 'N/A';

    el.memObjTitle.textContent = `${obj.object_id} — ${obj.type || 'Unknown'}`;
    el.memObjSubtitle.textContent = `${storage} memory object located at ${addrHex}`;
    el.memObjTypeBadge.textContent = obj.type || 'Unknown';
    el.memObjStorageBadge.textContent = storage;
    el.memObjStorageBadge.className = 'badge ' + storageClass;

    // Collapsible technical details
    el.memTechAddr.textContent = addrHex;
    el.memTechStorage.textContent = storage;
    el.memTechType.textContent = obj.type || 'Unknown';
    el.memTechId.textContent = obj.object_id;

    // Fields Table
    const fields = obj.fields || [];
    if (fields.length === 0) {
      el.tableSemanticFields.innerHTML = `<tr><td colspan="6" class="text-muted text-center">No fields defined for this object</td></tr>`;
      return;
    }

    let fieldsHtml = '';
    fields.forEach((f) => {
      const isRef = Boolean(f.object_ref);
      const isMutable = isFieldMutable(f.type);
      const valHtml = formatSemanticValue(f.value, f.type, f.object_ref);

      let refChipHtml = '<span class="text-muted">null</span>';
      if (isRef) {
        const targetObj = state.objects.find((target) => target.object_id === f.object_ref);
        const targetType = targetObj ? targetObj.type : 'Object';
        refChipHtml = `
          <button class="pointer-chip" data-ref-id="${f.object_ref}" title="Jump to referenced object">
            <span>🔗</span> ${escapeHtml(f.object_ref)} (${escapeHtml(targetType)})
          </button>
        `;
      }

      fieldsHtml += `
        <tr>
          <td><strong>${escapeHtml(f.name)}</strong></td>
          <td class="mono">${escapeHtml(f.type || '')}</td>
          <td>${valHtml}</td>
          <td>${refChipHtml}</td>
          <td><span class="badge ${isMutable ? 'badge-success' : 'badge-neutral'}">${isMutable ? 'mutable' : 'read_only'}</span></td>
          <td>
            ${isMutable ? `<button class="btn btn-secondary btn-sm btn-inspect-cand" data-object-id="${objectId}" data-field-name="${f.name}">Mutate</button>` : '<span class="text-muted">—</span>'}
          </td>
        </tr>
      `;
    });
    el.tableSemanticFields.innerHTML = fieldsHtml;

    el.tableSemanticFields.querySelectorAll('.pointer-chip').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const refId = btn.getAttribute('data-ref-id');
        jumpToObject(refId);
      });
    });

    el.tableSemanticFields.querySelectorAll('.btn-inspect-cand').forEach((btn) => {
      btn.addEventListener('click', () => {
        const oid = btn.getAttribute('data-object-id');
        const fld = btn.getAttribute('data-field-name');
        switchTab('tab-advanced-explore');
        const pill = document.querySelector('[data-subtab="subtab-mutations"]');
        if (pill) switchSubtab('subtab-mutations', pill);
        loadCandidates(oid, fld);
      });
    });
  }

  function jumpToObject(objectId) {
    if (!objectId) return;
    selectObject(objectId);

    const listItem = el.listMemoryObjects.querySelector(`[data-object-id="${objectId}"]`);
    if (listItem) {
      listItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function formatSemanticValue(val, typeStr, objectRef) {
    if (val === null || val === undefined) return '<span class="text-muted">None</span>';

    if (typeof val === 'boolean' || val === 'true' || val === 'false') {
      const boolVal = val === true || val === 'true';
      return `<span class="val-badge-bool-${boolVal}">${boolVal ? 'TRUE' : 'FALSE'}</span>`;
    }

    if (val === 'UNAVAILABLE' || val === 'UNKNOWN') {
      return `<span class="val-badge-unavailable">⚠️ ${val}</span>`;
    }

    const strVal = String(val);
    if (strVal.includes('::') || (strVal.length > 2 && /^[A-Z][A-Z0-9_]+$/.test(strVal))) {
      return `<span class="val-badge-enum">${escapeHtml(strVal)}</span>`;
    }

    if (objectRef) {
      return `<span class="mono text-accent">${escapeHtml(strVal)}</span>`;
    }

    return `<span class="mono">${escapeHtml(strVal)}</span>`;
  }

  function isFieldMutable(typeStr) {
    if (!typeStr) return false;
    const lower = typeStr.toLowerCase();
    if (lower.includes('const')) return false;
    return ['int', 'bool', 'enum', 'float', 'double', 'char', '*'].some((t) => lower.includes(t));
  }

  // --------------------------------------------------------------------------
  // Tab 3: Object Topology & Graph (Interactive SVG)
  // --------------------------------------------------------------------------

  function renderObjectTopology() {
    const svg = el.svgTopologyGraph;
    const objects = state.objects || [];

    if (!svg || objects.length === 0) {
      if (svg) svg.innerHTML = '<text x="50%" y="50%" fill="#6b7280" text-anchor="middle">No objects in current snapshot</text>';
      return;
    }

    const incomingEdges = {};
    const outgoingEdges = {};
    objects.forEach((o) => {
      incomingEdges[o.object_id] = 0;
      outgoingEdges[o.object_id] = [];
    });

    objects.forEach((src) => {
      (src.fields || []).forEach((f) => {
        if (f.object_ref && incomingEdges[f.object_ref] !== undefined) {
          incomingEdges[f.object_ref]++;
          outgoingEdges[src.object_id].push({
            to: f.object_ref,
            field: f.name,
          });
        }
      });
    });

    const levels = {};
    objects.forEach((o) => {
      const st = (o.storage || '').toLowerCase();
      if (st === 'global' || st === 'stack' || incomingEdges[o.object_id] === 0) {
        levels[o.object_id] = 0;
      }
    });

    const queue = Object.keys(levels);
    while (queue.length > 0) {
      const curr = queue.shift();
      const currLevel = levels[curr];
      (outgoingEdges[curr] || []).forEach((edge) => {
        if (levels[edge.to] === undefined) {
          levels[edge.to] = currLevel + 1;
          queue.push(edge.to);
        }
      });
    }

    objects.forEach((o) => {
      if (levels[o.object_id] === undefined) levels[o.object_id] = 0;
    });

    const levelGroups = {};
    objects.forEach((o) => {
      const lvl = levels[o.object_id] || 0;
      if (!levelGroups[lvl]) levelGroups[lvl] = [];
      levelGroups[lvl].push(o);
    });

    const nodeWidth = 140;
    const nodeHeight = 54;
    const colSpacing = 200;
    const rowSpacing = 90;

    const coords = {};
    let maxSvgWidth = 600;
    let maxSvgHeight = 400;

    Object.keys(levelGroups).forEach((lvlStr) => {
      const lvl = parseInt(lvlStr, 10);
      const group = levelGroups[lvl];
      const x = 50 + lvl * colSpacing;
      group.forEach((obj, idx) => {
        const y = 50 + idx * rowSpacing;
        coords[obj.object_id] = { x, y };
        if (x + nodeWidth + 60 > maxSvgWidth) maxSvgWidth = x + nodeWidth + 60;
        if (y + nodeHeight + 60 > maxSvgHeight) maxSvgHeight = y + nodeHeight + 60;
      });
    });

    svg.setAttribute('width', maxSvgWidth);
    svg.setAttribute('height', maxSvgHeight);

    let svgHtml = `
      <defs>
        <marker id="topo-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8" />
        </marker>
      </defs>
    `;

    objects.forEach((src) => {
      const fromPos = coords[src.object_id];
      if (!fromPos) return;

      (outgoingEdges[src.object_id] || []).forEach((edge) => {
        const toPos = coords[edge.to];
        if (!toPos) return;

        const x1 = fromPos.x + nodeWidth;
        const y1 = fromPos.y + nodeHeight / 2;
        const x2 = toPos.x;
        const y2 = toPos.y + nodeHeight / 2;

        const midX = (x1 + x2) / 2;
        const d = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;

        svgHtml += `
          <g class="topo-edge">
            <path d="${d}" marker-end="url(#topo-arrow)" />
            <text x="${midX}" y="${(y1 + y2) / 2 - 4}">${escapeHtml(edge.field)}</text>
          </g>
        `;
      });
    });

    objects.forEach((obj) => {
      const pos = coords[obj.object_id];
      if (!pos) return;

      const isSelected = obj.object_id === state.selectedObjectId;
      const storage = (obj.storage || 'unknown').toLowerCase();
      const barColor = storage === 'heap' ? '#38bdf8' : storage === 'global' ? '#c084fc' : '#34d399';

      svgHtml += `
        <g class="topo-node ${isSelected ? 'selected' : ''}" data-object-id="${obj.object_id}" transform="translate(${pos.x}, ${pos.y})">
          <rect class="topo-box" width="${nodeWidth}" height="${nodeHeight}" />
          <rect class="topo-header-bar" width="${nodeWidth}" height="4" fill="${barColor}" />
          <text class="topo-node-title" x="10" y="24">${escapeHtml(obj.object_id)}</text>
          <text class="topo-node-sub" x="10" y="42">${escapeHtml((obj.type || '').substring(0, 18))}</text>
        </g>
      `;
    });

    svg.innerHTML = svgHtml;

    svg.querySelectorAll('.topo-node').forEach((nodeEl) => {
      nodeEl.addEventListener('click', () => {
        const oid = nodeEl.getAttribute('data-object-id');
        selectObject(oid);
        switchTab('tab-runtime-objects');
      });
    });
  }

  // --------------------------------------------------------------------------
  // Tab 4: History / State Diff
  // --------------------------------------------------------------------------

  function renderStateGraph() {
    const svg = el.svgStateGraph;
    const data = state.stateGraphData;
    if (!svg || !data.nodes || data.nodes.length === 0) {
      if (svg) svg.innerHTML = '<text x="50%" y="50%" fill="#6b7280" text-anchor="middle">No states discovered yet</text>';
      return;
    }

    const nodes = data.nodes;
    const edges = data.edges;

    const parents = {};
    edges.forEach((e) => {
      parents[e.to] = e.from;
    });

    const levels = {};
    nodes.forEach((n) => {
      let depth = 0;
      let curr = n.id;
      const visited = new Set();
      while (parents[curr] && !visited.has(curr)) {
        visited.add(curr);
        curr = parents[curr];
        depth++;
      }
      levels[n.id] = depth;
    });

    const levelGroups = {};
    nodes.forEach((n) => {
      const d = levels[n.id] || 0;
      if (!levelGroups[d]) levelGroups[d] = [];
      levelGroups[d].push(n);
    });

    const nodeWidth = 120;
    const nodeHeight = 56;
    const levelSpacing = 160;
    const siblingSpacing = 80;

    const coords = {};
    let maxSvgWidth = 600;
    let maxSvgHeight = 350;

    Object.keys(levelGroups).forEach((lvlStr) => {
      const lvl = parseInt(lvlStr, 10);
      const group = levelGroups[lvl];
      const y = 40 + lvl * levelSpacing;
      group.forEach((n, idx) => {
        const x = 50 + idx * (nodeWidth + siblingSpacing);
        coords[n.id] = { x, y };
        if (x + nodeWidth + 50 > maxSvgWidth) maxSvgWidth = x + nodeWidth + 50;
        if (y + nodeHeight + 50 > maxSvgHeight) maxSvgHeight = y + nodeHeight + 50;
      });
    });

    svg.setAttribute('width', maxSvgWidth);
    svg.setAttribute('height', maxSvgHeight);

    let svgHtml = `
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
        </marker>
        <marker id="arrow-crash" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
        </marker>
      </defs>
    `;

    edges.forEach((e) => {
      const from = coords[e.from];
      const to = coords[e.to];
      if (!from || !to) return;

      const x1 = from.x + nodeWidth / 2;
      const y1 = from.y + nodeHeight;
      const x2 = to.x + nodeWidth / 2;
      const y2 = to.y;

      const isCrash = e.status === 'CRASHED';
      const marker = isCrash ? 'url(#arrow-crash)' : 'url(#arrow)';
      const edgeClass = isCrash ? 'graph-edge crashed' : e.status === 'TIMEOUT' ? 'graph-edge timeout' : 'graph-edge';

      const midY = (y1 + y2) / 2;
      const d = `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`;

      const label = e.field ? `${e.field}: ${e.old_value !== null ? e.old_value + '→' : ''}${e.new_value}` : e.id;
      const midX = (x1 + x2) / 2;

      svgHtml += `
        <g class="${edgeClass}">
          <path d="${d}" marker-end="${marker}" />
          <text x="${midX}" y="${midY - 4}">${escapeHtml(label)}</text>
        </g>
      `;
    });

    nodes.forEach((n) => {
      const pos = coords[n.id];
      if (!pos) return;

      const isSelected = n.id === state.selectedStateId;
      const isSeed = n.is_seed;
      const isCrash = n.status === 'CRASHED';
      const isTimeout = n.status === 'TIMEOUT';

      let nodeClass = 'graph-node';
      if (isSelected) nodeClass += ' selected';
      if (isSeed) nodeClass += ' seed';
      if (isCrash) nodeClass += ' crashed';
      if (isTimeout) nodeClass += ' timeout';

      const shortHash = n.short_hash || n.id;

      svgHtml += `
        <g class="${nodeClass}" data-node-id="${n.id}" transform="translate(${pos.x}, ${pos.y})">
          <rect width="${nodeWidth}" height="${nodeHeight}" />
          <text class="graph-node-title" x="${nodeWidth / 2}" y="22">${n.id}</text>
          <text class="graph-node-sub" x="${nodeWidth / 2}" y="40">${shortHash}</text>
        </g>
      `;
    });

    svg.innerHTML = svgHtml;

    svg.querySelectorAll('.graph-node').forEach((nodeEl) => {
      nodeEl.addEventListener('click', () => {
        const nid = nodeEl.getAttribute('data-node-id');
        selectState(nid);
      });
    });
  }

  async function computeDiff(snapA, snapB) {
    if (!snapA || !snapB) {
      showToast('Both Snapshot A and Snapshot B are required', 'error');
      return;
    }

    showToast(`Computing diff between ${snapA} and ${snapB}...`, 'info');
    const res = await apiGet(`/api/snapshots/${encodeURIComponent(snapA)}/diff/${encodeURIComponent(snapB)}`);

    if (!res.success) {
      showToast(res.error ? res.error.message : 'Diff computation failed', 'error');
      return;
    }

    const diff = res.data;
    state.jsonViewerCache['diff'] = diff;
    el.diffResults.style.display = 'block';

    const summary = diff.summary || {};
    el.diffValChanges.textContent = summary.value_changes || 0;
    el.diffRefChanges.textContent = summary.reference_changes || 0;
    el.diffObjCreated.textContent = summary.objects_created || 0;
    el.diffObjRemoved.textContent = summary.objects_removed || 0;

    const changes = diff.changes || [];
    if (changes.length === 0) {
      el.tableDiffChanges.innerHTML = `<tr><td colspan="5" class="text-muted text-center">No field changes between snapshots</td></tr>`;
      return;
    }

    let html = '';
    changes.forEach((c) => {
      html += `
        <tr>
          <td class="mono">${escapeHtml(c.object_id || '')}</td>
          <td><strong>${escapeHtml(c.field || '')}</strong></td>
          <td class="mono text-muted">${escapeHtml(String(c.before))}</td>
          <td class="mono text-accent"><strong>${escapeHtml(String(c.after))}</strong></td>
          <td><span class="tag">${escapeHtml(c.category || 'value')}</span></td>
        </tr>
      `;
    });
    el.tableDiffChanges.innerHTML = html;
  }

  // --------------------------------------------------------------------------
  // Tab 5: Advanced Exploration (Mutations & Autonomous Loop)
  // --------------------------------------------------------------------------

  async function loadCandidates(filterObjId = null, filterField = null) {
    let url = '/api/mutation-candidates';
    const params = [];
    if (filterObjId) params.push(`object_id=${encodeURIComponent(filterObjId)}`);
    if (filterField) params.push(`field=${encodeURIComponent(filterField)}`);
    if (params.length) url += '?' + params.join('&');

    const res = await apiGet(url);
    if (!res.success) {
      const msg = res.error ? res.error.message : 'Failed to load candidates';
      el.tableCandidates.innerHTML = `<tr><td colspan="9" class="text-warning text-center">⚠️ ${escapeHtml(msg)}</td></tr>`;
      return;
    }

    const cands = res.data || [];
    state.candidates = cands;
    state.jsonViewerCache['candidates'] = cands;
    el.ovCandidatesCount.textContent = cands.length;

    renderCandidatesTable(cands);
  }

  function renderCandidatesTable(cands) {
    if (!cands || cands.length === 0) {
      el.tableCandidates.innerHTML = `<tr><td colspan="9" class="text-muted text-center">No mutation candidates available for this state</td></tr>`;
      return;
    }

    const isLowImpact = state.runtime && state.runtime.mode === 'LOW_IMPACT';

    let html = '';
    cands.forEach((c) => {
      html += `
        <tr>
          <td class="mono">${escapeHtml(c.candidate_id)}</td>
          <td class="mono">${escapeHtml(c.object_id)}</td>
          <td><strong>${escapeHtml(c.field)}</strong></td>
          <td class="mono">${escapeHtml(String(c.current_value))}</td>
          <td class="mono text-accent"><strong>${escapeHtml(String(c.proposed_value))}</strong></td>
          <td class="mono">${escapeHtml(c.type || '')}</td>
          <td><span class="tag">${escapeHtml(c.reason || 'candidate')}</span></td>
          <td><span class="badge ${c.supported ? 'badge-success' : 'badge-neutral'}">${c.supported ? 'YES' : 'NO'}</span></td>
          <td>
            <button class="btn btn-primary btn-sm btn-exec-mutation" data-candidate-id="${c.candidate_id}" ${isLowImpact ? 'disabled title="Disabled in LOW_IMPACT"' : ''}>
              Execute
            </button>
          </td>
        </tr>
      `;
    });
    el.tableCandidates.innerHTML = html;

    el.tableCandidates.querySelectorAll('.btn-exec-mutation').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const candId = btn.getAttribute('data-candidate-id');
        await executeTransition(candId);
      });
    });
  }

  async function executeTransition(candidateId) {
    showToast(`Executing mutation ${candidateId}...`, 'info');
    const res = await apiPost('/api/mutation', { candidate_id: candidateId, timeout_ms: 1000 });

    if (!res.success) {
      showToast(`Mutation failed: ${res.error ? res.error.message : 'Unknown error'}`, 'error');
      return;
    }

    const trans = res.data;
    state.jsonViewerCache['last_transition'] = trans;
    showToast('Transition executed successfully!', 'success');

    el.cardExecutionResult.style.display = 'block';
    el.execTransId.textContent = trans.transition_id || 'Transition Complete';

    const execStatus = (trans.execution && trans.execution.status) || 'STOPPED';
    el.execStatusText.textContent = execStatus;
    el.execStatusBadge.textContent = execStatus;
    el.execStatusBadge.className = 'badge ' + (execStatus === 'CRASHED' ? 'badge-danger' : execStatus === 'TIMEOUT' ? 'badge-warning' : 'badge-success');

    el.execChildState.textContent = trans.child_state || 'None';
    el.execChildHash.textContent = trans.state_hash || 'N/A';

    const facts = trans.facts || {};
    const changed = facts.field_changed || [];
    if (changed.length === 0) {
      el.listExecChangedFields.innerHTML = '<li>No semantic fields modified</li>';
    } else {
      el.listExecChangedFields.innerHTML = changed.map((f) => `<li class="mono">${escapeHtml(f)}</li>`).join('');
    }

    await loadStatesAndGraph();
  }

  async function runAutonomousExplore(maxSteps, timeoutMs, maxStates) {
    showToast('Starting autonomous state exploration loop...', 'info');
    el.btnStartExplore.disabled = true;

    const res = await apiPost('/api/explore', {
      max_steps: maxSteps,
      timeout_ms: timeoutMs,
      max_states: maxStates,
    });

    el.btnStartExplore.disabled = false;

    if (!res.success) {
      const errData = res.data;
      if (errData && errData.status === 'UNAVAILABLE') {
        showToast(`Exploration Unavailable: ${res.error ? res.error.message : 'Branch isolation unsupported'}`, 'warning');
        if (el.exploreIsolationBanner) {
          el.exploreIsolationBanner.style.display = 'block';
          el.exploreIsolationBanner.className = 'alert-banner alert-warning';
          if (el.exploreIsolationTitle) el.exploreIsolationTitle.textContent = `Branch Isolation Unavailable (${errData.threads || 1} Threads)`;
          if (el.exploreIsolationMsg) el.exploreIsolationMsg.textContent = errData.message || res.error.message;
          if (el.exploreIsolationAlternatives && el.exploreAlternativesList) {
            el.exploreIsolationAlternatives.style.display = 'block';
            const alts = errData.safe_alternatives || ['OBSERVE', 'SNAPSHOT', 'LIST_OBJECTS', 'INSPECT_OBJECT', 'LIST_MUTATION_CANDIDATES'];
            el.exploreAlternativesList.innerHTML = alts.map(a => `<span class="badge badge-info" style="cursor: pointer;" onclick="handleAlternativeAction('${a}')">${a}</span>`).join(' ');
          }
          el.btnStartExplore.disabled = true;
        }
      } else {
        showToast(res.error ? res.error.message : 'Exploration loop failed', 'error');
      }
      return;
    }

    const exp = res.data;
    state.jsonViewerCache['explore'] = exp;
    showToast(`Exploration complete: Discovered ${exp.new_states} new states!`, 'success');

    el.cardExploreResults.style.display = 'block';
    el.expResSteps.textContent = exp.steps || 0;
    el.expResStates.textContent = exp.new_states || 0;
    el.expResTransitions.textContent = exp.new_transitions || 0;
    el.expResCrashes.textContent = exp.crashes || 0;
    el.expResTimeouts.textContent = exp.timeouts || 0;

    await loadRuntimeOverview();
    await loadStatesAndGraph();
  }

  window.handleAlternativeAction = function(action) {
    if (action === 'SNAPSHOT' || action === 'OBSERVE') {
      const tabBtn = document.querySelector('.tab-btn[data-tab="tab-viewer"]');
      if (tabBtn) tabBtn.click();
      if (el.btnObserve) el.btnObserve.click();
    } else if (action === 'LIST_OBJECTS' || action === 'INSPECT_OBJECT') {
      const tabBtn = document.querySelector('.tab-btn[data-tab="tab-objects"]');
      if (tabBtn) tabBtn.click();
    } else if (action === 'LIST_MUTATION_CANDIDATES') {
      const tabBtn = document.querySelector('.tab-btn[data-tab="tab-advanced"]');
      if (tabBtn) tabBtn.click();
      const subBtn = document.querySelector('.subnav-pill[data-subtab="subtab-candidates"]');
      if (subBtn) subBtn.click();
    }
  };

  // --------------------------------------------------------------------------
  // Modals & Event Bindings
  // --------------------------------------------------------------------------

  function openJsonModal(title, jsonData) {
    el.modalJsonTitle.textContent = title;
    el.modalJsonContent.textContent = JSON.stringify(jsonData, null, 2);
    el.modalJson.style.display = 'flex';
  }

  function initJsonViewerButtons() {
    document.querySelectorAll('.btn-view-json').forEach((btn) => {
      btn.addEventListener('click', () => {
        const entity = btn.getAttribute('data-entity');
        const data = state.jsonViewerCache[entity];
        if (data) {
          openJsonModal(`${entity.toUpperCase()} JSON`, data);
        } else {
          showToast(`No JSON data cached for ${entity}`, 'warning');
        }
      });
    });

    el.btnViewStateJson.addEventListener('click', () => {
      if (state.selectedStateId) {
        const data = state.jsonViewerCache[`state_${state.selectedStateId}`];
        openJsonModal(`State ${state.selectedStateId} JSON`, data);
      }
    });

    el.btnViewObjJson.addEventListener('click', () => {
      if (state.selectedObjectId) {
        const data = state.jsonViewerCache[`object_${state.selectedObjectId}`];
        openJsonModal(`Object ${state.selectedObjectId} JSON`, data);
      }
    });

    el.btnViewTransJson.addEventListener('click', () => {
      const data = state.jsonViewerCache['last_transition'];
      if (data) openJsonModal('Transition JSON', data);
    });

    el.btnCloseJsonModal.addEventListener('click', () => {
      el.modalJson.style.display = 'none';
    });

    el.btnCopyJson.addEventListener('click', () => {
      const text = el.modalJsonContent.textContent;
      navigator.clipboard.writeText(text);
      showToast('JSON copied to clipboard', 'success');
    });
  }

  function initObserveDialog() {
    el.btnObserveDialog.addEventListener('click', () => {
      el.modalObserve.style.display = 'flex';
    });

    el.btnCloseObserveModal.addEventListener('click', () => {
      el.modalObserve.style.display = 'none';
    });

    el.btnCancelObserve.addEventListener('click', () => {
      el.modalObserve.style.display = 'none';
    });

    el.formObserve.addEventListener('submit', async (e) => {
      e.preventDefault();
      const mode = el.formObserve.elements['obs-mode'].value;
      const pidVal = el.obsPid.value ? parseInt(el.obsPid.value, 10) : null;
      const debugImg = el.obsDebugImage.value.trim() || null;
      const policy = el.obsPolicy.value;

      showToast(`Initiating observation (${mode})...`, 'info');
      el.modalObserve.style.display = 'none';

      const res = await apiPost('/api/observe', {
        mode,
        pid: pidVal,
        debug_image: debugImg,
        policy,
      });

      if (!res.success) {
        showToast(res.error ? res.error.message : 'Observation failed', 'error');
        return;
      }

      showToast('Observation captured successfully!', 'success');
      await loadRuntimeOverview();
      await loadStatesAndGraph();
    });
  }

  function bindEvents() {
    el.btnRefresh.addEventListener('click', async () => {
      showToast('Refreshing runtime state...', 'info');
      await loadRuntimeOverview();
      await loadStatesAndGraph();
    });

    el.selectSnapshotId.addEventListener('change', (e) => {
      const sid = e.target.value;
      if (sid) selectState(sid);
    });

    el.btnGotoObjects.addEventListener('click', () => {
      switchTab('tab-runtime-objects');
    });

    el.inputSearchObjects.addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      renderMemoryObjectsList();
    });

    el.storageFilterPills.forEach((pill) => {
      pill.addEventListener('click', () => {
        el.storageFilterPills.forEach((p) => p.classList.remove('active'));
        pill.classList.add('active');
        state.storageFilter = pill.getAttribute('data-storage');
        renderMemoryObjectsList();
      });
    });

    el.btnJumpTopology.addEventListener('click', () => {
      switchTab('tab-object-graph');
    });

    el.btnResetTopology.addEventListener('click', () => {
      renderObjectTopology();
    });

    el.btnResetGraph.addEventListener('click', () => {
      renderStateGraph();
    });

    el.inputSearchStates.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      const filtered = state.states.filter((s) => {
        return s.state_id.toLowerCase().includes(q) || (s.state_hash || '').toLowerCase().includes(q);
      });
      renderStatesList(filtered);
    });

    el.btnInspectStateObjects.addEventListener('click', () => {
      if (state.selectedStateId) {
        switchTab('tab-runtime-objects');
      }
    });

    el.btnStateDiffParent.addEventListener('click', () => {
      if (state.selectedStateId) {
        const diffPill = document.querySelector('[data-subtab="subtab-diff"]');
        if (diffPill) switchSubtab('subtab-diff', diffPill);
        computeDiff(el.inputDiffA.value, el.inputDiffB.value);
      }
    });

    el.btnStateMutate.addEventListener('click', () => {
      switchTab('tab-advanced-explore');
      const mutPill = document.querySelector('[data-subtab="subtab-mutations"]');
      if (mutPill) switchSubtab('subtab-mutations', mutPill);
      loadCandidates();
    });

    el.inputFilterCandField.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      const filtered = state.candidates.filter((c) => {
        return (c.field || '').toLowerCase().includes(q) || (c.object_id || '').toLowerCase().includes(q);
      });
      renderCandidatesTable(filtered);
    });

    el.btnRunDiff.addEventListener('click', () => {
      const a = el.inputDiffA.value.trim();
      const b = el.inputDiffB.value.trim();
      computeDiff(a, b);
    });

    if (el.btnVerifyDeterminism) {
      el.btnVerifyDeterminism.addEventListener('click', async () => {
        showToast('Verifying restart determinism across process restarts...', 'info');
        el.btnVerifyDeterminism.disabled = true;
        const res = await apiPost('/api/runtime/verify_determinism', {});
        el.btnVerifyDeterminism.disabled = false;

        if (el.boxDeterminismResult) {
          el.boxDeterminismResult.style.display = 'block';
          if (res.success && res.data && res.data.deterministic) {
            showToast('Restart determinism VERIFIED: parent state matches restored state!', 'success');
            el.boxDeterminismResult.className = 'alert-banner alert-success';
            if (el.detResultTitle) el.detResultTitle.textContent = '✓ Restart Determinism Verified';
            const d = res.data;
            const pH = d.parent_state_hash ? d.parent_state_hash.substring(0, 16) + '...' : 'N/A';
            const rH = d.restored_state_hash ? d.restored_state_hash.substring(0, 16) + '...' : 'N/A';
            if (el.detResultDetails) {
              el.detResultDetails.innerHTML = `Status: <strong>${d.status}</strong><br>Parent Hash: ${pH}<br>Restored Hash: ${rH}`;
            }
          } else {
            const d = res.data || {};
            const statusVal = d.status || (res.error ? res.error.code : 'FAILED');
            const isNonDet = statusVal === 'NON_DETERMINISTIC';
            showToast(`Determinism Verification: ${statusVal}`, isNonDet ? 'warning' : 'error');
            el.boxDeterminismResult.className = `alert-banner ${isNonDet ? 'alert-warning' : 'alert-danger'}`;
            if (el.detResultTitle) el.detResultTitle.textContent = isNonDet ? '⚠️ Non-Deterministic State Detected' : '❌ Restart Determinism Failed';
            const errCode = (res.error && res.error.code) || d.reason_code || statusVal;
            const errMsg = (res.error && res.error.message) || d.message || 'Mismatches detected between parent and restored state';
            const mismatches = d.mismatches || [];
            let detailsHtml = `Status: <strong>${statusVal}</strong> (${errCode})<br>${escapeHtml(errMsg)}`;
            if (mismatches.length > 0) {
              detailsHtml += '<br>Mismatches: ' + mismatches.map(m => escapeHtml(m.field || m.object_id || JSON.stringify(m))).join(', ');
            }
            if (el.detResultDetails) {
              el.detResultDetails.innerHTML = detailsHtml;
            }
          }
        }
        await loadRuntimeOverview();
      });
    }

    el.formExplore.addEventListener('submit', (e) => {
      e.preventDefault();
      const steps = parseInt(el.expMaxSteps.value, 10);
      const timeout = parseInt(el.expTimeout.value, 10);
      const statesCount = parseInt(el.expMaxStates.value, 10);
      runAutonomousExplore(steps, timeout, statesCount);
    });
  }

  // --------------------------------------------------------------------------
  // Application Bootstrap
  // --------------------------------------------------------------------------

  async function init() {
    initTabs();
    initJsonViewerButtons();
    initObserveDialog();
    bindEvents();

    await loadRuntimeOverview();
    await loadStatesAndGraph();
  }

  window.addEventListener('DOMContentLoaded', init);
})();
