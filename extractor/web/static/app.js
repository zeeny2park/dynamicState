/**
 * dynamicState — Memory Snapshot & Runtime State Explorer Frontend
 * Single-Page Application communicating via AgentRuntime REST API.
 */

(function () {
  'use strict';

  // Global Application State
  // Global Application State
  const state = {
    runtime: null,
    states: [],
    selectedStateId: null,
    memorySummary: null,
    objects: [],
    selectedObjectId: null,
    storageFilter: 'all',
    objectFilterGroup: 'all', // 'all', 'roots', 'heap', 'globals', 'stack', 'types'
    objectSort: 'name-asc', // 'name-asc', 'name-desc', 'type-asc', 'fields-desc', 'refs-desc', 'addr-asc'
    searchQuery: '',
    candidates: [],
    stateGraphData: { nodes: [], edges: [] },
    activeTab: 'tab-object-explorer',
    activeSubtab: 'subtab-dag',
    centerView: 'tree', // 'tree', 'table', 'graph'
    jsonViewerCache: {},
    isAdvancedMode: false,
    currentMutationTarget: null,
    currentMutableField: null,
    globalTimeoutMs: 1000,
    expandedTreeNodes: new Set(),
    treeFilterQuery: '',
    selectedLabSnapshotId: null,
    lastCaptureReport: null,
    stateLabTree: null,
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
    tagHeaderObsPoint: document.getElementById('tag-header-obs-point'),
    txtHeaderObsPoint: document.getElementById('txt-header-obs-point'),
    btnModeBasic: document.getElementById('btn-mode-basic'),
    btnModeAdvanced: document.getElementById('btn-mode-advanced'),
    btnRefresh: document.getElementById('btn-refresh'),
    btnObserveDialog: document.getElementById('btn-observe-dialog'),
    lowImpactBanner: document.getElementById('low-impact-banner'),
    toastContainer: document.getElementById('toast-container'),

    // Runtime Memory & State Summary Bar (Top Overview)
    sumRuntimeStatus: document.getElementById('sum-runtime-status'),
    sumThreadCount: document.getElementById('sum-thread-count'),
    sumObjectCount: document.getElementById('sum-object-count'),
    sumRootCount: document.getElementById('sum-root-count'),
    sumStateHash: document.getElementById('sum-state-hash'),
    sumCheckpointStatus: document.getElementById('sum-checkpoint-status'),
    sumIsolationStatus: document.getElementById('sum-isolation-status'),
    sumDeterminismStatus: document.getElementById('sum-determinism-status'),
    sumObsPoint: document.getElementById('sum-obs-point'),
    selectGlobalTimeout: document.getElementById('select-global-timeout'),
    selectSnapshotId: document.getElementById('select-snapshot-id'),

    // Main Nav Tabs (6 Tabs)
    navTabs: document.querySelectorAll('.nav-tab'),
    tabPanes: document.querySelectorAll('.tab-pane'),

    // TAB 1: 3-Pane Object Explorer Workspace
    // Left Pane
    badgeMemObjectsCount: document.getElementById('badge-mem-objects-count'),
    selectObjSort: document.getElementById('select-obj-sort'),
    inputSearchObjects: document.getElementById('input-search-objects'),
    btnClearObjSearch: document.getElementById('btn-clear-obj-search'),
    filterObjGroupPills: document.querySelectorAll('#filter-obj-group .filter-pill'),
    memGraphTruncatedWarning: document.getElementById('mem-graph-truncated-warning'),
    txtMemTruncatedCount: document.getElementById('txt-mem-truncated-count'),
    listMemoryObjects: document.getElementById('list-memory-objects'),

    // Center Pane
    centerBreadcrumb: document.getElementById('center-breadcrumb'),
    bcCurrentName: document.getElementById('bc-current-name'),
    btnViewTree: document.getElementById('btn-view-tree'),
    btnViewTable: document.getElementById('btn-view-table'),
    btnViewGraph: document.getElementById('btn-view-graph'),
    centerViewTabs: document.querySelectorAll('.center-view-tabs .btn-tab-pill'),
    viewReferenceTree: document.getElementById('view-reference-tree'),
    viewReferenceTable: document.getElementById('view-reference-table'),
    viewTopologyGraph: document.getElementById('view-topology-graph'),
    treeReferenceContainer: document.getElementById('tree-reference-container'),
    btnExpandAllTree: document.getElementById('btn-expand-all-tree'),
    btnCollapseAllTree: document.getElementById('btn-collapse-all-tree'),
    tableObjectsSummary: document.getElementById('table-objects-summary'),
    tbodyObjectsSummary: document.getElementById('tbody-objects-summary'),
    svgTopologyGraph: document.getElementById('topology-graph-svg'),
    btnResetTopology: document.getElementById('btn-reset-topology'),

    // Right Pane (Inspector)
    memObjTitle: document.getElementById('mem-obj-title'),
    memObjSubtitle: document.getElementById('mem-obj-subtitle'),
    memObjTypeBadge: document.getElementById('mem-obj-type-badge'),
    memObjStorageBadge: document.getElementById('mem-obj-storage-badge'),
    btnViewObjJson: document.getElementById('btn-view-obj-json'),
    btnJumpTopology: document.getElementById('btn-jump-topology'),

    inspValName: document.getElementById('insp-val-name'),
    inspValType: document.getElementById('insp-val-type'),
    inspValStorage: document.getElementById('insp-val-storage'),
    inspValStatus: document.getElementById('insp-val-status'),
    inspValRoot: document.getElementById('insp-val-root'),
    inspValThread: document.getElementById('insp-val-thread'),
    memTechId: document.getElementById('mem-tech-id'),
    memTechAddr: document.getElementById('mem-tech-addr'),
    memTechDwarf: document.getElementById('mem-tech-dwarf'),
    memTechRange: document.getElementById('mem-tech-range'),
    memTechBuildId: document.getElementById('mem-tech-build-id'),
    memTechStorage: document.getElementById('mem-tech-storage'),
    memTechType: document.getElementById('mem-tech-type'),

    inspFieldsCount: document.getElementById('insp-fields-count'),
    tableSemanticFields: document.querySelector('#table-semantic-fields tbody'),

    badgeTotalRefsCount: document.getElementById('badge-total-refs-count'),
    badgeOutgoingCount: document.getElementById('badge-outgoing-count'),
    badgeIncomingCount: document.getElementById('badge-incoming-count'),
    inspectorOutgoingRefs: document.getElementById('inspector-outgoing-refs'),
    inspectorIncomingRefs: document.getElementById('inspector-incoming-refs'),

    cardIntegratedMutation: document.getElementById('card-integrated-mutation'),
    inspMutBadge: document.getElementById('insp-mut-badge'),
    inspMutTargetLabel: document.getElementById('insp-mut-target-label'),
    inspMutCurrentVal: document.getElementById('insp-mut-current-val'),
    inspMutInputContainer: document.getElementById('insp-mut-input-container'),
    inspMutNewVal: document.getElementById('insp-mut-new-val'),
    inspMutBackend: document.getElementById('insp-mut-backend'),
    inspMutObsPoint: document.getElementById('insp-mut-obs-point'),
    btnInspRunMutation: document.getElementById('btn-insp-run-mutation'),

    inspStateId: document.getElementById('insp-state-id'),
    inspParentStateId: document.getElementById('insp-parent-state-id'),
    inspStateHash: document.getElementById('insp-state-hash'),

    // Thread Explorer (Tab 2)
    badgeThreadsCount: document.getElementById('badge-threads-count'),
    tableThreads: document.getElementById('table-threads'),
    tbodyThreads: document.getElementById('tbody-threads'),

    // Memory Snapshot Explorer (Tab 3)
    msBadgeMode: document.getElementById('ms-badge-mode'),
    msBadgeStatus: document.getElementById('ms-badge-status'),
    msBadgeConsistency: document.getElementById('ms-badge-consistency'),
    msBadgeBackend: document.getElementById('ms-badge-backend'),
    msBadgeIsolation: document.getElementById('ms-badge-isolation'),
    msTxtObsPoint: document.getElementById('ms-txt-obs-point'),
    msTargetTitle: document.getElementById('ms-target-title'),
    msTargetSubtitle: document.getElementById('ms-target-subtitle'),

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

    storageFilterPills: document.querySelectorAll('.storage-filter-pills .filter-pill'),

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
    execRestoreBackend: document.getElementById('exec-restore-backend'),
    execStepDuration: document.getElementById('exec-step-duration'),
    execChildHashBox: document.getElementById('exec-child-hash-box'),
    transFlowContainer: document.getElementById('trans-flow-container'),
    flowParentId: document.getElementById('flow-parent-id'),
    flowParentHash: document.getElementById('flow-parent-hash'),
    flowParentVal: document.getElementById('flow-parent-val'),
    flowMutationLabel: document.getElementById('flow-mutation-label'),
    flowArrowMeta: document.getElementById('flow-arrow-meta'),
    flowChildId: document.getElementById('flow-child-id'),
    flowChildHash: document.getElementById('flow-child-hash'),
    flowChildVal: document.getElementById('flow-child-val'),
    execTimelineList: document.getElementById('exec-timeline-list'),
    tbodyExecDiff: document.getElementById('tbody-exec-diff'),
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

    modalMutationPreview: document.getElementById('modal-mutation-preview'),
    btnCloseMutationModal: document.getElementById('btn-close-mutation-modal'),
    btnCancelMutation: document.getElementById('btn-cancel-mutation'),
    formMutationPreview: document.getElementById('form-mutation-preview'),
    prevTargetStorage: document.getElementById('prev-target-storage'),
    prevTargetMutability: document.getElementById('prev-target-mutability'),
    prevTargetRawId: document.getElementById('prev-target-raw-id'),
    prevTargetSemantic: document.getElementById('prev-target-semantic'),
    prevTargetType: document.getElementById('prev-target-type'),
    prevCurrentValue: document.getElementById('prev-current-value'),
    prevInputContainer: document.getElementById('prev-input-container'),
    prevObsPoint: document.getElementById('prev-obs-point'),
    prevRestoreBackend: document.getElementById('prev-restore-backend'),
    prevBranchIsolation: document.getElementById('prev-branch-isolation'),
    prevTimeoutSelect: document.getElementById('prev-timeout-select'),
    btnSubmitMutation: document.getElementById('btn-submit-mutation'),

    modalJson: document.getElementById('modal-json'),
    modalJsonTitle: document.getElementById('modal-json-title'),
    modalJsonContent: document.getElementById('modal-json-content'),
    btnCloseJsonModal: document.getElementById('btn-close-json-modal'),
    btnCopyJson: document.getElementById('btn-copy-json'),

    // Tab 7: State Laboratory
    btnFastCapture: document.getElementById('btn-fast-capture'),
    sumCaptureBackend: document.getElementById('sum-capture-backend'),
    sumCaptureLatency: document.getElementById('sum-capture-latency'),
    statelabBackendBadge: document.getElementById('statelab-backend-badge'),
    btnLabOpenCapture: document.getElementById('btn-lab-open-capture'),
    btnLabOpenBranch: document.getElementById('btn-lab-open-branch'),
    btnLabOpenMutate: document.getElementById('btn-lab-open-mutate'),
    btnRefreshLabTree: document.getElementById('btn-refresh-lab-tree'),
    statelabSnapId: document.getElementById('statelab-snap-id'),
    statelabStopTime: document.getElementById('statelab-stop-time'),
    statelabObjCount: document.getElementById('statelab-obj-count'),
    statelabMemSize: document.getElementById('statelab-mem-size'),
    statelabThreadsCount: document.getElementById('statelab-threads-count'),
    statelabStateHash: document.getElementById('statelab-state-hash'),
    latStopTime: document.getElementById('lat-stop-time'),
    latThreadTime: document.getElementById('lat-thread-time'),
    latMemoryTime: document.getElementById('lat-memory-time'),
    latResumeTime: document.getElementById('lat-resume-time'),
    latTotalStopTime: document.getElementById('lat-total-stop-time'),
    statelabTreeContainer: document.getElementById('statelab-tree-container'),
    impactTargetLabel: document.getElementById('impact-target-label'),
    impactDirectList: document.getElementById('impact-direct-list'),
    impactParentList: document.getElementById('impact-parent-list'),
    impactSharedList: document.getElementById('impact-shared-list'),
    impactRefThreadsList: document.getElementById('impact-ref-threads-list'),
    impactPotThreadsList: document.getElementById('impact-pot-threads-list'),
    badgeReplayCap: document.getElementById('badge-replay-cap'),
    replayValCapability: document.getElementById('replay-val-capability'),
    replayValAttempted: document.getElementById('replay-val-attempted'),
    replayValCompleted: document.getElementById('replay-val-completed'),
    replayValVerified: document.getElementById('replay-val-verified'),
    replayValSource: document.getElementById('replay-val-source'),
    btnRunReplayAction: document.getElementById('btn-run-replay-action'),

    // State Lab Modals
    modalFastCapture: document.getElementById('modal-fast-capture'),
    btnCloseFastCaptureModal: document.getElementById('btn-close-fast-capture-modal'),
    btnCancelFastCapture: document.getElementById('btn-cancel-fast-capture'),
    formFastCapture: document.getElementById('form-fast-capture'),
    groupTargetPath: document.getElementById('group-target-path'),
    capTargetPath: document.getElementById('cap-target-path'),
    capPid: document.getElementById('cap-pid'),
    capTimeout: document.getElementById('cap-timeout'),
    modalSnapshotMutate: document.getElementById('modal-snapshot-mutate'),
    btnCloseSnapMutateModal: document.getElementById('btn-close-snap-mutate-modal'),
    btnCancelSnapMutate: document.getElementById('btn-cancel-snap-mutate'),
    formSnapshotMutate: document.getElementById('form-snapshot-mutate'),
    snapMutTarget: document.getElementById('snap-mut-target'),
    snapMutValue: document.getElementById('snap-mut-value'),
    snapMutBranchName: document.getElementById('snap-mut-branch-name'),
  };

  // --------------------------------------------------------------------------
  // API Helpers (subpath & reverse-proxy aware)
  // --------------------------------------------------------------------------

  const _rawPath = (window.location && window.location.pathname) ? window.location.pathname : '';
  const _basePath = _rawPath.endsWith('/')
    ? _rawPath.slice(0, -1)
    : _rawPath.replace(/\/[^/]*$/, '');

  function getApiUrl(endpoint) {
    if (!endpoint.startsWith('/')) {
      endpoint = '/' + endpoint;
    }
    return _basePath ? `${_basePath}${endpoint}` : endpoint;
  }

  async function apiGet(endpoint) {
    try {
      const res = await fetch(getApiUrl(endpoint));
      return await res.json();
    } catch (err) {
      console.error(`API GET ${endpoint} error:`, err);
      return { success: false, error: { code: 'NETWORK_ERROR', message: String(err) } };
    }
  }

  async function apiPost(endpoint, body = {}) {
    try {
      const res = await fetch(getApiUrl(endpoint), {
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

  // Mutability Normalization & Helpers (Source of Truth)
  function normalizeMutability(val) {
    if (!val) return 'unsupported';
    const lower = String(val).toLowerCase().trim();
    if (lower === 'mutable') return 'mutable';
    if (lower === 'read_only' || lower === 'readonly' || lower === 'const') return 'read_only';
    return 'unsupported';
  }

  function isFieldMutable(typeStr, mutabilityVal) {
    if (mutabilityVal !== undefined && mutabilityVal !== null) {
      return normalizeMutability(mutabilityVal) === 'mutable';
    }
    if (!typeStr) return false;
    const lower = typeStr.toLowerCase();
    if (lower.includes('const')) return false;
    return ['int', 'bool', 'enum', 'float', 'double', 'char', '*'].some((t) => lower.includes(t));
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

    // Center view pills (Reference Tree, Table, SVG Graph)
    if (el.btnViewTree) el.btnViewTree.addEventListener('click', () => switchCenterView('tree'));
    if (el.btnViewTable) el.btnViewTable.addEventListener('click', () => switchCenterView('table'));
    if (el.btnViewGraph) el.btnViewGraph.addEventListener('click', () => switchCenterView('graph'));
  }

  function switchCenterView(viewMode) {
    state.centerView = viewMode;
    if (el.btnViewTree) el.btnViewTree.classList.toggle('active', viewMode === 'tree');
    if (el.btnViewTable) el.btnViewTable.classList.toggle('active', viewMode === 'table');
    if (el.btnViewGraph) el.btnViewGraph.classList.toggle('active', viewMode === 'graph');

    if (el.viewReferenceTree) el.viewReferenceTree.style.display = viewMode === 'tree' ? 'flex' : 'none';
    if (el.viewReferenceTable) el.viewReferenceTable.style.display = viewMode === 'table' ? 'flex' : 'none';
    if (el.viewTopologyGraph) el.viewTopologyGraph.style.display = viewMode === 'graph' ? 'flex' : 'none';

    if (viewMode === 'tree') {
      renderReferenceTree();
    } else if (viewMode === 'table') {
      renderReferenceTable();
    } else if (viewMode === 'graph') {
      renderObjectTopology();
    }
  }

  function switchTab(tabId) {
    state.activeTab = tabId;
    el.navTabs.forEach((t) => {
      t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
    });
    el.tabPanes.forEach((p) => {
      p.classList.toggle('active', p.id === tabId);
    });

    if (tabId === 'tab-object-explorer') {
      renderMemoryObjectsList();
      if (state.centerView === 'tree') renderReferenceTree();
      else if (state.centerView === 'table') renderReferenceTable();
      else if (state.centerView === 'graph') renderObjectTopology();
      if (state.selectedObjectId) selectObject(state.selectedObjectId);
    } else if (tabId === 'tab-object-graph') {
      renderObjectTopology();
    } else if (tabId === 'tab-runtime-objects') {
      renderMemoryObjectsList();
    } else if (tabId === 'tab-history-diff') {
      renderStateGraph();
    } else if (tabId === 'tab-state-lab') {
      loadStateLabTree();
      if (state.selectedLabSnapshotId) {
        selectLabSnapshot(state.selectedLabSnapshotId);
      }
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
  // Mode Toggle (Basic Human-Centric vs Advanced Developer/Agent)
  // --------------------------------------------------------------------------

  function initModeToggle() {
    if (!el.btnModeBasic || !el.btnModeAdvanced) return;

    el.btnModeBasic.addEventListener('click', () => {
      setMode(false);
    });

    el.btnModeAdvanced.addEventListener('click', () => {
      setMode(true);
    });
  }

  function setMode(isAdvanced) {
    state.isAdvancedMode = isAdvanced;
    if (el.btnModeBasic) el.btnModeBasic.classList.toggle('active', !isAdvanced);
    if (el.btnModeAdvanced) el.btnModeAdvanced.classList.toggle('active', isAdvanced);
    document.body.classList.toggle('advanced-mode', isAdvanced);

    // Re-render currently visible components that differ between basic & advanced
    renderMemoryObjectsList();
    if (state.selectedObjectId) selectObject(state.selectedObjectId);
    if (state.candidates && state.candidates.length > 0) renderCandidatesTable(state.candidates);
  }

  // --------------------------------------------------------------------------
  // Thread Explorer Renderer
  // --------------------------------------------------------------------------

  function renderThreads(threadsList, obsPoint) {
    if (!el.tbodyThreads) return;
    const threads = threadsList || [];
    if (el.badgeThreadsCount) el.badgeThreadsCount.textContent = threads.length || (state.runtime && state.runtime.threads) || 1;

    if (threads.length === 0) {
      el.tbodyThreads.innerHTML = `<tr><td colspan="7" class="text-muted text-center p-3">Single execution thread active</td></tr>`;
      return;
    }

    let rowsHtml = '';
    threads.forEach((t) => {
      const isObsThread = obsPoint && (
        (obsPoint.function && t.function === obsPoint.function) ||
        (obsPoint.location && t.location === obsPoint.location) ||
        (obsPoint.thread_id !== undefined && t.thread_id === obsPoint.thread_id)
      );

      const stateBadge = t.state === 'STOPPED' ? '<span class="badge badge-success">STOPPED</span>' :
                         t.state === 'RUNNING' ? '<span class="badge badge-info">RUNNING</span>' :
                         `<span class="badge badge-neutral">${escapeHtml(t.state || 'UNKNOWN')}</span>`;

      // Honest thread display: NEVER fabricate thread names or locations
      const threadDisplayName = t.name ? escapeHtml(t.name) : '<span class="text-muted">Name unavailable</span>';
      const funcDisplay = t.function ? `<code class="mono">${escapeHtml(t.function)}</code>` : '<span class="text-muted">Unavailable</span>';
      const locDisplay = t.location ? `<span class="mono">${escapeHtml(t.location)}</span>` : '<span class="text-muted">Unavailable</span>';

      rowsHtml += `
        <tr class="${isObsThread ? 'row-obs-thread' : ''}">
          <td class="mono font-semibold">#${escapeHtml(String(t.thread_id))}</td>
          <td>${threadDisplayName}</td>
          <td>${stateBadge}</td>
          <td>${funcDisplay}</td>
          <td class="mono text-muted">${locDisplay}</td>
          <td class="mono">${t.frame_depth !== undefined ? t.frame_depth : 1}</td>
          <td>
            ${isObsThread ? '<span class="badge badge-obs-active">📍 OBS POINT</span>' : '<span class="text-muted">—</span>'}
          </td>
        </tr>
      `;
    });
    el.tbodyThreads.innerHTML = rowsHtml;
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
    if (el.txtRuntimeStatus) el.txtRuntimeStatus.textContent = status;
    if (el.pillRuntimeStatus) el.pillRuntimeStatus.className = 'status-pill ' + status.toLowerCase();

    const mode = data.mode || 'CONSISTENT';
    if (el.badgeObsMode) {
      el.badgeObsMode.textContent = mode;
      el.badgeObsMode.className = 'mode-badge' + (mode === 'LOW_IMPACT' ? ' low-impact' : '');
    }

    // Top Summary Bar Updates
    if (el.sumRuntimeStatus) {
      el.sumRuntimeStatus.textContent = status;
      el.sumRuntimeStatus.className = 'summary-val status-badge ' + (status === 'STOPPED' ? 'status-stopped' : status === 'RUNNING' ? 'status-running' : 'status-crashed');
    }

    const threadCount = data.threads || 1;
    if (el.sumThreadCount) el.sumThreadCount.textContent = threadCount;
    if (el.sumObjectCount) el.sumObjectCount.textContent = (data.state_summary && data.state_summary.objects_count) || (state.objects && state.objects.length) || 0;
    if (el.sumRootCount) el.sumRootCount.textContent = (data.state_summary && data.state_summary.roots_count) || 0;
    if (el.sumStateHash) {
      const sh = (data.state_summary && data.state_summary.state_hash) || data.current_state_hash || 'N/A';
      el.sumStateHash.textContent = sh && sh !== 'N/A' ? sh.substring(0, 8) + '...' : 'N/A';
    }

    // Timeout Source of Truth (Backend default unless user customized)
    if (!state.userCustomizedTimeout) {
      const backendTimeout = (data.mutation && data.mutation.default_timeout_ms)
        || (data.limits && data.limits.default_timeout_ms)
        || data.default_timeout_ms
        || 1000;
      state.globalTimeoutMs = backendTimeout;
      if (el.selectGlobalTimeout) el.selectGlobalTimeout.value = String(backendTimeout);
      if (el.prevTimeoutSelect) el.prevTimeoutSelect.value = String(backendTimeout);
    }

    // Show/hide low-impact banner & branch isolation banner
    const branchIso = data.branch_isolation || {};
    const isIsoSupported = branchIso.status === 'SUPPORTED';

    if (mode === 'LOW_IMPACT') {
      if (el.lowImpactBanner) el.lowImpactBanner.style.display = 'flex';
      if (el.exploreIsolationBanner) el.exploreIsolationBanner.style.display = 'none';
      if (el.btnStartExplore) {
        el.btnStartExplore.disabled = true;
        el.btnStartExplore.title = 'Exploration unsupported in LOW_IMPACT mode';
      }
    } else {
      if (el.lowImpactBanner) el.lowImpactBanner.style.display = 'none';

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
          if (el.btnStartExplore) {
            el.btnStartExplore.disabled = true;
            el.btnStartExplore.title = 'Autonomous exploration disabled: Branch isolation unavailable for multithreaded inferior';
          }
        } else {
          el.exploreIsolationBanner.className = 'alert-banner alert-success';
          const backendName = branchIso.restore_backend || 'RESTART';
          if (el.exploreIsolationTitle) el.exploreIsolationTitle.textContent = `Branch Isolation Active (${backendName} Backend, ${threadCount} Thread${threadCount > 1 ? 's' : ''})`;
          if (el.exploreIsolationMsg) {
            el.exploreIsolationMsg.textContent = `Independent sibling mutation execution is supported via ${backendName} restore.`;
          }
          if (el.exploreIsolationAlternatives) el.exploreIsolationAlternatives.style.display = 'none';
          if (el.btnStartExplore) {
            el.btnStartExplore.disabled = false;
            el.btnStartExplore.title = '';
          }
        }
      } else if (el.btnStartExplore) {
        el.btnStartExplore.disabled = false;
        el.btnStartExplore.title = '';
      }
    }

    if (el.tagPid) el.tagPid.textContent = data.pid ? `PID: ${data.pid}` : 'PID: N/A';
    if (el.tagArch) el.tagArch.textContent = `Arch: ${data.architecture || 'UNKNOWN'}`;
    if (el.tagEndian) el.tagEndian.textContent = `Endian: ${data.endianness || 'UNKNOWN'}`;
    if (el.tagElf) el.tagElf.textContent = `ELF: ${data.elf_class || 'UNKNOWN'}`;

    // Observation Point display - HONEST: NEVER fabricate 'observation_checkpoint' or copy spec
    const obsPoint = data.observation_point;
    if (obsPoint && (obsPoint.location || obsPoint.spec || obsPoint.function)) {
      let obsDisplay;
      if (obsPoint.location) {
        obsDisplay = obsPoint.function ? `${obsPoint.function} @ ${obsPoint.location}` : obsPoint.location;
      } else if (obsPoint.function) {
        obsDisplay = `${obsPoint.function}()`;
      } else if (obsPoint.spec) {
        obsDisplay = obsPoint.spec;
      } else {
        obsDisplay = 'Available';
      }
      if (el.tagHeaderObsPoint) el.tagHeaderObsPoint.style.display = 'inline-flex';
      if (el.txtHeaderObsPoint) el.txtHeaderObsPoint.textContent = obsDisplay;
      if (el.msTxtObsPoint) el.msTxtObsPoint.textContent = obsDisplay;
      if (el.sumObsPoint) el.sumObsPoint.textContent = obsDisplay;
      if (el.inspMutObsPoint) el.inspMutObsPoint.textContent = obsDisplay;
    } else {
      if (el.tagHeaderObsPoint) el.tagHeaderObsPoint.style.display = 'none';
      if (el.msTxtObsPoint) el.msTxtObsPoint.textContent = 'Unavailable';
      if (el.sumObsPoint) el.sumObsPoint.textContent = 'Unavailable';
      if (el.inspMutObsPoint) el.inspMutObsPoint.textContent = 'Unavailable';
    }

    // Checkpoint & Determinism: Capability vs Verification
    const cpRestore = data.checkpoint_restore || {};
    const backendName = cpRestore.backend || branchIso.restore_backend || (threadCount > 1 ? 'RESTART' : 'GDB_CHECKPOINT');
    const semantics = cpRestore.semantics || branchIso.semantics || (backendName === 'RESTART' ? 'RESTART_TO_OBSERVATION_POINT' : 'MEMORY_CHECKPOINT');
    const scope = cpRestore.scope || branchIso.scope || (threadCount > 1 ? 'MULTITHREAD' : 'SINGLE_THREAD');

    // Checkpoint capability
    const cpCap = data.checkpoint_capability !== undefined ? data.checkpoint_capability : (cpRestore.supported !== undefined ? cpRestore.supported : true);
    if (el.sumCheckpointStatus) {
      el.sumCheckpointStatus.innerHTML = `<span class="badge ${cpCap ? 'badge-success' : 'badge-danger'}">${cpCap ? 'Supported' : 'Unavailable'}</span>`;
    }

    // Branch isolation: Capability vs Verification
    const branchIsoCap = data.branch_isolation_capability || (branchIso.capability || (branchIso.status === 'SUPPORTED' ? 'SUPPORTED' : 'UNAVAILABLE'));
    const branchIsoVer = Boolean(data.branch_isolation_verified || branchIso.verified);

    if (el.sumIsolationStatus) {
      let isoBadgeClass = branchIsoVer ? 'badge-success' : (branchIsoCap === 'SUPPORTED' ? 'badge-info' : (branchIsoCap === 'CONDITIONAL' ? 'badge-warning' : 'badge-danger'));
      let isoText = branchIsoCap === 'SUPPORTED' ? (branchIsoVer ? 'Supported (Verified)' : 'Supported (Not verified)') : (branchIsoCap === 'CONDITIONAL' ? 'Conditional' : 'Unavailable');
      el.sumIsolationStatus.innerHTML = `<span class="badge ${isoBadgeClass}" title="${branchIso.reason || ''}">${escapeHtml(isoText)}</span>`;
    }

    // Determinism: Capability vs Verification
    const detCap = data.determinism_capability || (data.determinism && data.determinism.capability) || 'SUPPORTED';
    const detVer = Boolean(data.determinism_verified || (data.determinism && data.determinism.verified));
    const detStatus = cpRestore.determinism_status || branchIso.determinism_status || (detVer ? 'VERIFIED' : 'NOT_VERIFIED');

    if (el.sumDeterminismStatus) {
      let detClass = 'badge-neutral';
      let detText = 'Supported (Not verified)';
      if (detStatus === 'VERIFIED' || detVer) {
        detClass = 'badge-success';
        detText = 'Verified';
      } else if (detStatus === 'FAILED' || detStatus === 'NON_DETERMINISTIC') {
        detClass = 'badge-danger';
        detText = detStatus === 'NON_DETERMINISTIC' ? 'Non-deterministic' : 'Failed';
      } else if (detCap === 'UNSUPPORTED' || detCap === 'UNAVAILABLE') {
        detClass = 'badge-warning';
        detText = 'Unavailable';
      } else if (detCap === 'SUPPORTED') {
        detClass = 'badge-neutral';
        detText = 'Supported (Not verified)';
      }
      el.sumDeterminismStatus.innerHTML = `<span class="badge ${detClass}">${escapeHtml(detText)}</span>`;
    }

    // Inspector mutation backend card
    if (el.inspMutBackend) el.inspMutBackend.textContent = backendName;

    // Tab 1 Hero Badges
    if (el.msBadgeBackend) el.msBadgeBackend.textContent = backendName;
    if (el.msBadgeIsolation) {
      let badgeText = branchIsoCap === 'SUPPORTED' ? (branchIsoVer ? 'SUPPORTED (VERIFIED)' : 'SUPPORTED (NOT VERIFIED)') : branchIsoCap;
      let badgeClass = branchIsoVer ? 'badge-success' : (branchIsoCap === 'SUPPORTED' ? 'badge-info' : (branchIsoCap === 'CONDITIONAL' ? 'badge-warning' : 'badge-danger'));
      el.msBadgeIsolation.textContent = badgeText;
      el.msBadgeIsolation.className = 'badge ' + badgeClass;
    }

    // Render Threads detail table
    renderThreads(data.threads_detail, data.observation_point);

    const branchStatus = branchIso.status || branchIsoCap || 'UNAVAILABLE';

    // Fast Runtime Capture & State Laboratory summary
    if (el.sumCaptureBackend) {
      el.sumCaptureBackend.textContent = data.capture_backend || 'process_vm_readv';
    }
    if (el.statelabBackendBadge) {
      el.statelabBackendBadge.textContent = data.capture_backend || 'process_vm_readv';
    }
    if (data.last_capture_latency_report) {
      const rep = data.last_capture_latency_report;
      state.lastCaptureReport = rep;
      if (el.sumCaptureLatency) {
        el.sumCaptureLatency.textContent = `${(rep.total_stop_time_ms || 0).toFixed(2)} ms`;
      }
      renderCaptureLatencyReport(rep);
    }
    if (data.state_lab_tree) {
      state.stateLabTree = data.state_lab_tree;
      renderStateLabTree(data.state_lab_tree);
    }

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
    if (el.ovStatus) el.ovStatus.textContent = status;
    if (el.ovPid) el.ovPid.textContent = data.pid || 'None';
    if (el.ovThreads) el.ovThreads.textContent = threadCount;
    if (el.ovMode) el.ovMode.innerHTML = `<span class="badge ${mode === 'LOW_IMPACT' ? 'badge-warning' : 'badge-info'}">${mode}</span>`;
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
    if (el.ovBinary) el.ovBinary.textContent = data.executable || 'None';
    if (el.ovDebugImage) el.ovDebugImage.textContent = data.debug_image || 'None';
    if (el.ovDebugStatus) el.ovDebugStatus.innerHTML = `<span class="badge ${data.debug_image_status === 'VERIFIED' ? 'badge-success' : 'badge-neutral'}">${data.debug_image_status || 'NOT_AVAILABLE'}</span>`;

    if (el.ovArch) el.ovArch.textContent = data.architecture || 'UNKNOWN';
    if (el.ovEndian) el.ovEndian.textContent = data.endianness || 'UNKNOWN';
    if (el.ovElf) el.ovElf.textContent = data.elf_class || 'UNKNOWN';
    if (el.ovBuildId) el.ovBuildId.textContent = data.build_id || 'None';
    if (el.ovModulesCount) el.ovModulesCount.textContent = data.module_count || 0;
    if (el.ovCheckpoint) el.ovCheckpoint.textContent = data.current_checkpoint || 'None';

    if (el.ovStatesCount) el.ovStatesCount.textContent = data.state_count || 0;
    if (el.ovTransCount) el.ovTransCount.textContent = data.transition_count || 0;

    const limits = data.safety_limits || {};
    if (el.ovLimits) {
      el.ovLimits.innerHTML = `
        <span class="tag">Max steps: ${limits.max_steps || 50}</span>
        <span class="tag">Timeout: ${limits.max_timeout_ms || 5000}ms</span>
        <span class="tag">Max candidates: ${limits.max_candidates || 50}</span>
        <span class="tag">Max corpus states: ${limits.max_corpus_states || 100}</span>
      `;
    }

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

  // --------------------------------------------------------------------------
  // TAB 1: 3-Pane Object Explorer Workspace (Android Studio / HeapHero Inspired)
  // --------------------------------------------------------------------------

  async function loadObjectsForState(stateId) {
    if (!stateId) return;
    const res = await apiGet(`/api/states/${stateId}/objects`);
    if (!res.success) {
      if (el.listMemoryObjects) {
        el.listMemoryObjects.innerHTML = `<div class="text-muted text-center p-3">${escapeHtml(res.error.message)}</div>`;
      }
      return;
    }

    const objects = res.data || [];
    state.objects = objects;
    state.jsonViewerCache['objects'] = objects;

    // Default expand root nodes in reference tree
    state.expandedTreeNodes.clear();
    objects.slice(0, 5).forEach((o) => {
      state.expandedTreeNodes.add(o.object_id);
    });

    renderMemoryObjectsList();
    if (state.centerView === 'tree') {
      renderReferenceTree();
    } else if (state.centerView === 'table') {
      renderReferenceTable();
    } else if (state.centerView === 'graph') {
      renderObjectTopology();
    }

    if (state.selectedObjectId && objects.some((o) => o.object_id === state.selectedObjectId)) {
      selectObject(state.selectedObjectId);
    } else if (objects.length > 0) {
      selectObject(objects[0].object_id);
    }
  }

  function renderMemoryObjectsList() {
    if (!el.listMemoryObjects) return;
    const objects = state.objects || [];
    const query = (state.searchQuery || '').toLowerCase().trim();
    const groupFilter = state.objectFilterGroup || 'all';

    // 1. Group Filtering
    let filtered = objects.filter((o) => {
      const st = (o.storage || 'unknown').toLowerCase();
      if (groupFilter === 'roots') {
        const isRoot = Boolean(o.root_source) || st === 'global' || st === 'stack' || (o.incoming_count === 0);
        if (!isRoot) return false;
      } else if (groupFilter === 'heap') {
        if (st !== 'heap') return false;
      } else if (groupFilter === 'globals') {
        if (st !== 'global') return false;
      } else if (groupFilter === 'stack') {
        if (st !== 'stack') return false;
      }

      // Search Query
      if (!query) return true;
      const matchesId = (o.object_id || '').toLowerCase().includes(query);
      const matchesSemantic = (o.semantic_name || '').toLowerCase().includes(query);
      const matchesType = (o.type || '').toLowerCase().includes(query);
      const matchesCleaned = (o.cleaned_type || '').toLowerCase().includes(query);
      const matchesField = (o.fields || []).some((f) => {
        return (f.name || '').toLowerCase().includes(query) || String(f.value || '').toLowerCase().includes(query);
      });
      return matchesId || matchesSemantic || matchesType || matchesCleaned || matchesField;
    });

    // 2. Sorting
    const sortMode = state.objectSort || 'name-asc';
    filtered.sort((a, b) => {
      const nameA = a.semantic_name || a.object_id;
      const nameB = b.semantic_name || b.object_id;
      if (sortMode === 'name-asc') return nameA.localeCompare(nameB);
      if (sortMode === 'name-desc') return nameB.localeCompare(nameA);
      if (sortMode === 'type-asc') {
        const typeA = a.cleaned_type || a.type || '';
        const typeB = b.cleaned_type || b.type || '';
        return typeA.localeCompare(typeB);
      }
      if (sortMode === 'fields-desc') {
        const fA = a.field_count !== undefined ? a.field_count : (a.fields ? a.fields.length : 0);
        const fB = b.field_count !== undefined ? b.field_count : (b.fields ? b.fields.length : 0);
        return fB - fA;
      }
      if (sortMode === 'refs-desc') {
        const rA = (a.outgoing_count || 0) + (a.incoming_count || 0);
        const rB = (b.outgoing_count || 0) + (b.incoming_count || 0);
        return rB - rA;
      }
      if (sortMode === 'addr-asc') {
        return (Number(a.address) || 0) - (Number(b.address) || 0);
      }
      return 0;
    });

    if (el.badgeMemObjectsCount) {
      el.badgeMemObjectsCount.textContent = `${filtered.length} / ${objects.length}`;
    }

    if (filtered.length === 0) {
      el.listMemoryObjects.innerHTML = `<div class="text-muted text-center p-3">No matching objects found</div>`;
      return;
    }

    // 3. Render: By Type (Accordion Grouping) vs Flat Card List
    if (groupFilter === 'types') {
      const typeGroups = {};
      filtered.forEach((o) => {
        const t = o.cleaned_type || (o.type ? o.type.replace(/\b(struct|class|enum)\s+/g, '') : 'Unknown');
        if (!typeGroups[t]) typeGroups[t] = [];
        typeGroups[t].push(o);
      });

      let html = '';
      Object.keys(typeGroups).sort().forEach((typeName) => {
        const groupObjs = typeGroups[typeName];
        html += `
          <div class="obj-tree-group">
            <div class="obj-tree-group-header" data-group-type="${escapeHtml(typeName)}">
              <span class="obj-tree-group-title">🏷️ ${escapeHtml(typeName)}</span>
              <span class="obj-tree-group-count">${groupObjs.length} instance${groupObjs.length > 1 ? 's' : ''}</span>
            </div>
            <div class="obj-tree-group-body">
              ${groupObjs.map((o) => renderObjectCardHtml(o)).join('')}
            </div>
          </div>
        `;
      });
      el.listMemoryObjects.innerHTML = html;
    } else {
      el.listMemoryObjects.innerHTML = filtered.map((o) => renderObjectCardHtml(o)).join('');
    }

    // Attach click listeners to cards
    el.listMemoryObjects.querySelectorAll('.object-card-item').forEach((item) => {
      item.addEventListener('click', () => {
        const oid = item.getAttribute('data-object-id');
        selectObject(oid);
      });
    });
  }

  function renderObjectCardHtml(o) {
    const isSelected = o.object_id === state.selectedObjectId;
    const storage = (o.storage || 'unknown').toLowerCase();
    const storageClass = storage === 'heap' ? 'badge-storage-heap' : storage === 'global' ? 'badge-storage-global' : 'badge-storage-stack';
    const fieldCount = o.field_count !== undefined ? o.field_count : ((o.fields && o.fields.length) || 0);
    const outgoingCount = o.outgoing_count !== undefined ? o.outgoing_count : ((o.fields || []).filter((f) => f.object_ref).length);
    const incomingCount = o.incoming_count || 0;

    const semanticName = o.semantic_name || o.object_id;
    const cleanedType = o.cleaned_type || (o.type ? o.type.replace(/\b(struct|class|enum)\s+/g, '') : 'Unknown');

    const advancedIdHtml = state.isAdvancedMode
      ? `<span class="mono text-muted text-xs" style="margin-left: 4px;">[${escapeHtml(o.object_id)}]</span>`
      : '';

    return `
      <div class="object-card-item ${isSelected ? 'selected' : ''}" data-object-id="${o.object_id}">
        <div class="obj-card-top">
          <span class="obj-name-semantic">${escapeHtml(semanticName)}${advancedIdHtml}</span>
          <span class="badge ${storageClass}" style="font-size: 0.65rem;">${storage.toUpperCase()}</span>
        </div>
        <div class="obj-card-meta">
          <span class="obj-type-tag">${escapeHtml(cleanedType)}</span>
        </div>
        <div class="obj-stats-badges">
          <span class="obj-badge">${fieldCount} flds</span>
          ${outgoingCount > 0 ? `<span class="obj-badge" title="${outgoingCount} outgoing references">🔗 ${outgoingCount} out</span>` : ''}
          ${incomingCount > 0 ? `<span class="obj-badge" title="${incomingCount} incoming references">📥 ${incomingCount} in</span>` : ''}
        </div>
      </div>
    `;
  }

  // --------------------------------------------------------------------------
  // Center Pane: Reference Tree & Hierarchy (Android Studio Heap Dump Tree Style)
  // --------------------------------------------------------------------------

  function renderReferenceTree() {
    if (!el.treeReferenceContainer) return;
    const objects = state.objects || [];

    if (objects.length === 0) {
      el.treeReferenceContainer.innerHTML = '<div class="text-muted text-center p-3">No objects available in current snapshot</div>';
      return;
    }

    // Identify Root Objects: globals, stack locals, root_source, or no incoming refs
    let rootObjects = objects.filter((o) => {
      const st = (o.storage || '').toLowerCase();
      return Boolean(o.root_source) || st === 'global' || st === 'stack' || (o.incoming_count === 0);
    });

    if (rootObjects.length === 0) {
      rootObjects = objects;
    }

    let treeHtml = '';
    rootObjects.forEach((rootObj) => {
      treeHtml += renderTreeNodeHtml(rootObj, null, new Set(), 0);
    });

    el.treeReferenceContainer.innerHTML = treeHtml;

    // Attach tree expand/collapse handlers
    el.treeReferenceContainer.querySelectorAll('.tree-expander').forEach((exp) => {
      exp.addEventListener('click', (e) => {
        e.stopPropagation();
        const nodeKey = exp.getAttribute('data-node-key');
        if (state.expandedTreeNodes.has(nodeKey)) {
          state.expandedTreeNodes.delete(nodeKey);
        } else {
          state.expandedTreeNodes.add(nodeKey);
        }
        renderReferenceTree();
      });
    });

    // Attach node row select handlers
    el.treeReferenceContainer.querySelectorAll('.tree-node-row').forEach((row) => {
      row.addEventListener('click', () => {
        const oid = row.getAttribute('data-object-id');
        if (oid) selectObject(oid);
      });
    });
  }

  function renderTreeNodeHtml(obj, viaField, visitedPath, depth) {
    if (!obj) return '';
    const nodeKey = `${obj.object_id}_${depth}`;
    const isExpanded = state.expandedTreeNodes.has(nodeKey) || state.expandedTreeNodes.has(obj.object_id);
    const isSelected = obj.object_id === state.selectedObjectId;

    // Find outgoing reference fields
    const refFields = (obj.fields || []).filter((f) => Boolean(f.object_ref));
    const hasChildren = refFields.length > 0 && !visitedPath.has(obj.object_id) && depth < 8;

    const expanderIcon = hasChildren ? (isExpanded ? '▼' : '▶') : ' ';
    const semanticName = obj.semantic_name || obj.object_id;
    const cleanedType = obj.cleaned_type || (obj.type ? obj.type.replace(/\b(struct|class|enum)\s+/g, '') : 'Unknown');
    const storage = (obj.storage || 'HEAP').toUpperCase();

    const fieldLabelHtml = viaField
      ? `<span class="tree-node-field">${escapeHtml(viaField)}: </span>`
      : '';

    const isCycle = visitedPath.has(obj.object_id);

    let html = `
      <div class="ref-tree-node">
        <div class="tree-node-row ${isSelected ? 'selected' : ''}" data-object-id="${obj.object_id}">
          <span class="tree-expander" data-node-key="${nodeKey}">${expanderIcon}</span>
          <span class="tree-node-icon">${depth === 0 ? '📦' : '🔗'}</span>
          ${fieldLabelHtml}
          <span class="tree-node-label">${escapeHtml(semanticName)}</span>
          <span class="tree-node-type">(${escapeHtml(cleanedType)})</span>
          ${isCycle ? '<span class="badge badge-warning text-xs">cyclic</span>' : ''}
          <span class="tree-node-badge">${storage}</span>
        </div>
    `;

    if (hasChildren && isExpanded) {
      const nextVisited = new Set(visitedPath);
      nextVisited.add(obj.object_id);

      html += `<div class="ref-tree-children">`;
      refFields.forEach((rf) => {
        const childObj = state.objects.find((candidate) => candidate.object_id === rf.object_ref);
        if (childObj) {
          html += renderTreeNodeHtml(childObj, rf.name, nextVisited, depth + 1);
        } else {
          html += `
            <div class="tree-node-row" style="opacity: 0.7;">
              <span class="tree-expander"> </span>
              <span class="tree-node-icon">🔗</span>
              <span class="tree-node-field">${escapeHtml(rf.name)}: </span>
              <span class="tree-node-label mono text-muted">${escapeHtml(rf.object_ref)}</span>
              <span class="text-muted text-xs">(External reference)</span>
            </div>
          `;
        }
      });
      html += `</div>`;
    }

    html += `</div>`;
    return html;
  }

  // --------------------------------------------------------------------------
  // Center Pane: Reference Table View
  // --------------------------------------------------------------------------

  function renderReferenceTable() {
    if (!el.tbodyObjectsSummary) return;
    const objects = state.objects || [];

    if (objects.length === 0) {
      el.tbodyObjectsSummary.innerHTML = `<tr><td colspan="7" class="text-muted text-center p-3">No objects available in current snapshot</td></tr>`;
      return;
    }

    let rowsHtml = '';
    objects.forEach((o) => {
      const isSelected = o.object_id === state.selectedObjectId;
      const storage = (o.storage || 'UNKNOWN').toUpperCase();
      const storageClass = storage === 'HEAP' ? 'badge-storage-heap' : storage === 'GLOBAL' ? 'badge-storage-global' : 'badge-storage-stack';
      const fieldCount = o.field_count !== undefined ? o.field_count : ((o.fields && o.fields.length) || 0);
      const outgoingCount = o.outgoing_count !== undefined ? o.outgoing_count : ((o.fields || []).filter((f) => f.object_ref).length);
      const incomingCount = o.incoming_count || 0;

      const semanticName = o.semantic_name || o.object_id;
      const cleanedType = o.cleaned_type || (o.type ? o.type.replace(/\b(struct|class|enum)\s+/g, '') : 'Unknown');

      rowsHtml += `
        <tr class="${isSelected ? 'selected' : ''}">
          <td class="mono font-semibold text-accent">${escapeHtml(semanticName)}</td>
          <td class="mono">${escapeHtml(cleanedType)}</td>
          <td><span class="badge ${storageClass}">${storage}</span></td>
          <td class="mono">${fieldCount}</td>
          <td class="mono">${outgoingCount > 0 ? `🔗 ${outgoingCount}` : '0'}</td>
          <td class="mono">${incomingCount > 0 ? `📥 ${incomingCount}` : '0'}</td>
          <td>
            <button class="btn btn-sm btn-secondary btn-table-inspect" data-object-id="${o.object_id}">Inspect →</button>
          </td>
        </tr>
      `;
    });

    el.tbodyObjectsSummary.innerHTML = rowsHtml;

    el.tbodyObjectsSummary.querySelectorAll('.btn-table-inspect').forEach((btn) => {
      btn.addEventListener('click', () => {
        const oid = btn.getAttribute('data-object-id');
        selectObject(oid);
      });
    });
  }

  // --------------------------------------------------------------------------
  // Right Pane: Object Inspector & Reference Navigation
  // --------------------------------------------------------------------------

  function selectObject(objectId) {
    if (!objectId) return;
    state.selectedObjectId = objectId;

    // 1. Highlight in list & table
    if (el.listMemoryObjects) {
      el.listMemoryObjects.querySelectorAll('.object-card-item').forEach((item) => {
        item.classList.toggle('selected', item.getAttribute('data-object-id') === objectId);
      });
    }

    if (el.tbodyObjectsSummary) {
      el.tbodyObjectsSummary.querySelectorAll('tr').forEach((tr) => {
        const btn = tr.querySelector('.btn-table-inspect');
        const isSel = btn && btn.getAttribute('data-object-id') === objectId;
        tr.classList.toggle('selected', isSel);
      });
    }

    // Highlight in Reference Tree
    if (el.treeReferenceContainer) {
      el.treeReferenceContainer.querySelectorAll('.tree-node-row').forEach((row) => {
        row.classList.toggle('selected', row.getAttribute('data-object-id') === objectId);
      });
    }

    const obj = state.objects.find((o) => o.object_id === objectId);
    if (!obj) return;
    state.jsonViewerCache[`object_${objectId}`] = obj;

    const storage = (obj.storage || 'UNKNOWN').toUpperCase();
    const storageClass = storage === 'HEAP' ? 'badge-storage-heap' : storage === 'GLOBAL' ? 'badge-storage-global' : 'badge-storage-stack';
    const addrHex = obj.address ? '0x' + Number(obj.address).toString(16) : 'N/A';
    const semanticName = obj.primary_path || obj.semantic_path || obj.semantic_name || obj.object_id;
    const additionalPaths = obj.additional_paths || [];
    const cleanedType = obj.cleaned_type || obj.canonical_type || (obj.type ? obj.type.replace(/\b(struct|class|enum)\s+/g, '') : 'Unknown');

    // 2. Update Center Breadcrumb
    if (el.bcCurrentName) {
      el.bcCurrentName.textContent = `${semanticName} (${cleanedType})`;
    }

    // 3. Populate Inspector Header
    if (el.memObjTitle) el.memObjTitle.textContent = `${semanticName} — ${cleanedType}`;
    if (el.memObjSubtitle) {
      let sub = state.isAdvancedMode
        ? `[${obj.object_id}] ${storage} memory object located at ${addrHex}`
        : `${storage} memory object · ${obj.root_source || 'Application Root'}`;
      if (additionalPaths.length > 0) {
        sub += ` · Also referenced as: ${additionalPaths.join(', ')}`;
      }
      el.memObjSubtitle.textContent = sub;
    }
    if (el.memObjTypeBadge) el.memObjTypeBadge.textContent = cleanedType;
    if (el.memObjStorageBadge) {
      el.memObjStorageBadge.textContent = storage;
      el.memObjStorageBadge.className = 'badge ' + storageClass;
    }

    // 4. Identity & Scope Details
    if (el.inspValName) el.inspValName.textContent = semanticName;
    if (el.inspValType) el.inspValType.textContent = cleanedType;
    if (el.inspValStorage) {
      el.inspValStorage.textContent = storage;
      el.inspValStorage.className = 'badge ' + storageClass;
    }
    const semStatus = (obj.semantic_status || (obj.synthetic ? 'SYNTHETIC' : (obj.status === 'PARTIAL' ? 'PARTIAL' : (obj.status === 'UNRESOLVED' ? 'UNRESOLVED' : 'REAL')))).toUpperCase();
    if (el.inspValStatus) {
      el.inspValStatus.textContent = semStatus;
      el.inspValStatus.className = 'badge ' + (
        semStatus === 'REAL' ? 'badge-storage-global' :
        semStatus === 'PARTIAL' ? 'badge-storage-heap' :
        semStatus === 'SYNTHETIC' ? 'badge-storage-stack' : 'badge-storage-stack'
      );
    }
    if (el.inspValRoot) el.inspValRoot.textContent = obj.root_source || (storage === 'GLOBAL' ? 'Global Variable' : storage === 'STACK' ? 'Stack Local' : 'Heap Allocated');
    if (el.inspValThread) el.inspValThread.textContent = obj.thread_name || (state.runtime && state.runtime.threads ? `${state.runtime.threads} Thread(s)` : 'N/A');

    if (el.memTechId) el.memTechId.textContent = obj.object_id;
    if (el.memTechAddr) el.memTechAddr.textContent = addrHex;
    if (el.memTechDwarf) el.memTechDwarf.textContent = obj.dwarf_type || obj.type || '—';
    if (el.memTechRange) {
      const mr = obj.memory_range || (obj.provenance && obj.provenance.memory_range);
      el.memTechRange.textContent = Array.isArray(mr) && mr.length >= 2 ? `${mr[0]} - ${mr[1]}` : (addrHex !== 'N/A' ? `${addrHex} (+${obj.size || 0}B)` : '—');
    }
    if (el.memTechBuildId) {
      const bid = obj.build_id || (obj.provenance && obj.provenance.build_id);
      el.memTechBuildId.textContent = bid || '—';
    }
    if (el.memTechStorage) el.memTechStorage.textContent = storage;
    if (el.memTechType) el.memTechType.textContent = obj.type || 'Unknown';

    // 5. Fields Table
    const fields = obj.fields || [];
    if (el.inspFieldsCount) el.inspFieldsCount.textContent = `${fields.length} field${fields.length !== 1 ? 's' : ''}`;

    if (fields.length === 0) {
      if (el.tableSemanticFields) {
        el.tableSemanticFields.innerHTML = `<tr><td colspan="6" class="text-muted text-center">No fields defined for this object</td></tr>`;
      }
    } else {
      let fieldsHtml = '';
      fields.forEach((f) => {
        const isRef = Boolean(f.object_ref);
        const mutStatus = normalizeMutability(f.mutability);
        const isMut = mutStatus === 'mutable' || isFieldMutable(f.type, f.mutability);
        const valHtml = formatSemanticValue(f.value, f.type, f.object_ref);
        const cleanedFieldType = f.cleaned_type || (f.type ? f.type.replace(/\b(struct|class|enum)\s+/g, '') : '');

        let refChipHtml = '<span class="text-muted">—</span>';
        if (isRef) {
          const targetObj = state.objects.find((target) => target.object_id === f.object_ref);
          const targetName = targetObj ? (targetObj.semantic_name || targetObj.cleaned_type || targetObj.type) : f.object_ref;
          refChipHtml = `
            <button class="ref-chip outgoing-chip" data-ref-id="${f.object_ref}" title="Jump to referenced object">
              <span class="ref-chip-field">🔗</span> <span class="ref-chip-target">${escapeHtml(targetName)}</span>
            </button>
          `;
        }

        const mutBadgeHtml = isMut
          ? '<span class="badge badge-success">MUTABLE</span>'
          : '<span class="badge badge-neutral">READ_ONLY</span>';

        fieldsHtml += `
          <tr>
            <td><strong>${escapeHtml(f.name)}</strong></td>
            <td class="mono text-accent">${escapeHtml(cleanedFieldType)}</td>
            <td>${valHtml}</td>
            <td>${refChipHtml}</td>
            <td>${mutBadgeHtml}</td>
            <td>
              ${isMut ? `<button class="field-mutate-btn" data-object-id="${objectId}" data-field-name="${f.name}">⚡ Mutate</button>` : '<span class="text-muted">—</span>'}
            </td>
          </tr>
        `;
      });
      if (el.tableSemanticFields) el.tableSemanticFields.innerHTML = fieldsHtml;

      // Pointer chip jump handlers
      if (el.tableSemanticFields) {
        el.tableSemanticFields.querySelectorAll('.ref-chip').forEach((btn) => {
          btn.addEventListener('click', (e) => {
            e.preventDefault();
            const refId = btn.getAttribute('data-ref-id');
            jumpToObject(refId);
          });
        });

        // Field Mutate inline button handlers
        el.tableSemanticFields.querySelectorAll('.field-mutate-btn').forEach((btn) => {
          btn.addEventListener('click', () => {
            const fldName = btn.getAttribute('data-field-name');
            const targetField = fields.find((f) => f.name === fldName);
            if (targetField) {
              populateIntegratedMutation(obj, targetField);
            }
          });
        });
      }
    }

    // 6. Reference Relations (HeapHero / Android Studio Incoming & Outgoing)
    // Outgoing References (this points to other objects)
    const outgoingRefs = obj.outgoing_references || [];
    const directOutgoing = outgoingRefs.length > 0 ? outgoingRefs : (fields.filter((f) => f.object_ref).map((f) => ({
      field: f.name,
      target_id: f.object_ref,
      type: f.cleaned_type || f.type
    })));

    if (el.badgeOutgoingCount) el.badgeOutgoingCount.textContent = `(${directOutgoing.length})`;

    if (el.inspectorOutgoingRefs) {
      if (directOutgoing.length === 0) {
        el.inspectorOutgoingRefs.innerHTML = '<span class="text-muted text-xs">No outgoing references</span>';
      } else {
        let outHtml = '';
        directOutgoing.forEach((ref) => {
          const targetObj = state.objects.find((o) => o.object_id === ref.target_id);
          const targetName = targetObj ? (targetObj.semantic_name || targetObj.cleaned_type || targetObj.object_id) : ref.target_id;
          outHtml += `
            <button class="ref-chip outgoing-chip" data-nav-id="${ref.target_id}" title="Click to inspect ${escapeHtml(targetName)}">
              <span class="ref-chip-field">${escapeHtml(ref.field)} ➔</span>
              <span class="ref-chip-target">${escapeHtml(targetName)}</span>
            </button>
          `;
        });
        el.inspectorOutgoingRefs.innerHTML = outHtml;

        el.inspectorOutgoingRefs.querySelectorAll('.ref-chip').forEach((chip) => {
          chip.addEventListener('click', () => {
            const navId = chip.getAttribute('data-nav-id');
            jumpToObject(navId);
          });
        });
      }
    }

    // Incoming References (other objects point to this)
    let incomingRefs = obj.incoming_references || [];
    if (incomingRefs.length === 0) {
      // Compute from state objects
      state.objects.forEach((srcObj) => {
        (srcObj.fields || []).forEach((f) => {
          if (f.object_ref === objectId) {
            incomingRefs.push({
              source_id: srcObj.object_id,
              semantic_name: srcObj.semantic_name,
              field: f.name,
              type: srcObj.cleaned_type || srcObj.type
            });
          }
        });
      });
    }

    if (el.badgeIncomingCount) el.badgeIncomingCount.textContent = `(${incomingRefs.length})`;

    if (el.inspectorIncomingRefs) {
      if (incomingRefs.length === 0) {
        el.inspectorIncomingRefs.innerHTML = '<span class="text-muted text-xs">No incoming references (Root / Unreferenced)</span>';
      } else {
        let inHtml = '';
        incomingRefs.forEach((ref) => {
          const srcObj = state.objects.find((o) => o.object_id === ref.source_id);
          const srcName = srcObj ? (srcObj.semantic_name || srcObj.cleaned_type || srcObj.object_id) : (ref.semantic_name || ref.source_id);
          inHtml += `
            <button class="ref-chip incoming-chip" data-nav-id="${ref.source_id}" title="Referenced by ${escapeHtml(srcName)}.${escapeHtml(ref.field)}">
              <span class="ref-chip-target">${escapeHtml(srcName)}</span>
              <span class="ref-chip-field">.${escapeHtml(ref.field)} ➔</span>
            </button>
          `;
        });
        el.inspectorIncomingRefs.innerHTML = inHtml;

        el.inspectorIncomingRefs.querySelectorAll('.ref-chip').forEach((chip) => {
          chip.addEventListener('click', () => {
            const navId = chip.getAttribute('data-nav-id');
            jumpToObject(navId);
          });
        });
      }
    }

    if (el.badgeTotalRefsCount) {
      const totalRefs = directOutgoing.length + incomingRefs.length;
      el.badgeTotalRefsCount.textContent = `${totalRefs} reference${totalRefs !== 1 ? 's' : ''}`;
    }

    // 7. Populate Integrated Field Mutation Card
    const firstMutable = fields.find((f) => {
      const mutStatus = normalizeMutability(f.mutability);
      return mutStatus === 'mutable' || isFieldMutable(f.type, f.mutability);
    });
    populateIntegratedMutation(obj, firstMutable || null);

    // 8. State Context
    if (el.inspStateId) el.inspStateId.textContent = state.selectedStateId || 'N/A';
    if (el.inspParentStateId) {
      const curState = state.states.find((s) => s.state_id === state.selectedStateId);
      el.inspParentStateId.textContent = (curState && curState.parent_state) || (curState && curState.metadata && curState.metadata.parent_state_id) || 'None (Seed)';
    }
    if (el.inspStateHash) {
      const curState = state.states.find((s) => s.state_id === state.selectedStateId);
      el.inspStateHash.textContent = (curState && curState.state_hash) || 'UNKNOWN';
    }
  }

  function populateIntegratedMutation(obj, targetField) {
    if (!el.cardIntegratedMutation) return;

    if (!targetField) {
      if (el.inspMutTargetLabel) el.inspMutTargetLabel.textContent = 'No mutable fields available';
      if (el.inspMutCurrentVal) el.inspMutCurrentVal.textContent = '—';
      if (el.inspMutInputContainer) {
        el.inspMutInputContainer.innerHTML = '<input type="text" class="input-text input-text-sm mono" disabled placeholder="Read-only object">';
      }
      if (el.btnInspRunMutation) el.btnInspRunMutation.disabled = true;
      if (el.inspMutBadge) {
        el.inspMutBadge.textContent = 'READ_ONLY';
        el.inspMutBadge.className = 'badge badge-neutral';
      }
      state.currentMutableField = null;
      return;
    }

    state.currentMutableField = { object: obj, field: targetField };

    const targetBase = obj.primary_path || obj.semantic_path || obj.semantic_name || obj.object_id;
    const semanticLabel = `${targetBase}.${targetField.name}`;
    if (el.inspMutTargetLabel) el.inspMutTargetLabel.textContent = semanticLabel;
    if (el.inspMutCurrentVal) el.inspMutCurrentVal.textContent = String(targetField.value);
    if (el.btnInspRunMutation) el.btnInspRunMutation.disabled = false;
    if (el.inspMutBadge) {
      el.inspMutBadge.textContent = 'MUTABLE';
      el.inspMutBadge.className = 'badge badge-success';
    }

    // Type-Aware Input Box
    const rawType = (targetField.type || '').toLowerCase();
    const curVal = targetField.value;
    let inputHtml = '';

    if (rawType.includes('bool')) {
      const isCurTrue = curVal === true || curVal === 'true' || curVal === 1 || curVal === '1';
      inputHtml = `
        <select id="insp-mut-new-val" class="input-select input-select-sm" style="width: 100%; font-weight: 600;">
          <option value="true" ${!isCurTrue ? 'selected' : ''}>true</option>
          <option value="false" ${isCurTrue ? 'selected' : ''}>false</option>
        </select>
      `;
    } else if (rawType.includes('int') || rawType.includes('short') || rawType.includes('long') || rawType.includes('size_t')) {
      const nextVal = Number.isInteger(Number(curVal)) ? Number(curVal) + 1 : 1;
      inputHtml = `
        <input type="number" id="insp-mut-new-val" class="input-text input-text-sm mono" style="width: 100%; font-weight: 600;" value="${escapeHtml(String(nextVal))}">
      `;
    } else if (rawType.includes('float') || rawType.includes('double')) {
      const nextVal = (Number(curVal) || 0) + 1.0;
      inputHtml = `
        <input type="number" step="any" id="insp-mut-new-val" class="input-text input-text-sm mono" style="width: 100%; font-weight: 600;" value="${escapeHtml(String(nextVal))}">
      `;
    } else {
      inputHtml = `
        <input type="text" id="insp-mut-new-val" class="input-text input-text-sm mono" style="width: 100%; font-weight: 600;" value="${escapeHtml(String(curVal))}">
      `;
    }

    if (el.inspMutInputContainer) el.inspMutInputContainer.innerHTML = inputHtml;

    // Environmental details
    const branchIso = state.runtime ? (state.runtime.branch_isolation || {}) : {};
    const backendName = branchIso.restore_backend || 'RESTART';
    if (el.inspMutBackend) el.inspMutBackend.textContent = backendName;

    const obsPoint = state.runtime ? state.runtime.observation_point : null;
    const obsText = obsPoint ? (obsPoint.location || obsPoint.spec || (obsPoint.function ? `${obsPoint.function}()` : 'Breakpoint Active')) : 'Not available';
    if (el.inspMutObsPoint) el.inspMutObsPoint.textContent = obsText;
  }

  function jumpToObject(objectId) {
    if (!objectId) return;
    selectObject(objectId);

    const listItem = el.listMemoryObjects ? el.listMemoryObjects.querySelector(`[data-object-id="${objectId}"]`) : null;
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
      const semanticTarget = c.semantic_target || (c.semantic_name ? `${c.semantic_name}.${c.field}` : `${c.object_id}.${c.field}`);
      const cleanedType = c.cleaned_type || (c.type ? c.type.replace(/\b(struct|class|enum)\s+/g, '') : '');
      const rawIdDisplay = state.isAdvancedMode
        ? `<div class="mono text-muted" style="font-size: 0.75rem;">[${escapeHtml(c.candidate_id)}] ${escapeHtml(c.object_id)}</div>`
        : '';

      html += `
        <tr>
          <td class="mono font-semibold text-accent">
            ${escapeHtml(semanticTarget)}
            ${rawIdDisplay}
          </td>
          <td class="mono">${escapeHtml(c.object_id)}</td>
          <td><strong>${escapeHtml(c.field)}</strong></td>
          <td class="mono">${escapeHtml(String(c.current_value))}</td>
          <td class="mono text-success"><strong>${escapeHtml(String(c.proposed_value))}</strong></td>
          <td class="mono">${escapeHtml(cleanedType)}</td>
          <td><span class="tag">${escapeHtml(c.reason || 'candidate')}</span></td>
          <td><span class="badge ${c.supported ? 'badge-success' : 'badge-neutral'}">${c.supported ? 'YES' : 'NO'}</span></td>
          <td>
            <button class="btn btn-primary btn-sm btn-preview-mutation" data-candidate-id="${c.candidate_id}" ${isLowImpact ? 'disabled title="Disabled in LOW_IMPACT"' : ''}>
              ⚡ Preview & Mutate
            </button>
          </td>
        </tr>
      `;
    });
    el.tableCandidates.innerHTML = html;

    el.tableCandidates.querySelectorAll('.btn-preview-mutation').forEach((btn) => {
      btn.addEventListener('click', () => {
        const candId = btn.getAttribute('data-candidate-id');
        const cand = state.candidates.find((c) => c.candidate_id === candId);
        if (cand) {
          openMutationPreview(cand);
        }
      });
    });
  }

  // --------------------------------------------------------------------------
  // Mutation Preview & Execution Modal
  // --------------------------------------------------------------------------

  function openMutationPreview(target) {
    state.currentMutationTarget = target;

    const storage = (target.storage || 'HEAP').toUpperCase();
    const storageClass = storage === 'HEAP' ? 'badge-storage-heap' : storage === 'GLOBAL' ? 'badge-storage-global' : 'badge-storage-stack';
    if (el.prevTargetStorage) {
      el.prevTargetStorage.textContent = storage;
      el.prevTargetStorage.className = 'badge ' + storageClass;
    }

    if (el.prevTargetMutability) {
      el.prevTargetMutability.textContent = target.mutability || 'MUTABLE';
      el.prevTargetMutability.className = 'badge ' + (target.mutability === 'READ_ONLY' ? 'badge-neutral' : 'badge-success');
    }

    if (el.prevTargetRawId) {
      if (state.isAdvancedMode) {
        el.prevTargetRawId.style.display = 'inline-block';
        el.prevTargetRawId.textContent = target.object_id + (target.field ? `.${target.field}` : '');
      } else {
        el.prevTargetRawId.style.display = 'none';
      }
    }

    const semanticTitle = target.semantic_target || (target.semantic_name ? `${target.semantic_name}.${target.field}` : `${target.object_id}.${target.field}`);
    if (el.prevTargetSemantic) el.prevTargetSemantic.textContent = semanticTitle;

    const cleanedType = target.cleaned_type || (target.type ? target.type.replace(/\b(struct|class|enum)\s+/g, '') : 'Unknown');
    if (el.prevTargetType) el.prevTargetType.textContent = `Type: ${cleanedType}`;

    const curVal = target.current_value !== undefined ? target.current_value : (target.value !== undefined ? target.value : 'N/A');
    if (el.prevCurrentValue) el.prevCurrentValue.textContent = String(curVal);

    // Build Type-Aware Input Container
    const rawType = (target.type || '').toLowerCase();
    let inputHtml = '';
    if (rawType.includes('bool')) {
      const isCurTrue = curVal === true || curVal === 'true' || curVal === 1 || curVal === '1';
      inputHtml = `
        <select id="prev-proposed-value" class="input-select" style="width: 100%; padding: 8px 12px; font-weight: 600;">
          <option value="true" ${!isCurTrue ? 'selected' : ''}>true (TRUE)</option>
          <option value="false" ${isCurTrue ? 'selected' : ''}>false (FALSE)</option>
        </select>
      `;
    } else if (rawType.includes('int') || rawType.includes('short') || rawType.includes('long') || rawType.includes('size_t')) {
      let nextVal = target.proposed_value !== undefined ? target.proposed_value : (Number.isInteger(Number(curVal)) ? Number(curVal) + 1 : 1);
      inputHtml = `
        <input type="number" id="prev-proposed-value" class="input-text mono" required style="width: 100%; padding: 8px 12px; font-weight: 600;" value="${escapeHtml(String(nextVal))}">
      `;
    } else if (rawType.includes('float') || rawType.includes('double')) {
      let nextVal = target.proposed_value !== undefined ? target.proposed_value : (Number(curVal) || 0) + 1.0;
      inputHtml = `
        <input type="number" step="any" id="prev-proposed-value" class="input-text mono" required style="width: 100%; padding: 8px 12px; font-weight: 600;" value="${escapeHtml(String(nextVal))}">
      `;
    } else {
      let nextVal = target.proposed_value !== undefined ? target.proposed_value : '';
      inputHtml = `
        <input type="text" id="prev-proposed-value" class="input-text mono" required style="width: 100%; padding: 8px 12px; font-weight: 600;" value="${escapeHtml(String(nextVal))}">
      `;
    }
    if (el.prevInputContainer) el.prevInputContainer.innerHTML = inputHtml;

    // Execution & Isolation Context
    const obsPoint = state.runtime ? state.runtime.observation_point : null;
    let obsText = 'Unavailable';
    if (obsPoint) {
      if (obsPoint.location) {
        obsText = obsPoint.function ? `${obsPoint.function} @ ${obsPoint.location}` : obsPoint.location;
      } else if (obsPoint.function) {
        obsText = `${obsPoint.function}()`;
      } else if (obsPoint.spec) {
        obsText = obsPoint.spec;
      }
    }
    if (el.prevObsPoint) el.prevObsPoint.textContent = obsText;

    const cpRestore = state.runtime ? (state.runtime.checkpoint_restore || {}) : {};
    const branchIso = state.runtime ? (state.runtime.branch_isolation || {}) : {};
    const threads = state.runtime ? (state.runtime.threads || 1) : 1;
    const backendName = cpRestore.backend || branchIso.restore_backend || (threads > 1 ? 'RESTART' : 'GDB_CHECKPOINT');
    if (el.prevRestoreBackend) el.prevRestoreBackend.textContent = `${backendName} (${backendName === 'RESTART' ? 'RestartBasedRestorer' : 'NativeCheckpointRestorer'})`;

    const isoCap = (state.runtime && state.runtime.branch_isolation_capability) || branchIso.capability || branchIso.status || 'UNAVAILABLE';
    const isIsoVerified = Boolean(state.runtime && (state.runtime.branch_isolation_verified || branchIso.verified));
    if (el.prevBranchIsolation) {
      let isoText = isoCap === 'SUPPORTED' ? (isIsoVerified ? 'Supported (Verified)' : 'Supported (Not verified)') : (isoCap === 'CONDITIONAL' ? 'Conditional' : 'Unavailable');
      el.prevBranchIsolation.textContent = isoText;
      el.prevBranchIsolation.className = 'badge ' + (isIsoVerified ? 'badge-success' : (isoCap === 'SUPPORTED' ? 'badge-info' : 'badge-warning'));
    }

    if (el.prevTimeoutSelect) el.prevTimeoutSelect.value = String(state.globalTimeoutMs || 1000);
    if (el.modalMutationPreview) el.modalMutationPreview.style.display = 'flex';
  }

  function initMutationPreview() {
    if (!el.modalMutationPreview) return;

    if (el.btnCloseMutationModal) {
      el.btnCloseMutationModal.addEventListener('click', () => {
        el.modalMutationPreview.style.display = 'none';
      });
    }
    if (el.btnCancelMutation) {
      el.btnCancelMutation.addEventListener('click', () => {
        el.modalMutationPreview.style.display = 'none';
      });
    }

    if (el.prevTimeoutSelect) {
      el.prevTimeoutSelect.addEventListener('change', (e) => {
        state.globalTimeoutMs = parseInt(e.target.value, 10) || 1000;
        state.userCustomizedTimeout = true;
        if (el.selectGlobalTimeout) el.selectGlobalTimeout.value = String(state.globalTimeoutMs);
      });
    }

    if (el.formMutationPreview) {
      el.formMutationPreview.addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = state.currentMutationTarget;
        if (!target) return;

        const valInput = document.getElementById('prev-proposed-value');
        if (!valInput) return;

        let inputVal = valInput.value;
        const rawType = (target.type || '').toLowerCase();
        if (rawType.includes('bool')) {
          inputVal = inputVal === 'true' || inputVal === '1';
        } else if (rawType.includes('int') || rawType.includes('short') || rawType.includes('long') || rawType.includes('size_t')) {
          inputVal = parseInt(inputVal, 10);
        } else if (rawType.includes('float') || rawType.includes('double')) {
          inputVal = parseFloat(inputVal);
        }

        const timeoutMs = parseInt(el.prevTimeoutSelect.value, 10) || state.globalTimeoutMs || 1000;
        state.globalTimeoutMs = timeoutMs;
        state.userCustomizedTimeout = true;
        if (el.selectGlobalTimeout) el.selectGlobalTimeout.value = String(timeoutMs);

        el.modalMutationPreview.style.display = 'none';

        await executeTransitionWithParams({
          candidate_id: target.candidate_id,
          object_id: target.object_id,
          field: target.field,
          proposed_value: inputVal,
          current_value: target.current_value,
          semantic_target: target.semantic_target || (target.semantic_name ? `${target.semantic_name}.${target.field}` : `${target.object_id}.${target.field}`),
          timeout_ms: timeoutMs,
        });
      });
    }
  }

  async function executeTransitionWithParams(params) {
    const semanticName = params.semantic_target || `${params.object_id || ''}.${params.field || ''}`;
    const effectiveTimeout = params.timeout_ms || state.globalTimeoutMs || 1000;
    showToast(`Executing mutation on ${semanticName} (${effectiveTimeout}ms)...`, 'info');

    const payload = {
      timeout_ms: effectiveTimeout,
    };
    if (params.candidate_id) {
      payload.candidate_id = params.candidate_id;
      if (params.proposed_value !== undefined) {
        payload.proposed_value = params.proposed_value;
      }
    } else {
      payload.candidate = {
        object_id: params.object_id,
        field: params.field,
        proposed_value: params.proposed_value,
        current_value: params.current_value,
      };
    }

    const res = await apiPost('/api/mutation', payload);
    if (!res.success) {
      showToast(`Mutation failed: ${res.error ? res.error.message : 'Unknown error'}`, 'error');
      return;
    }

    const trans = res.data;
    state.jsonViewerCache['last_transition'] = trans;
    showToast('Mutation executed & state verified successfully!', 'success');

    // Display execution result flow & timeline
    renderExecutionResult(trans, params);
    if (el.cardExecutionResult) {
      el.cardExecutionResult.style.display = 'block';
      el.cardExecutionResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Refresh states and select child state if produced
    await loadStatesAndGraph();
    if (trans.child_state) {
      await selectState(trans.child_state);
    }
  }

  async function executeTransition(candidateId) {
    const cand = (state.candidates || []).find((c) => c.candidate_id === candidateId);
    if (cand) {
      openMutationPreview(cand);
    } else {
      await executeTransitionWithParams({ candidate_id: candidateId, timeout_ms: state.globalTimeoutMs });
    }
  }

  function renderExecutionResult(trans, mutationParams) {
    if (!el.cardExecutionResult) return;
    el.cardExecutionResult.style.display = 'block';

    const execStatus = (trans.execution && trans.execution.status) || 'STOPPED';
    const restoreBackend = trans.restore_backend || (state.runtime && state.runtime.branch_isolation && state.runtime.branch_isolation.restore_backend) || 'RESTART';
    const stepDuration = trans.execution && trans.execution.step_duration_ms !== undefined ? `${trans.execution.step_duration_ms} ms` : (trans.timeout_ms ? `${trans.timeout_ms} ms` : 'N/A');

    if (el.execTransId) el.execTransId.textContent = trans.transition_id || 'Transition Completed';
    if (el.execStatusText) el.execStatusText.textContent = execStatus;
    if (el.execStatusBadge) {
      el.execStatusBadge.textContent = execStatus;
      el.execStatusBadge.className = 'badge ' + (execStatus === 'CRASHED' ? 'badge-danger' : execStatus === 'TIMEOUT' ? 'badge-warning' : 'badge-success');
    }
    if (el.execRestoreBackend) el.execRestoreBackend.textContent = restoreBackend;
    if (el.execStepDuration) el.execStepDuration.textContent = stepDuration;

    const childHash = trans.child_state_hash || trans.state_hash || 'N/A';
    if (el.execChildHashBox) el.execChildHashBox.textContent = childHash.substring(0, 16) + '...';

    // 1. Render 3-Card Flow
    const parentId = trans.parent_state || (state.selectedStateId || 'Seed State');
    const parentHash = trans.parent_state_hash ? trans.parent_state_hash.substring(0, 8) + '...' : 'seed';
    const childId = trans.child_state || 'child_state';
    const childHashShort = childHash ? childHash.substring(0, 8) + '...' : 'N/A';

    const mut = trans.mutation || {};
    const fieldName = mut.field || (mutationParams ? mutationParams.field : 'field');
    const oldVal = mut.before !== undefined ? mut.before : (mutationParams && mutationParams.current_value !== undefined ? mutationParams.current_value : 'prior');
    const newVal = mut.value !== undefined ? mut.value : (mut.after !== undefined ? mut.after : (mutationParams && mutationParams.proposed_value !== undefined ? mutationParams.proposed_value : 'new'));
    const targetLabel = mutationParams && mutationParams.semantic_target ? mutationParams.semantic_target : (mut.object_id ? `${mut.object_id}.${fieldName}` : fieldName);

    if (el.flowParentId) el.flowParentId.textContent = parentId;
    if (el.flowParentHash) el.flowParentHash.textContent = `hash: ${parentHash}`;
    if (el.flowParentVal) el.flowParentVal.textContent = `${fieldName} = ${oldVal}`;

    if (el.flowMutationLabel) el.flowMutationLabel.textContent = `${targetLabel}: ${oldVal} ➔ ${newVal}`;
    if (el.flowArrowMeta) el.flowArrowMeta.textContent = `Backend: ${restoreBackend} · Duration: ${stepDuration}`;

    if (el.flowChildId) el.flowChildId.textContent = childId;
    if (el.flowChildHash) el.flowChildHash.textContent = `hash: ${childHashShort}`;
    if (el.flowChildVal) el.flowChildVal.textContent = `${fieldName} = ${newVal}`;

    // 2. Render Verified Execution Timeline (Strictly honest provenance)
    if (el.execTimelineList) {
      const obsPointObj = state.runtime ? state.runtime.observation_point : null;
      let obsPointLoc = 'Unavailable';
      if (obsPointObj) {
        if (obsPointObj.location) {
          obsPointLoc = obsPointObj.function ? `${obsPointObj.function} @ ${obsPointObj.location}` : obsPointObj.location;
        } else if (obsPointObj.function) {
          obsPointLoc = `${obsPointObj.function}()`;
        } else if (obsPointObj.spec) {
          obsPointLoc = obsPointObj.spec;
        }
      }

      const branchIsoObj = trans.branch_isolation || (state.runtime && state.runtime.branch_isolation) || {};
      const isIsoVerified = Boolean(trans.branch_isolation_verified || branchIsoObj.verified);
      const isIsoSupported = (trans.branch_isolation_capability || branchIsoObj.capability || branchIsoObj.status) === 'SUPPORTED';

      const detObj = trans.determinism || (state.runtime && state.runtime.determinism) || {};
      const isDetVerified = Boolean(trans.determinism_verified || detObj.verified);
      const isDetSupported = (trans.determinism_capability || detObj.capability) === 'SUPPORTED';

      let isoBadge = isIsoVerified ? 'VERIFIED' : (isIsoSupported ? 'SUPPORTED (NOT VERIFIED)' : 'UNAVAILABLE');
      let isoBadgeClass = isIsoVerified ? 'badge-success' : (isIsoSupported ? 'badge-info' : 'badge-warning');

      let detBadge = isDetVerified ? 'VERIFIED' : (isDetSupported ? 'SUPPORTED (NOT VERIFIED)' : 'UNAVAILABLE');
      let detBadgeClass = isDetVerified ? 'badge-success' : (isDetSupported ? 'badge-info' : 'badge-warning');

      const isStopped = execStatus === 'STOPPED';
      const isCrashed = execStatus === 'CRASHED';
      const isTimeout = execStatus === 'TIMEOUT';

      const timelineSteps = [
        {
          title: 'Observation Point',
          semanticStatus: obsPointObj ? 'COMPLETED' : 'UNAVAILABLE',
          badgeClass: obsPointObj ? 'badge-info' : 'badge-warning',
          detail: obsPointObj ? `Target suspended at ${obsPointLoc}` : 'Observation point metadata unavailable',
          iconType: obsPointObj ? 'success' : 'warning'
        },
        {
          title: 'Parent State Captured & Preserved',
          semanticStatus: 'COMPLETED',
          badgeClass: 'badge-info',
          detail: `State ${parentId} snapshot registered in corpus`,
          iconType: 'success'
        },
        {
          title: 'Branch Isolation',
          semanticStatus: isoBadge,
          badgeClass: isoBadgeClass,
          detail: isIsoVerified ? `Isolation verified via ${restoreBackend}` : `Backend: ${restoreBackend} (not verified during this transition)`,
          iconType: isIsoVerified ? 'success' : 'info'
        },
        {
          title: 'Determinism Provenance',
          semanticStatus: detBadge,
          badgeClass: detBadgeClass,
          detail: isDetVerified ? 'Restart determinism verified' : `Determinism status: ${trans.determinism_status || detObj.status || 'NOT VERIFIED'}`,
          iconType: isDetVerified ? 'success' : 'info'
        },
        {
          title: 'Mutation Injected into Target',
          semanticStatus: 'COMPLETED',
          badgeClass: 'badge-info',
          detail: `Applied ${targetLabel} = ${newVal}`,
          iconType: 'success'
        },
        {
          title: 'Target Execution Monitored',
          semanticStatus: isTimeout ? 'TIMEOUT' : 'COMPLETED',
          badgeClass: isTimeout ? 'badge-warning' : 'badge-info',
          detail: `Inferior resumed with timeout limit ${stepDuration}`,
          iconType: isTimeout ? 'warning' : 'success'
        },
        {
          title: `Inferior Re-suspended (${execStatus})`,
          semanticStatus: isCrashed ? 'CRASHED' : (isTimeout ? 'TIMEOUT' : 'COMPLETED'),
          badgeClass: isCrashed ? 'badge-danger' : (isTimeout ? 'badge-warning' : 'badge-info'),
          detail: isCrashed ? `Inferior crashed with signal ${trans.execution && trans.execution.signal ? trans.execution.signal : 'abnormal'}` : `Execution halted with status ${execStatus}`,
          iconType: isCrashed ? 'danger' : 'success'
        },
        {
          title: 'Child State Recorded & Semantic Diff Computed',
          semanticStatus: childHash !== 'N/A' ? 'COMPLETED' : 'UNAVAILABLE',
          badgeClass: childHash !== 'N/A' ? 'badge-info' : 'badge-warning',
          detail: `Child state ${childId} recorded (hash: ${childHashShort})`,
          iconType: 'success'
        }
      ];

      let timelineHtml = '';
      timelineSteps.forEach((s) => {
        timelineHtml += `
          <div class="timeline-step">
            <div class="step-icon-box ${s.iconType === 'danger' ? 'danger' : (s.iconType === 'warning' ? 'warning' : 'success')}">
              <span>${s.iconType === 'danger' ? '✕' : (s.iconType === 'warning' ? '!' : '✓')}</span>
            </div>
            <div class="step-content">
              <div class="step-header flex justify-between items-center">
                <div class="step-title font-semibold">${escapeHtml(s.title)}</div>
                <span class="badge ${s.badgeClass} text-xs font-mono ml-2">${escapeHtml(s.semanticStatus)}</span>
              </div>
              <div class="step-detail text-muted">${escapeHtml(s.detail)}</div>
            </div>
          </div>
        `;
      });
      el.execTimelineList.innerHTML = timelineHtml;
    }

    // 3. Render Semantic Diff Table
    if (el.tbodyExecDiff) {
      const facts = trans.facts || {};
      const changed = facts.field_changed || [];

      if (changed.length === 0 && (!mut || mut.field === undefined)) {
        el.tbodyExecDiff.innerHTML = `<tr><td colspan="4" class="text-muted text-center p-3">No field modifications detected between parent and child state</td></tr>`;
      } else {
        let diffHtml = '';
        if (changed.length > 0) {
          changed.forEach((c) => {
            const parts = c.split(':');
            const targetField = parts[0] ? parts[0].trim() : 'field';
            const valParts = parts[1] ? parts[1].split('->') : [];
            const bVal = valParts[0] ? valParts[0].trim() : oldVal;
            const aVal = valParts[1] ? valParts[1].trim() : newVal;

            diffHtml += `
              <tr>
                <td class="mono font-semibold text-accent">${escapeHtml(targetField)}</td>
                <td class="mono diff-val-old">${escapeHtml(String(bVal))}</td>
                <td class="mono diff-val-new font-semibold">${escapeHtml(String(aVal))}</td>
                <td><span class="badge badge-info">FIELD_MUTATION</span></td>
              </tr>
            `;
          });
        } else {
          diffHtml += `
            <tr>
              <td class="mono font-semibold text-accent">${escapeHtml(targetLabel)}</td>
              <td class="mono diff-val-old">${escapeHtml(String(oldVal))}</td>
              <td class="mono diff-val-new font-semibold">${escapeHtml(String(newVal))}</td>
              <td><span class="badge badge-info">FIELD_MUTATION</span></td>
            </tr>
          `;
        }
        el.tbodyExecDiff.innerHTML = diffHtml;
      }
    }
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

  // --------------------------------------------------------------------------
  // Tab 7: State Laboratory & Fast Runtime Capture
  // --------------------------------------------------------------------------

  function renderCaptureLatencyReport(rep) {
    if (!rep) return;
    if (el.latStopTime) el.latStopTime.textContent = `${(rep.stop_time_ms || 0).toFixed(2)} ms`;
    if (el.latThreadTime) el.latThreadTime.textContent = `${(rep.thread_metadata_time_ms || 0).toFixed(2)} ms`;
    if (el.latMemoryTime) el.latMemoryTime.textContent = `${(rep.memory_capture_time_ms || 0).toFixed(2)} ms`;
    if (el.latResumeTime) el.latResumeTime.textContent = `${(rep.resume_time_ms || 0).toFixed(2)} ms`;
    if (el.latTotalStopTime) {
      el.latTotalStopTime.textContent = `${(rep.total_stop_time_ms || 0).toFixed(2)} ms`;
      if (rep.total_stop_time_ms < 10) {
        el.latTotalStopTime.style.color = 'var(--accent)';
      } else {
        el.latTotalStopTime.style.color = 'var(--warning)';
      }
    }
    if (el.statelabStopTime) {
      el.statelabStopTime.textContent = `${(rep.total_stop_time_ms || 0).toFixed(2)} ms`;
    }
  }

  function renderStateLabTree(treeData) {
    if (!el.statelabTreeContainer) return;
    if (!treeData || !treeData.roots || treeData.roots.length === 0) {
      el.statelabTreeContainer.innerHTML = '<div class="text-muted text-center p-4">No snapshots registered in State Laboratory yet. Click [Capture State] to begin.</div>';
      return;
    }

    const snaps = treeData.snapshots || {};
    let html = '';

    function renderNode(snapId, depth) {
      const s = snaps[snapId];
      if (!s) return '';
      const isSelected = state.selectedLabSnapshotId === snapId;
      const shortHash = (s.state_hash || '').substring(0, 8);
      const isMutation = Boolean(s.is_mutation);
      const branchBadge = s.branch_name ? `<span class="badge badge-info text-xs">${escapeHtml(s.branch_name)}</span>` : '';
      const typeBadge = isMutation
        ? `<span class="badge badge-warning text-xs">Mutation: ${escapeHtml(s.mutated_path || 'field')}</span>`
        : (s.parent_id ? `<span class="badge badge-neutral text-xs">Branch</span>` : `<span class="badge badge-success text-xs">Root Snapshot</span>`);

      const indent = depth * 24;

      let nodeHtml = `
        <div class="branch-tree-node ${isSelected ? 'active' : ''}" style="margin-left: ${indent}px;" data-snap-id="${escapeHtml(snapId)}">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="tree-icon">${depth > 0 ? (isMutation ? '✏️' : '🌿') : '📸'}</span>
            <span class="mono font-semibold">${escapeHtml(snapId)}</span>
            ${branchBadge}
            ${typeBadge}
          </div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <span class="mono text-xs text-muted">Hash: ${escapeHtml(shortHash)}</span>
            <span class="text-xs text-muted">${s.objects_count || 0} objs</span>
          </div>
        </div>
      `;

      if (s.children && s.children.length > 0) {
        for (const childId of s.children) {
          nodeHtml += renderNode(childId, depth + 1);
        }
      }
      return nodeHtml;
    }

    for (const rootId of treeData.roots) {
      html += renderNode(rootId, 0);
    }
    el.statelabTreeContainer.innerHTML = html;

    el.statelabTreeContainer.querySelectorAll('.branch-tree-node').forEach((node) => {
      node.addEventListener('click', () => {
        const sid = node.getAttribute('data-snap-id');
        if (sid) selectLabSnapshot(sid);
      });
    });
  }

  async function selectLabSnapshot(snapshotId) {
    if (!snapshotId) return;
    state.selectedLabSnapshotId = snapshotId;

    if (el.statelabTreeContainer) {
      el.statelabTreeContainer.querySelectorAll('.branch-tree-node').forEach((n) => {
        n.classList.toggle('active', n.getAttribute('data-snap-id') === snapshotId);
      });
    }

    if (el.statelabSnapId) el.statelabSnapId.textContent = snapshotId;

    // Fetch snapshot details
    const res = await apiGet(`/api/state/${snapshotId}`);
    if (res.success && res.data) {
      const snap = res.data;
      const sh = snap.state_hash || 'N/A';
      if (el.statelabStateHash) el.statelabStateHash.textContent = sh.length > 12 ? sh.substring(0, 12) + '...' : sh;
      if (el.statelabObjCount) el.statelabObjCount.textContent = (snap.objects && snap.objects.length) || 0;
      if (el.statelabThreadsCount) el.statelabThreadsCount.textContent = (snap.threads && snap.threads.length) || 1;

      const prov = snap.provenance || {};
      const lat = prov.latency_report || prov.capture_latency || {};
      if (lat.total_stop_time_ms !== undefined) {
        renderCaptureLatencyReport(lat);
      } else if (snap.parent_id) {
        // Logical branch mutation
        if (el.statelabStopTime) el.statelabStopTime.textContent = '0.00 ms (Offline)';
        if (el.latStopTime) el.latStopTime.textContent = '0.00 ms';
        if (el.latThreadTime) el.latThreadTime.textContent = '0.00 ms';
        if (el.latMemoryTime) el.latMemoryTime.textContent = '0.00 ms';
        if (el.latResumeTime) el.latResumeTime.textContent = '0.00 ms';
        if (el.latTotalStopTime) el.latTotalStopTime.textContent = '0.00 ms (Offline Logical State)';
      }

      const memSize = prov.captured_bytes || snap.captured_bytes || 0;
      if (el.statelabMemSize) el.statelabMemSize.textContent = formatBytes(memSize);

      const isMutationBranch = Boolean(snap.parent_id);
      const repCap = (state.runtime && state.runtime.capabilities && state.runtime.capabilities.replay && state.runtime.capabilities.replay.capability) || 'UNAVAILABLE';
      if (el.badgeReplayCap) {
        el.badgeReplayCap.textContent = repCap;
        el.badgeReplayCap.className = `badge badge-${repCap === 'SUPPORTED' ? 'success' : repCap === 'CONDITIONAL' ? 'warning' : 'neutral'} text-xs`;
      }
      if (el.replayValCapability) el.replayValCapability.textContent = repCap;
      if (el.btnRunReplayAction) {
        el.btnRunReplayAction.disabled = (repCap === 'UNAVAILABLE' || !isMutationBranch);
        el.btnRunReplayAction.title = !isMutationBranch ? 'Replay requires a mutated branch' : '';
      }
    }

    await loadImpactAnalysis(snapshotId);
  }

  async function loadImpactAnalysis(snapshotId, targetPath) {
    let url = `/api/impact/${snapshotId}`;
    if (targetPath) {
      url += `?target_path=${encodeURIComponent(targetPath)}`;
    }
    const res = await apiGet(url);
    if (!res.success || !res.data) {
      renderImpactData({
        target_path: targetPath || 'None selected',
        directly_affected_objects: [],
        parent_objects: [],
        shared_objects: [],
        referencing_threads: [],
        potentially_affected_threads: []
      });
      return;
    }
    renderImpactData(res.data);
  }

  function renderImpactData(data) {
    if (el.impactTargetLabel) {
      el.impactTargetLabel.textContent = data.target_path || 'No mutation target specified';
    }

    function renderTagList(container, items, tagClass = '') {
      if (!container) return;
      if (!items || items.length === 0) {
        container.innerHTML = `<li class="tag text-muted">None</li>`;
        return;
      }
      container.innerHTML = items.map(it => {
        const label = typeof it === 'object' ? (it.name || it.path || it.id || JSON.stringify(it)) : String(it);
        return `<li class="tag ${tagClass}">${escapeHtml(label)}</li>`;
      }).join('');
    }

    renderTagList(el.impactDirectList, data.directly_affected_objects, 'tag-accent');
    renderTagList(el.impactParentList, data.parent_objects);
    renderTagList(el.impactSharedList, data.shared_objects);
    renderTagList(el.impactRefThreadsList, data.referencing_threads, 'tag-warning');
    renderTagList(el.impactPotThreadsList, data.potentially_affected_threads);
  }

  async function loadStateLabTree() {
    const res = await apiGet('/api/state-lab/tree');
    if (res.success && res.data) {
      state.stateLabTree = res.data;
      renderStateLabTree(res.data);
      if (!state.selectedLabSnapshotId && res.data.roots && res.data.roots.length > 0) {
        selectLabSnapshot(res.data.roots[0]);
      }
    }
  }

  function initFastCaptureModal() {
    if (!el.modalFastCapture) return;

    const radios = el.formFastCapture.querySelectorAll('input[name="cap-mode"]');
    radios.forEach((r) => {
      r.addEventListener('change', () => {
        if (el.groupTargetPath) {
          el.groupTargetPath.style.display = r.value === 'TARGETED' ? 'block' : 'none';
        }
      });
    });

    const openCaptureModal = () => {
      if (el.capPid && state.runtime && state.runtime.pid) {
        el.capPid.value = state.runtime.pid;
      }
      el.modalFastCapture.style.display = 'flex';
    };

    if (el.btnFastCapture) el.btnFastCapture.addEventListener('click', openCaptureModal);
    if (el.btnLabOpenCapture) el.btnLabOpenCapture.addEventListener('click', openCaptureModal);

    if (el.btnCloseFastCaptureModal) {
      el.btnCloseFastCaptureModal.addEventListener('click', () => {
        el.modalFastCapture.style.display = 'none';
      });
    }
    if (el.btnCancelFastCapture) {
      el.btnCancelFastCapture.addEventListener('click', () => {
        el.modalFastCapture.style.display = 'none';
      });
    }

    if (el.formFastCapture) {
      el.formFastCapture.addEventListener('submit', async (e) => {
        e.preventDefault();
        const mode = el.formFastCapture.elements['cap-mode'].value || 'FULL';
        const targetPath = el.capTargetPath ? el.capTargetPath.value.trim() : '';
        const pid = el.capPid && el.capPid.value ? parseInt(el.capPid.value, 10) : (state.runtime && state.runtime.pid);
        const timeoutMs = el.capTimeout ? parseInt(el.capTimeout.value, 10) : 1000;

        showToast(`Initiating ${mode} capture (<10ms stop time)...`, 'info');
        el.modalFastCapture.style.display = 'none';

        const res = await apiPost('/api/capture', {
          mode,
          target_path: targetPath,
          pid,
          timeout_ms: timeoutMs
        });

        if (!res.success) {
          showToast(res.error ? res.error.message : 'Fast capture failed', 'error');
          return;
        }

        const snapData = res.data;
        const stopTime = snapData.latency_report ? snapData.latency_report.total_stop_time_ms.toFixed(2) : '0';
        showToast(`Snapshot ${snapData.snapshot_id} captured in ${stopTime} ms stop time!`, 'success');

        if (snapData.latency_report) {
          renderCaptureLatencyReport(snapData.latency_report);
        }
        if (snapData.tree) {
          renderStateLabTree(snapData.tree);
        }

        await loadRuntimeOverview();
        await loadStatesAndGraph();
        await selectLabSnapshot(snapData.snapshot_id);
      });
    }
  }

  function initSnapshotMutateModal() {
    if (!el.modalSnapshotMutate) return;

    if (el.btnLabOpenMutate) {
      el.btnLabOpenMutate.addEventListener('click', () => {
        if (!state.selectedLabSnapshotId) {
          const defaultId = state.selectedStateId || (state.stateLabTree && state.stateLabTree.roots && state.stateLabTree.roots[0]);
          if (defaultId) {
            state.selectedLabSnapshotId = defaultId;
          } else {
            showToast('No snapshot available to mutate. Capture a snapshot first.', 'warning');
            return;
          }
        }
        if (state.currentMutationTarget && el.snapMutTarget) {
          el.snapMutTarget.value = state.currentMutationTarget.semantic_path || state.currentMutationTarget.path || '';
        }
        el.modalSnapshotMutate.style.display = 'flex';
      });
    }

    if (el.btnCloseSnapMutateModal) {
      el.btnCloseSnapMutateModal.addEventListener('click', () => {
        el.modalSnapshotMutate.style.display = 'none';
      });
    }
    if (el.btnCancelSnapMutate) {
      el.btnCancelSnapMutate.addEventListener('click', () => {
        el.modalSnapshotMutate.style.display = 'none';
      });
    }

    if (el.formSnapshotMutate) {
      el.formSnapshotMutate.addEventListener('submit', async (e) => {
        e.preventDefault();
        const targetPath = el.snapMutTarget.value.trim();
        let newVal = el.snapMutValue.value.trim();
        const branchName = el.snapMutBranchName.value.trim() || undefined;

        if (!isNaN(newVal) && newVal !== '') {
          newVal = Number(newVal);
        } else if (newVal.toLowerCase() === 'true') {
          newVal = true;
        } else if (newVal.toLowerCase() === 'false') {
          newVal = false;
        }

        showToast(`Mutating snapshot branch (${targetPath})...`, 'info');
        el.modalSnapshotMutate.style.display = 'none';

        const res = await apiPost(`/api/snapshots/${state.selectedLabSnapshotId}/mutate`, {
          target_path: targetPath,
          new_value: newVal,
          branch_name: branchName
        });

        if (!res.success) {
          showToast(res.error ? res.error.message : 'Snapshot mutation failed', 'error');
          return;
        }

        const mutData = res.data;
        showToast(`Mutated branch ${mutData.child_id} created with verified isolation!`, 'success');

        await loadStateLabTree();
        await selectLabSnapshot(mutData.child_id);
      });
    }
  }

  function initLabBranchAndReplay() {
    if (el.btnLabOpenBranch) {
      el.btnLabOpenBranch.addEventListener('click', async () => {
        if (!state.selectedLabSnapshotId) {
          const defaultId = state.selectedStateId || (state.stateLabTree && state.stateLabTree.roots && state.stateLabTree.roots[0]);
          if (defaultId) state.selectedLabSnapshotId = defaultId;
          else {
            showToast('Capture a snapshot first before branching.', 'warning');
            return;
          }
        }
        const branchName = prompt('Enter new branch name (e.g. branch_b):', 'branch_' + Date.now().toString(36).slice(-4));
        if (branchName === null) return;

        showToast(`Creating snapshot branch...`, 'info');
        const res = await apiPost(`/api/snapshots/${state.selectedLabSnapshotId}/branch`, {
          branch_name: branchName.trim()
        });

        if (!res.success) {
          showToast(res.error ? res.error.message : 'Branch creation failed', 'error');
          return;
        }

        const branchData = res.data;
        showToast(`Branch ${branchData.branch_id} created successfully!`, 'success');
        await loadStateLabTree();
        await selectLabSnapshot(branchData.branch_id);
      });
    }

    if (el.btnRefreshLabTree) {
      el.btnRefreshLabTree.addEventListener('click', () => {
        showToast('Refreshing State Laboratory tree...', 'info');
        loadStateLabTree();
      });
    }

    if (el.btnRunReplayAction) {
      el.btnRunReplayAction.addEventListener('click', async () => {
        if (!state.selectedLabSnapshotId) {
          showToast('Select a mutation snapshot first', 'warning');
          return;
        }
        showToast('Initiating live target replay & readback verification...', 'info');
        el.btnRunReplayAction.disabled = true;

        const res = await apiPost(`/api/snapshots/${state.selectedLabSnapshotId}/replay`, {
          pid: state.runtime && state.runtime.pid,
          timeout_ms: state.globalTimeoutMs || 1000
        });
        el.btnRunReplayAction.disabled = false;

        if (!res.success) {
          showToast(res.error ? res.error.message : 'Replay failed', 'error');
          if (el.replayValAttempted) el.replayValAttempted.textContent = 'Yes';
          if (el.replayValCompleted) el.replayValCompleted.textContent = 'Failed';
          if (el.replayValVerified) el.replayValVerified.textContent = 'No';
          return;
        }

        const rep = res.data;
        if (el.replayValAttempted) el.replayValAttempted.textContent = rep.attempted ? 'Yes' : 'No';
        if (el.replayValCompleted) el.replayValCompleted.textContent = rep.completed ? 'Yes' : 'No';
        if (el.replayValVerified) {
          el.replayValVerified.textContent = rep.verified ? 'Verified ✓' : 'Unverified ✗';
          el.replayValVerified.className = `font-mono text-xs ${rep.verified ? 'text-accent' : 'text-danger'}`;
        }
        if (el.replayValSource) {
          el.replayValSource.textContent = rep.verification_source || 'readback';
        }

        if (rep.verified) {
          showToast('Live mutation successfully replayed and verified via readback!', 'success');
        } else if (rep.completed) {
          showToast('Live mutation executed but readback verification could not confirm value', 'warning');
        } else {
          showToast('Replay could not be completed on target process', 'warning');
        }
      });
    }
  }

  function bindEvents() {
    el.btnRefresh.addEventListener('click', async () => {
      showToast('Refreshing runtime state...', 'info');
      await loadRuntimeOverview();
      await loadStatesAndGraph();
    });

    if (el.selectGlobalTimeout) {
      el.selectGlobalTimeout.addEventListener('change', (e) => {
        state.globalTimeoutMs = parseInt(e.target.value, 10) || 1000;
        if (el.prevTimeoutSelect) el.prevTimeoutSelect.value = String(state.globalTimeoutMs);
      });
    }

    if (el.selectSnapshotId) {
      el.selectSnapshotId.addEventListener('change', (e) => {
        const sid = e.target.value;
        if (sid) selectState(sid);
      });
    }

    // Object Explorer Sorting
    if (el.selectObjSort) {
      el.selectObjSort.addEventListener('change', (e) => {
        state.objectSort = e.target.value;
        renderMemoryObjectsList();
      });
    }

    // Object Explorer Filter Group Pills
    el.filterObjGroupPills.forEach((pill) => {
      pill.addEventListener('click', () => {
        el.filterObjGroupPills.forEach((p) => p.classList.remove('active'));
        pill.classList.add('active');
        state.objectFilterGroup = pill.getAttribute('data-group');
        renderMemoryObjectsList();
      });
    });

    // Object Explorer Search & Clear
    if (el.inputSearchObjects) {
      el.inputSearchObjects.addEventListener('input', (e) => {
        state.searchQuery = e.target.value;
        renderMemoryObjectsList();
      });
    }

    if (el.btnClearObjSearch) {
      el.btnClearObjSearch.addEventListener('click', () => {
        if (el.inputSearchObjects) el.inputSearchObjects.value = '';
        state.searchQuery = '';
        renderMemoryObjectsList();
      });
    }

    // Reference Tree Toolbar: Expand/Collapse All
    if (el.btnExpandAllTree) {
      el.btnExpandAllTree.addEventListener('click', () => {
        (state.objects || []).forEach((o) => state.expandedTreeNodes.add(o.object_id));
        renderReferenceTree();
      });
    }

    if (el.btnCollapseAllTree) {
      el.btnCollapseAllTree.addEventListener('click', () => {
        state.expandedTreeNodes.clear();
        renderReferenceTree();
      });
    }

    // Integrated Field Mutation Trigger
    if (el.btnInspRunMutation) {
      el.btnInspRunMutation.addEventListener('click', () => {
        if (!state.currentMutableField || !state.currentMutableField.object || !state.currentMutableField.field) {
          showToast('No mutable field selected', 'warning');
          return;
        }
        const obj = state.currentMutableField.object;
        const field = state.currentMutableField.field;
        const inputEl = document.getElementById('insp-mut-new-val');
        if (!inputEl) return;

        let inputVal = inputEl.value;
        const rawType = (field.type || '').toLowerCase();
        if (rawType.includes('bool')) {
          inputVal = inputVal === 'true' || inputVal === '1';
        } else if (rawType.includes('int') || rawType.includes('short') || rawType.includes('long') || rawType.includes('size_t')) {
          inputVal = parseInt(inputVal, 10);
        } else if (rawType.includes('float') || rawType.includes('double')) {
          inputVal = parseFloat(inputVal);
        }

        openMutationPreview({
          object_id: obj.object_id,
          semantic_name: obj.semantic_name,
          field: field.name,
          current_value: field.value,
          proposed_value: inputVal,
          type: field.type,
          cleaned_type: field.cleaned_type,
          storage: obj.storage,
          mutability: 'MUTABLE',
        });
      });
    }

    if (el.btnGotoObjects) {
      el.btnGotoObjects.addEventListener('click', () => {
        switchTab('tab-object-explorer');
      });
    }

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
    initModeToggle();
    initMutationPreview();
    initJsonViewerButtons();
    initObserveDialog();
    initFastCaptureModal();
    initSnapshotMutateModal();
    initLabBranchAndReplay();
    bindEvents();

    await loadRuntimeOverview();
    await loadStatesAndGraph();
    await loadStateLabTree();
  }

  window.addEventListener('DOMContentLoaded', init);
})();
