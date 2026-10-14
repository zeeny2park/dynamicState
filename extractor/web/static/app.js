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
    activeTab: 'tab-investigation-overview',
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
    activeInvestigation: null,
    selectedInvestigationId: null,
    investigationFindingFilter: 'all',
    currentLang: 'en',
    navHistory: [],
    selectedFieldName: null,
    candidateTierFilter: 'all',
    showingRawJson: false,
  };

  // DOM Elements Cache
  const el = {
    // Language Toggle
    groupLangToggle: document.getElementById('group-lang-toggle'),
    btnLangEn: document.getElementById('btn-lang-en'),
    btnLangKo: document.getElementById('btn-lang-ko'),

    // TAB 0: Investigation Overview
    invInputGoal: document.getElementById('inv-input-goal'),
    btnRunInvestigation: document.getElementById('btn-run-investigation'),
    btnRunInvestigationCycle: document.getElementById('btn-run-investigation-cycle'),
    btnStepInvestigationCycle: document.getElementById('btn-step-investigation-cycle'),
    btnRefreshInvestigation: document.getElementById('btn-refresh-investigation'),
    invSelectSnapshot: document.getElementById('inv-select-snapshot'),
    invInputDebugImage: document.getElementById('inv-input-debug-image'),
    invCheckAuthorize: document.getElementById('inv-check-authorize'),
    invBadgeStatus: document.getElementById('inv-badge-status'),
    invTxtId: document.getElementById('inv-txt-id'),
    invStagePills: document.getElementById('inv-stage-pills'),
    invBadgeBuildStatus: document.getElementById('inv-badge-build-status'),
    invTxtExec: document.getElementById('inv-txt-exec'),
    invTxtTargetBid: document.getElementById('inv-txt-target-bid'),
    invTxtDebugImage: document.getElementById('inv-txt-debug-image'),
    invTxtDebugBid: document.getElementById('inv-txt-debug-bid'),
    invTxtPid: document.getElementById('inv-txt-pid'),
    invBadgeConsistency: document.getElementById('inv-badge-consistency'),
    invConsistencyWarning: document.getElementById('inv-consistency-warning'),
    invTxtConsistency: document.getElementById('inv-txt-consistency'),
    invTxtBackend: document.getElementById('inv-txt-backend'),
    invTxtStopMech: document.getElementById('inv-txt-stop-mech'),
    invTxtDuration: document.getElementById('inv-txt-duration'),
    invTxtBytes: document.getElementById('inv-txt-bytes'),
    invTxtRegions: document.getElementById('inv-txt-regions'),
    invTxtReadStatus: document.getElementById('inv-txt-read-status'),
    invTxtPartialReads: document.getElementById('inv-txt-partial-reads'),
    invTxtFailedReads: document.getElementById('inv-txt-failed-reads'),
    invLimitationsContainer: document.getElementById('inv-limitations-container'),
    invComparisonsContent: document.getElementById('inv-comparisons-content'),
    btnModalCompare: document.getElementById('btn-modal-compare'),
    invStepsContainer: document.getElementById('inv-steps-container'),
    invStepsCount: document.getElementById('inv-steps-count'),
    invTimelineContainer: document.getElementById('inv-timeline-container'),
    invTimelineCount: document.getElementById('inv-timeline-count'),
    invFindingsList: document.getElementById('inv-findings-list'),
    invCardDrilldown: document.getElementById('inv-card-drilldown'),
    invDrilldownContent: document.getElementById('inv-drilldown-content'),
    btnCloseDrilldown: document.getElementById('btn-close-drilldown'),
    invBadgeStaticProvider: document.getElementById('inv-badge-static-provider'),
    invStaticLinksList: document.getElementById('inv-static-links-list'),
    tbodyRawEvidence: document.getElementById('tbody-raw-evidence'),
    invTxtLedgerCount: document.getElementById('inv-txt-ledger-count'),
    btnDownloadLedger: document.getElementById('btn-download-ledger'),

    // Modernized Launchpad & Two-Level Header elements
    hdrTxtTarget: document.getElementById('hdr-txt-target'),
    hdrBadgeCaptureQuality: document.getElementById('hdr-badge-capture-quality'),
    hdrBadgeInvestigationState: document.getElementById('hdr-badge-investigation-state'),
    btnToggleTechDetails: document.getElementById('btn-toggle-tech-details'),
    runtimeSummaryBar: document.getElementById('runtime-summary-bar'),

    btnEntrySnapshot: document.getElementById('btn-entry-snapshot'),
    btnEntryLive: document.getElementById('btn-entry-live'),
    panelEntrySnapshot: document.getElementById('panel-entry-snapshot'),
    panelEntryLive: document.getElementById('panel-entry-live'),
    invInputLiveTarget: document.getElementById('inv-input-live-target'),
    invInputLiveDebugImage: document.getElementById('inv-input-live-debug-image'),
    invRecentSessionsContainer: document.getElementById('inv-recent-sessions-container'),
    invRecentSessionsList: document.getElementById('inv-recent-sessions-list'),
    invAlertBanner: document.getElementById('inv-alert-banner'),
    invAlertIcon: document.getElementById('inv-alert-icon'),
    invAlertMessage: document.getElementById('inv-alert-message'),
    invCmpSelectA: document.getElementById('inv-cmp-select-a'),
    invCmpSelectB: document.getElementById('inv-cmp-select-b'),
    btnRunInlineCompare: document.getElementById('btn-run-inline-compare'),
    invLineageContainer: document.getElementById('inv-lineage-container'),
    invLineageContent: document.getElementById('inv-lineage-content'),
    btnCloseLineage: document.getElementById('btn-close-lineage'),
    invDetailsRawEvidence: document.getElementById('inv-details-raw-evidence'),

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

    // Code Navigation & Breadcrumbs DOM Elements
    btnNavBack: document.getElementById('btn-nav-back'),
    navBreadcrumbsTrail: document.getElementById('nav-breadcrumbs-trail'),
    navHistoryInfo: document.getElementById('nav-history-info'),
    inspValDwarfLoc: document.getElementById('insp-val-dwarf-loc'),
    inspValInterpretation: document.getElementById('insp-val-interpretation'),
    cardCodeNavigation: document.getElementById('card-code-navigation'),
    badgeCodeNavTarget: document.getElementById('badge-code-nav-target'),
    codeNavTargetName: document.getElementById('code-nav-target-name'),
    codeNavTargetLoc: document.getElementById('code-nav-target-loc'),
    codeNavTargetInterp: document.getElementById('code-nav-target-interp'),
    tbodyCandidateFunctions: document.getElementById('tbody-candidate-functions'),
    codeNavTierChips: document.getElementById('code-nav-tier-chips'),
    countTierAll: document.getElementById('count-tier-all'),
    countTierObserved: document.getElementById('count-tier-observed'),
    countTierStatic: document.getElementById('count-tier-static'),
    countTierIndirect: document.getElementById('count-tier-indirect'),
    countTierUnknown: document.getElementById('count-tier-unknown'),
    inspectorRawJsonBody: document.getElementById('inspector-raw-json-body'),
    preObjRawJson: document.getElementById('pre-obj-raw-json'),
    btnCopyObjJson: document.getElementById('btn-copy-obj-json'),
    inspectorScrollBody: document.querySelector('.inspector-scroll-body'),

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
    const toastEl = document.createElement('div');
    toastEl.className = `toast ${type}`;
    const icon = type === 'success' ? '✓' : type === 'error' ? '⚠️' : 'ℹ';
    toastEl.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
    el.toastContainer.appendChild(toastEl);
    setTimeout(() => {
      toastEl.style.opacity = '0';
      setTimeout(() => toastEl.remove(), 250);
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

    if (tabId === 'tab-investigation-overview') {
      renderInvestigationOverview();
    } else if (tabId === 'tab-object-explorer') {
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
    if (el.btnModeBasic) {
      el.btnModeBasic.addEventListener('click', () => setMode(false));
    }
    if (el.btnModeAdvanced) {
      el.btnModeAdvanced.addEventListener('click', () => setMode(true));
    }
    if (el.btnToggleTechDetails && el.runtimeSummaryBar) {
      el.btnToggleTechDetails.addEventListener('click', () => {
        const isExp = el.runtimeSummaryBar.classList.toggle('expanded');
        el.btnToggleTechDetails.classList.toggle('active', isExp);
      });
    }
  }

  function setMode(isAdvanced) {
    state.isAdvancedMode = isAdvanced;
    if (el.btnModeBasic) el.btnModeBasic.classList.toggle('active', !isAdvanced);
    if (el.btnModeAdvanced) el.btnModeAdvanced.classList.toggle('active', isAdvanced);
    document.body.classList.toggle('advanced-mode', isAdvanced);

    // Expand or collapse raw evidence details according to mode
    if (el.invDetailsRawEvidence) {
      el.invDetailsRawEvidence.open = isAdvanced;
    }

    // Re-render currently visible components while preserving state (activeTab, activeInvestigation, selectedObjectId)
    renderMemoryObjectsList();
    if (state.selectedObjectId) selectObject(state.selectedObjectId);
    if (state.candidates && state.candidates.length > 0) renderCandidatesTable(state.candidates);
    renderInvestigationOverview();
  }

  // ==========================================================================
  // Internationalization (i18n): English (en) and Korean (ko) Support
  // ==========================================================================

  const TRANSLATIONS = {
    en: {
      // Header & Navigation
      hdr_brand_subtitle: 'C/C++ Runtime Investigation Workspace',
      pill_runtime_status_title: 'Target connection status',
      txt_disconnected: 'DISCONNECTED',
      txt_connected: 'CONNECTED',
      txt_paused: 'PAUSED',
      txt_stopped: 'STOPPED',
      txt_running: 'RUNNING',
      hdr_lbl_target: 'Target:',
      no_target_loaded: 'No target loaded',
      hdr_lbl_capture: 'Capture:',
      hdr_lbl_investigation: 'Investigation:',
      title_mode_toggle: 'Switch between human-friendly Basic view and technical Advanced view',
      btn_mode_basic: '👤 Basic',
      btn_mode_advanced: '⚙️ Advanced',
      title_lang_toggle: 'Switch language (English / 한국어)',
      btn_tech_details: '⚙️ Technical Details',
      btn_tech_details_title: 'Toggle technical hardware, ELF, and backend details',
      btn_refresh: 'Refresh',
      btn_refresh_title: 'Refresh runtime data',
      btn_fast_capture: 'Capture State',
      btn_fast_capture_title: 'Fast runtime state capture with minimal stop time',
      btn_observe: 'Observe',

      // Summary Bar
      sum_lbl_runtime: 'Runtime',
      sum_lbl_active_threads: 'Active Threads',
      sum_lbl_discovered_objects: 'Discovered Objects',
      sum_lbl_root_variables: 'Root Variables',
      sum_lbl_state_hash: 'State Hash',
      sum_lbl_capture_backend: 'Capture Backend',
      sum_title_capture_backend: 'Capture Backend',
      sum_lbl_stop_duration: 'Stop Duration',
      sum_title_stop_duration: 'Measured capture stop duration',
      sum_lbl_checkpoint: 'Checkpoint',
      sum_title_checkpoint: 'Checkpoint Restore Capability',
      sum_lbl_branch_isolation: 'Branch Isolation',
      sum_title_branch_isolation: 'Sibling mutation branch isolation capability & verification',
      sum_lbl_determinism: 'Determinism',
      sum_title_determinism: 'Restart reproducibility verification status',
      sum_lbl_observation_point: 'Observation Point',
      sum_title_obs_point: 'Observation Point (deterministic breakpoint)',
      sum_lbl_timeout: 'Timeout (Source of Truth)',
      sum_title_timeout: 'Execution Timeout Source of Truth',
      sum_lbl_active_snapshot: 'Active State / Snapshot',

      // Navigation Tabs
      nav_tab_0: '0. 🔍 Investigation Overview',
      nav_tab_1: '1. 📦 Object Explorer',
      nav_tab_2: '2. 🧵 Thread Explorer',
      nav_tab_3: '3. 🧠 Memory Snapshot',
      nav_tab_4: '4. 📜 State DAG & Diff',
      nav_tab_5: '5. ⚡ Autonomous Loop',
      nav_tab_6: '6. 🛠️ System / Modules',
      nav_tab_7: '7. 🔬 State Laboratory',

      // Investigation Launchpad
      inv_launchpad_title: '🔍 Investigation Workspace',
      inv_launchpad_subtitle: 'Select an entry path to analyze runtime memory, reconstruct C++ object graphs, and verify evidence integrity.',
      btn_entry_snapshot: '📁 Offline Snapshot Analysis',
      btn_entry_live: '⚡ Live Target Capture',
      badge_safe_det: 'SAFE & DETERMINISTIC',
      desc_entry_snapshot: 'Analyze a previously captured memory snapshot offline. Zero target stop time, zero execution interference, completely repeatable.',
      lbl_snapshot_target: 'Snapshot Target:',
      opt_active_state: '(Current / Active State)',
      lbl_debug_image: 'Debug Image (ELF with DWARF):',
      ph_debug_image: 'e.g. build/app_debug.elf (same Build-ID required)',
      badge_req_auth: 'REQUIRES AUTHORIZATION',
      desc_entry_live: 'Connect to an authorized running process. Memory pages are read via <code>process_vm_readv</code>. To reduce skew, the capture backend signals the target (SIGSTOP/SIGCONT); if unstopped or active multi-threaded, capture is NON_ATOMIC.',
      lbl_live_target_pid: 'Live Target PID:',
      ph_live_pid: 'e.g. 2048 (numeric PID required)',
      lbl_live_debug_image: 'Debug Image (ELF with DWARF):',
      ph_live_debug_image: 'e.g. build/app_debug.elf',
      lbl_authorize_check: 'Authorize Target Signal (SIGSTOP / SIGCONT) & Memory Read',
      lbl_goal: '🎯 Goal:',
      ph_goal: 'State your investigation objective (e.g. \'Investigate worker counter mismatch\', \'Verify state transition\')...',
      btn_run_investigation: '🚀 Start Investigation',
      btn_refresh_investigation: '🔄 Refresh',
      lbl_recent_sessions: 'Recent Sessions:',

      // Status Bar & Stages
      lbl_inv_status: 'Status:',
      stage_1: '1. Identity',
      stage_2: '2. Capture Quality',
      stage_3: '3. Typed Objects',
      stage_4: '4. Comparison',
      stage_5: '5. Static Links',
      stage_6: '6. Report',

      // Cards
      title_card_target_build: '🏷️ Target & Build Identity',
      lbl_executable: 'Executable:',
      lbl_target_build_id: 'Target Build ID:',
      lbl_debug_image_card: 'Debug Image:',
      lbl_debug_build_id: 'Debug Build ID:',
      lbl_pid_inferior: 'PID / Inferior:',
      lbl_identity_status: 'Identity Status:',
      lbl_persistence: 'Persistence:',

      title_card_capture_quality: '🛡️ Capture Quality & Constraints',
      lbl_consistency_level: 'Consistency Level:',
      lbl_capture_backend: 'Capture Backend:',
      lbl_stop_mechanism: 'Stop Mechanism:',
      lbl_capture_duration: 'Capture Duration:',
      lbl_bytes_captured: 'Bytes Captured / Req:',
      lbl_regions_read: 'Regions Read / Total:',
      lbl_partial_failed: 'Partial / Failed / Omitted:',

      title_card_comparisons: '⚖️ Observation Comparisons',
      lbl_baseline_a: 'Baseline A:',
      lbl_observed_b: 'Observed B:',
      opt_select_snapshot: '(Select Snapshot)',
      btn_compare_snapshots: 'Compare Snapshots',
      empty_no_comparison: 'No comparison performed yet. Select two snapshots above to isolate state diffs.',

      title_card_next_steps: '📋 Recommended Next Steps',
      empty_next_steps_init: 'Start an investigation to receive evidence-driven recommendations.',

      title_card_findings: '🔎 Investigation Findings',
      filter_all: 'All',
      filter_facts: '🟢 Facts',
      filter_hypo: '🟡 Hypotheses',
      filter_unknown: '⚪ Unknowns',
      empty_findings_init: 'No findings generated. Enter an investigation goal and click \'Start Investigation\'.',

      title_card_static_links: '📜 Resolved Static-Code References',
      empty_static_links_init: 'No static code links resolved yet. Provide a valid debug image to correlate runtime objects to source symbols.',

      summary_advanced_details: '⚙️ Advanced Details & Raw Evidence Ledger (Expand)',
      th_evidence_id: 'Evidence ID',
      th_type: 'Type',
      th_nature: 'Nature',
      th_source: 'Source',
      th_details: 'Details',
      btn_export_ledger: '📥 Export Ledger JSON',

      // Object Explorer
      title_object_explorer: 'Object Explorer',
      lbl_sort: 'Sort:',
      opt_name_asc: 'Name (A-Z)',
      opt_name_desc: 'Name (Z-A)',
      opt_type_asc: 'Type (A-Z)',
      opt_fields_desc: 'Fields (High-Low)',
      opt_refs_desc: 'Refs (High-Low)',
      opt_addr_asc: 'Address (0x...)',
      ph_search_objects: 'Filter by name, type, field, thread...',
      btn_clear_filter_title: 'Clear filter',
      pill_roots: 'Roots',
      pill_heap: 'Heap',
      pill_globals: 'Globals',
      pill_stack: 'Stack/Locals',
      pill_types: 'By Type',
      msg_select_state_objects: 'Select a state to inspect objects',
      bc_roots: 'Roots',
      bc_all_objects: 'All Objects',
      btn_view_tree: '🌲 Reference Tree',
      btn_view_table: '📊 Table',
      btn_view_graph: '🕸️ Topology Graph',
      txt_tree_toolbar: 'Expandable reference hierarchy from application roots:',
      btn_expand_all: 'Expand All',
      btn_collapse_all: 'Collapse All',
      th_semantic_name: 'Semantic Name',
      th_scope: 'Scope',
      th_fields: 'Fields',
      th_outgoing_refs: 'Outgoing Refs',
      th_incoming_refs: 'Incoming Refs',
      th_action: 'Action',
      btn_reset_topology: 'Reset Graph',
      txt_click_node_inspect: 'Click any node to inspect',

      // Object Inspector
      title_select_object: 'Select an Object',
      sub_select_object: 'Select an object from the explorer to inspect',
      title_identity_scope: 'Identity & Scope',
      lbl_semantic_name: 'Semantic Name:',
      lbl_storage_scope: 'Storage Scope:',
      lbl_state_status: 'State Status:',
      lbl_root_source: 'Root Source:',
      lbl_thread: 'Thread:',
      lbl_object_id: 'Object ID:',
      lbl_memory_address: 'Memory Address:',
      lbl_dwarf_type: 'DWARF Type:',
      lbl_snapshot_range: 'Snapshot Range:',
      lbl_build_id: 'Build ID:',
      title_semantic_fields: 'Semantic Fields',
      th_field: 'Field',
      th_value: 'Value',
      th_pointer: 'Pointer',
      th_mutability: 'Mutability',

      // Thread Explorer
      title_active_threads: 'Active Threads & Observation Context',
      sub_active_threads: 'Live thread execution state, source code locations, and active observation points',
      th_role_label: 'Role / Label',
      th_state: 'State',
      th_current_function: 'Current Function',
      th_source_location: 'Source Location',
      th_frames: 'Frames',
      th_obs_context: 'Observation Context',

      // Memory Snapshot
      title_capture_status: 'Capture Status',
      sub_capture_status: 'Execution capture parameters and memory consistency guarantees',
      lbl_capture_status: 'Capture Status',
      lbl_captured_mem: 'Captured Memory',
      lbl_memory_regions: 'Memory Regions',
      lbl_arch_endian: 'Architecture / Endian',
      cap_target_binary: 'Target binary characteristics',

      // State DAG & Diff
      subnav_dag: 'State Transition Graph',
      subnav_diff: 'Semantic State Diff',
      title_corpus_states: 'Corpus States',
      ph_search_states: 'Search state ID or hash...',
      msg_no_corpus_states: 'No states recorded in corpus',
      title_state_graph: 'State Transition Graph (Corpus History)',
      sub_state_graph: 'Directed edges indicate typed mutations & continuous execution',
      btn_fit_view: 'Fit View',
      btn_graph_json: 'Graph JSON',
      btn_inspect_objects: 'Inspect in Object Explorer',
      btn_diff_parent: 'Diff with Parent',
      btn_propose_mutations: 'Propose Mutations',
      title_state_diff: 'Semantic State Diff',
      sub_state_diff: 'Compare field modifications, pointer rewrites, and object lifecycle between two snapshots',
      lbl_diff_a: 'Snapshot A (Parent):',
      lbl_diff_b: 'Snapshot B (Child):',
      btn_compute_diff: 'Compute Diff',

      // State Laboratory
      title_state_lab: 'State Laboratory — Offline Snapshot & Branch Exploration',
      btn_lab_fast_capture: '⚡ Fast Capture',
      btn_lab_create_branch: '🌿 Create Branch',
      btn_lab_mutate_snapshot: '✏️ Mutate Snapshot',
      lbl_snapshot_id: 'Snapshot ID',
      lbl_capture_stop_time: 'Capture Stop Time',
      lbl_reconstructed_objects: 'Reconstructed Objects',
      lbl_captured_threads: 'Captured Threads',

      // Modals
      title_modal_observe: 'Initiate Target Observation',
      lbl_obs_mode: 'Observation Mode:',
      lbl_obs_pid: 'Attach to Existing Target PID (Optional):',
      lbl_obs_debug_image: 'Debug Image Path (Optional):',
      lbl_obs_policy: 'Snapshot Policy:',
      btn_cancel: 'Cancel',
      btn_capture_observation: 'Capture Observation',
      title_fast_capture_modal: '⚡ Fast Runtime State Capture',
      lbl_capture_mode: 'Capture Mode:',
      btn_capture_immediately: 'Capture Immediately',
      title_snap_mutate_modal: '✏️ Mutate Snapshot Branch',
      btn_create_mutated_branch: 'Create Mutated Branch',

      // Dynamic Findings & Scopes
      scope_boundaries_header: 'Scope Boundaries &amp; Uninspected Checks:',
      zero_findings_not_clean: 'Zero findings recorded does NOT indicate clean state; inspection was restricted.',
      observed_fact: 'Observed Fact',
      hypothesis: 'Hypothesis',
      unknown: 'Unknown',
      inspect_in_obj_explorer: 'Inspect in Object Explorer ➔',
      clean_completed_title: 'Completed: 0 Findings in Inspected Scope',
      inv_empty_findings_init: 'Investigation not started. Select an entry path above, enter an objective, and click "Start Investigation".',
      analysis_scope_incomplete: 'Analysis scope was incomplete:',
      clean_completed_no_disc: 'No discrepancies identified within inspected structures.',
      zero_findings_unverified_fallback: 'Unmapped heap allocations, private symbols, and uninspected runtime invariants remain unverified.',
      partial_0_findings_title: 'Partial Analysis: 0 Findings Recorded',
      inv_blocked_title: 'Investigation Blocked',
      inv_failed_title: 'Investigation Failed',
      no_active_session: 'No active session',
      ready_investigation_goal: 'Ready for investigation goal',
      badge_status_idle: 'IDLE / READY',
      toast_investigation_started: 'Investigation started...',
      toast_investigation_completed: 'Investigation completed',
      toast_investigation_refreshed: 'Investigation data refreshed',
    },
    ko: {
      // Header & Navigation
      hdr_brand_subtitle: 'C/C++ 런타임 상태 분석 워크스페이스',
      pill_runtime_status_title: '대상 프로세스 연결 상태',
      txt_disconnected: '연결 끊김',
      txt_connected: '연결됨',
      txt_paused: '일시 정지됨',
      txt_stopped: '정지됨',
      txt_running: '실행 중',
      hdr_lbl_target: '대상:',
      no_target_loaded: '로드된 대상 없음',
      hdr_lbl_capture: '캡처:',
      hdr_lbl_investigation: '조사:',
      title_mode_toggle: '사용자 친화적 기본 보기와 기술적 고급 보기 간 전환',
      btn_mode_basic: '👤 기본',
      btn_mode_advanced: '⚙️ 고급',
      title_lang_toggle: '언어 전환 (English / 한국어)',
      btn_tech_details: '⚙️ 기술 상세',
      btn_tech_details_title: '하드웨어, ELF 및 백엔드 기술 상세 전환',
      btn_refresh: '새로고침',
      btn_refresh_title: '런타임 데이터 새로고침',
      btn_fast_capture: '상태 캡처',
      btn_fast_capture_title: '최소 정지 시간으로 빠른 런타임 상태 캡처',
      btn_observe: '관측',

      // Summary Bar
      sum_lbl_runtime: '런타임',
      sum_lbl_active_threads: '활성 스레드',
      sum_lbl_discovered_objects: '발견된 객체',
      sum_lbl_root_variables: '루트 변수',
      sum_lbl_state_hash: '상태 해시',
      sum_lbl_capture_backend: '캡처 백엔드',
      sum_title_capture_backend: '캡처 백엔드',
      sum_lbl_stop_duration: '정지 시간',
      sum_title_stop_duration: '측정된 캡처 정지 시간',
      sum_lbl_checkpoint: '체크포인트',
      sum_title_checkpoint: '체크포인트 복원 역량',
      sum_lbl_branch_isolation: '브랜치 격리',
      sum_title_branch_isolation: '형제 변이 브랜치 격리 역량 및 검증',
      sum_lbl_determinism: '결정론성',
      sum_title_determinism: '재시작 재현성 검증 상태',
      sum_lbl_observation_point: '관측 지점',
      sum_title_obs_point: '관측 지점 (결정론적 중단점)',
      sum_lbl_timeout: '타임아웃 (단일 진실 공급원)',
      sum_title_timeout: '실행 타임아웃 단일 진실 공급원',
      sum_lbl_active_snapshot: '활성 상태 / 스냅샷',

      // Navigation Tabs
      nav_tab_0: '0. 🔍 조사 개요',
      nav_tab_1: '1. 📦 객체 탐색기',
      nav_tab_2: '2. 🧵 스레드 탐색기',
      nav_tab_3: '3. 🧠 메모리 스냅샷',
      nav_tab_4: '4. 📜 상태 DAG 및 차이',
      nav_tab_5: '5. ⚡ 자율 루프',
      nav_tab_6: '6. 🛠️ 시스템 / 모듈',
      nav_tab_7: '7. 🔬 상태 실험실',

      // Investigation Launchpad
      inv_launchpad_title: '🔍 조사 워크스페이스',
      inv_launchpad_subtitle: '런타임 메모리를 분석하고 C++ 객체 그래프를 재구성하며 증거 무결성을 검증할 진입 경로를 선택하세요.',
      btn_entry_snapshot: '📁 오프라인 스냅샷 분석',
      btn_entry_live: '⚡ 라이브 대상 캡처',
      badge_safe_det: '안전 및 결정론적',
      desc_entry_snapshot: '이전에 캡처된 메모리 스냅샷을 오프라인에서 분석합니다. 대상 정지 시간 0, 실행 간섭 없음, 완전한 재현성 보장.',
      lbl_snapshot_target: '스냅샷 대상:',
      opt_active_state: '(현재 / 활성 상태)',
      lbl_debug_image: '디버그 이미지 (DWARF 포함 ELF):',
      ph_debug_image: '예: build/app_debug.elf (동일 Build-ID 필요)',
      badge_req_auth: '권한 승인 필요',
      desc_entry_live: '권한이 부여된 실행 중인 프로세스에 연결합니다. 메모리 페이지는 <code>process_vm_readv</code>를 통해 읽힙니다. 편향을 줄이기 위해 백엔드가 대상을 신호(SIGSTOP/SIGCONT)로 정지시키며, 정지되지 않거나 활성 멀티스레드인 경우 캡처는 NON_ATOMIC으로 처리됩니다.',
      lbl_live_target_pid: '라이브 대상 PID:',
      ph_live_pid: '예: 2048 (숫자 PID 필요)',
      lbl_live_debug_image: '디버그 이미지 (DWARF 포함 ELF):',
      ph_live_debug_image: '예: build/app_debug.elf',
      lbl_authorize_check: '대상 신호(SIGSTOP / SIGCONT) 전송 및 메모리 읽기 승인',
      lbl_goal: '🎯 조사 목표:',
      ph_goal: '조사 목표를 입력하세요 (예: \'워커 카운터 불일치 조사\', \'상태 전이 검증\')...',
      btn_run_investigation: '🚀 조사 시작',
      btn_refresh_investigation: '🔄 새로고침',
      lbl_recent_sessions: '최근 세션:',

      // Status Bar & Stages
      lbl_inv_status: '상태:',
      stage_1: '1. 대상 식별',
      stage_2: '2. 캡처 품질',
      stage_3: '3. 타입 객체',
      stage_4: '4. 상태 비교',
      stage_5: '5. 정적 링크',
      stage_6: '6. 보고서',

      // Cards
      title_card_target_build: '🏷️ 대상 및 빌드 식별',
      lbl_executable: '실행 파일:',
      lbl_target_build_id: '대상 빌드 ID:',
      lbl_debug_image_card: '디버그 이미지:',
      lbl_debug_build_id: '디버그 빌드 ID:',
      lbl_pid_inferior: 'PID / 인피리어:',
      lbl_identity_status: '식별 상태:',
      lbl_persistence: '영속성:',

      title_card_capture_quality: '🛡️ 캡처 품질 및 제약사항',
      lbl_consistency_level: '일관성 수준:',
      lbl_capture_backend: '캡처 백엔드:',
      lbl_stop_mechanism: '정지 메커니즘:',
      lbl_capture_duration: '캡처 소요 시간:',
      lbl_bytes_captured: '캡처 바이트 / 요청:',
      lbl_regions_read: '읽은 영역 / 전체:',
      lbl_partial_failed: '부분 / 실패 / 생략:',

      title_card_comparisons: '⚖️ 관측 비교 분석',
      lbl_baseline_a: '기준 A:',
      lbl_observed_b: '관측 B:',
      opt_select_snapshot: '(스냅샷 선택)',
      btn_compare_snapshots: '스냅샷 비교',
      empty_no_comparison: '아직 수행된 비교가 없습니다. 위에서 두 개의 스냅샷을 선택하여 상태 차이를 격리하세요.',

      title_card_next_steps: '📋 권장 다음 단계',
      empty_next_steps_init: '증거 기반 권장 단계를 받으려면 조사를 시작하세요.',

      title_card_findings: '🔎 조사 발견 사항',
      filter_all: '전체',
      filter_facts: '🟢 관측 사실',
      filter_hypo: '🟡 가설',
      filter_unknown: '⚪ 미확인',
      empty_findings_init: '생성된 발견 사항이 없습니다. 조사 목표를 입력하고 \'조사 시작\'을 클릭하세요.',

      title_card_static_links: '📜 확인된 정적 코드 참조',
      empty_static_links_init: '해결된 정적 코드 링크가 없습니다. 런타임 객체와 소스 심볼을 연결하려면 유효한 디버그 이미지를 제공하세요.',

      summary_advanced_details: '⚙️ 고급 상세 정보 및 원시 증거 원장 (펼치기)',
      th_evidence_id: '증거 ID',
      th_type: '유형',
      th_nature: '성격',
      th_source: '출처',
      th_details: '상세 정보',
      btn_export_ledger: '📥 원장 JSON 내보내기',

      // Object Explorer
      title_object_explorer: '객체 탐색기',
      lbl_sort: '정렬:',
      opt_name_asc: '이름 (A-Z)',
      opt_name_desc: '이름 (Z-A)',
      opt_type_asc: '타입 (A-Z)',
      opt_fields_desc: '필드 수 (높은순)',
      opt_refs_desc: '참조 수 (높은순)',
      opt_addr_asc: '주소 (0x...)',
      ph_search_objects: '이름, 타입, 필드, 스레드로 필터링...',
      btn_clear_filter_title: '필터 초기화',
      pill_roots: '루트',
      pill_heap: '힙',
      pill_globals: '전역',
      pill_stack: '스택/로컬',
      pill_types: '타입별',
      msg_select_state_objects: '객체를 검사할 상태를 선택하세요',
      bc_roots: '루트',
      bc_all_objects: '전체 객체',
      btn_view_tree: '🌲 참조 트리',
      btn_view_table: '📊 표 보기',
      btn_view_graph: '🕸️ 위상 그래프',
      txt_tree_toolbar: '애플리케이션 루트로부터 확장 가능한 참조 계층 구조:',
      btn_expand_all: '모두 펼치기',
      btn_collapse_all: '모두 접기',
      th_semantic_name: '의미론적 이름',
      th_scope: '스코프',
      th_fields: '필드',
      th_outgoing_refs: '나가는 참조',
      th_incoming_refs: '들어오는 참조',
      th_action: '작업',
      btn_reset_topology: '그래프 초기화',
      txt_click_node_inspect: '노드를 클릭하여 검사하세요',

      // Object Inspector
      title_select_object: '객체 선택',
      sub_select_object: '검사할 객체를 탐색기에서 선택하세요',
      title_identity_scope: '식별 및 스코프',
      lbl_semantic_name: '의미론적 이름:',
      lbl_storage_scope: '저장소 스코프:',
      lbl_state_status: '상태 상황:',
      lbl_root_source: '루트 출처:',
      lbl_thread: '스레드:',
      lbl_object_id: '객체 ID:',
      lbl_memory_address: '메모리 주소:',
      lbl_dwarf_type: 'DWARF 타입:',
      lbl_snapshot_range: '스냅샷 범위:',
      lbl_build_id: '빌드 ID:',
      title_semantic_fields: '의미론적 필드',
      th_field: '필드',
      th_value: '값',
      th_pointer: '포인터',
      th_mutability: '가변성',

      // Thread Explorer
      title_active_threads: '활성 스레드 및 관측 컨텍스트',
      sub_active_threads: '실시간 스레드 실행 상태, 소스 코드 위치 및 활성 관측 지점',
      th_role_label: '역할 / 라벨',
      th_state: '상태',
      th_current_function: '현재 함수',
      th_source_location: '소스 위치',
      th_frames: '프레임',
      th_obs_context: '관측 컨텍스트',

      // Memory Snapshot
      title_capture_status: '캡처 상태',
      sub_capture_status: '실행 캡처 매개변수 및 메모리 일관성 보장',
      lbl_capture_status: '캡처 상태',
      lbl_captured_mem: '캡처된 메모리',
      lbl_memory_regions: '메모리 영역',
      lbl_arch_endian: '아키텍처 / 엔디언',
      cap_target_binary: '대상 바이너리 특성',

      // State DAG & Diff
      subnav_dag: '상태 전이 그래프',
      subnav_diff: '의미론적 상태 차이',
      title_corpus_states: '말뭉치 상태',
      ph_search_states: '상태 ID 또는 해시 검색...',
      msg_no_corpus_states: '말뭉치에 기록된 상태 없음',
      title_state_graph: '상태 전이 그래프 (말뭉치 이력)',
      sub_state_graph: '방향성 간선은 타입 변이 및 연속 실행을 나타냅니다',
      btn_fit_view: '화면 맞춤',
      btn_graph_json: '그래프 JSON',
      btn_inspect_objects: '객체 탐색기에서 검사',
      btn_diff_parent: '부모와 비교',
      btn_propose_mutations: '변이 제안',
      title_state_diff: '의미론적 상태 차이',
      sub_state_diff: '두 스냅샷 간의 필드 수정, 포인터 재작성 및 객체 수명 주기 비교',
      lbl_diff_a: '스냅샷 A (부모):',
      lbl_diff_b: '스냅샷 B (자식):',
      btn_compute_diff: '차이 계산',

      // State Laboratory
      title_state_lab: '상태 실험실 — 오프라인 스냅샷 및 브랜치 탐색',
      btn_lab_fast_capture: '⚡ 빠른 캡처',
      btn_lab_create_branch: '🌿 브랜치 생성',
      btn_lab_mutate_snapshot: '✏️ 스냅샷 변이',
      lbl_snapshot_id: '스냅샷 ID',
      lbl_capture_stop_time: '캡처 정지 시간',
      lbl_reconstructed_objects: '재구성된 객체',
      lbl_captured_threads: '캡처된 스레드',

      // Modals
      title_modal_observe: '대상 관측 시작',
      lbl_obs_mode: '관측 모드:',
      lbl_obs_pid: '기존 대상 PID에 연결 (선택 사항):',
      lbl_obs_debug_image: '디버그 이미지 경로 (선택 사항):',
      lbl_obs_policy: '스냅샷 정책:',
      btn_cancel: '취소',
      btn_capture_observation: '관측 캡처',
      title_fast_capture_modal: '⚡ 빠른 런타임 상태 캡처',
      lbl_capture_mode: '캡처 모드:',
      btn_capture_immediately: '즉시 캡처',
      title_snap_mutate_modal: '✏️ 스냅샷 브랜치 변이',
      btn_create_mutated_branch: '변이된 브랜치 생성',

      // Dynamic Findings & Scopes
      scope_boundaries_header: '조사 범위 경계 및 미검사 항목:',
      zero_findings_not_clean: '기록된 발견 사항이 없다고 해서 안전한 상태를 의미하지 않습니다. 조사가 제한되었습니다.',
      observed_fact: '관측 사실',
      hypothesis: '가설',
      unknown: '미확인',
      inspect_in_obj_explorer: '객체 탐색기에서 검사 ➔',
      clean_completed_title: '완료: 검사된 범위 내 0건의 발견 사항',
      inv_empty_findings_init: '조사가 시작되지 않았습니다. 위에서 진입 경로를 선택하고 목표를 입력한 뒤 "조사 시작"을 클릭하세요.',
      analysis_scope_incomplete: '분석 범위가 불완전했습니다:',
      clean_completed_no_disc: '검사된 구조 내에서 이상 불일치가 감지되지 않았습니다.',
      zero_findings_unverified_fallback: '매핑되지 않은 힙 할당, 비공개 심볼 및 미검사 런타임 불변조건은 검증되지 않은 상태로 유지됩니다.',
      partial_0_findings_title: '부분 분석: 0건의 발견 사항 기록됨',
      inv_blocked_title: '조사 차단됨',
      inv_failed_title: '조사 실패',
      no_active_session: '활성 세션 없음',
      ready_investigation_goal: '조사 목표 대기 중',
      badge_status_idle: '대기 / 준비 완료',
      toast_investigation_started: '조사가 시작되었습니다...',
      toast_investigation_completed: '조사가 완료되었습니다',
      toast_investigation_refreshed: '조사 데이터가 새로고침되었습니다',
    }
  };

  function t(key, fallback) {
    const lang = state.currentLang || 'en';
    if (TRANSLATIONS[lang] && TRANSLATIONS[lang][key] !== undefined) {
      return TRANSLATIONS[lang][key];
    }
    if (TRANSLATIONS.en && TRANSLATIONS.en[key] !== undefined) {
      return TRANSLATIONS.en[key];
    }
    return fallback !== undefined ? fallback : key;
  }

  function applyTranslations(lang) {
    const dict = TRANSLATIONS[lang] || TRANSLATIONS.en;
    if (!dict) return;

    // Elements with data-i18n
    const elements = document.querySelectorAll('[data-i18n]');
    elements.forEach(elem => {
      const key = elem.getAttribute('data-i18n');
      if (dict[key] !== undefined) {
        if (elem.getAttribute('data-i18n-html') === 'true') {
          elem.innerHTML = dict[key];
        } else {
          elem.textContent = dict[key];
        }
      }
    });

    // Elements with data-i18n-placeholder
    const inputs = document.querySelectorAll('[data-i18n-placeholder]');
    inputs.forEach(elem => {
      const key = elem.getAttribute('data-i18n-placeholder');
      if (dict[key] !== undefined) {
        elem.placeholder = dict[key];
      }
    });

    // Elements with data-i18n-title
    const titled = document.querySelectorAll('[data-i18n-title]');
    titled.forEach(elem => {
      const key = elem.getAttribute('data-i18n-title');
      if (dict[key] !== undefined) {
        elem.title = dict[key];
      }
    });
  }

  function setLanguage(lang, persist = true) {
    if (lang !== 'en' && lang !== 'ko') lang = 'en';
    state.currentLang = lang;
    if (persist) {
      try {
        localStorage.setItem('dynamicstate_language', lang);
      } catch (_) {}
    }

    if (el.btnLangEn) el.btnLangEn.classList.toggle('active', lang === 'en');
    if (el.btnLangKo) el.btnLangKo.classList.toggle('active', lang === 'ko');
    document.documentElement.lang = lang;

    applyTranslations(lang);

    // Refresh dynamic views
    if (state.runtime) {
      renderRuntimeOverview(state.runtime);
    }
    renderInvestigationOverview();
    if (state.memorySummary) {
      renderMemorySummary(state.memorySummary);
    }
    renderMemoryObjectsList();
    if (state.selectedObjectId) {
      selectObject(state.selectedObjectId);
    }
    if (state.candidates && state.candidates.length > 0) {
      renderCandidatesTable(state.candidates);
    }
  }

  function initI18n() {
    let initialLang = 'en';
    try {
      const saved = localStorage.getItem('dynamicstate_language');
      if (saved === 'ko' || saved === 'en') {
        initialLang = saved;
      } else if (navigator.language && navigator.language.toLowerCase().startsWith('ko')) {
        initialLang = 'ko';
      }
    } catch (_) {}

    if (el.btnLangEn) {
      el.btnLangEn.addEventListener('click', () => setLanguage('en'));
    }
    if (el.btnLangKo) {
      el.btnLangKo.addEventListener('click', () => setLanguage('ko'));
    }

    setLanguage(initialLang, false);
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

    // Level 1 Primary Header status updates
    if (el.hdrTxtTarget) {
      if (data.pid) el.hdrTxtTarget.textContent = `PID ${data.pid}${data.binary ? ` (${data.binary})` : ''}`;
      else if (state.selectedStateId) el.hdrTxtTarget.textContent = `Snapshot: ${state.selectedStateId}`;
      else el.hdrTxtTarget.textContent = 'No target loaded';
    }
    if (el.hdrBadgeCaptureQuality) {
      const q = data.consistency_level || (status === 'STOPPED' ? 'STOPPED' : (mode === 'LOW_IMPACT' ? 'NON_ATOMIC' : 'UNKNOWN'));
      el.hdrBadgeCaptureQuality.textContent = q;
      el.hdrBadgeCaptureQuality.className = `badge ${q === 'STOPPED' || q === 'ATOMIC' ? 'badge-success' : (q === 'NON_ATOMIC' ? 'badge-warning' : 'badge-neutral')}`;
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

      // Search Query: supports name, type, field name/value, and hex address
      if (!query) return true;
      const matchesId = (o.object_id || '').toLowerCase().includes(query);
      const matchesSemantic = (o.semantic_name || '').toLowerCase().includes(query);
      const matchesDisplayName = (o.display_name || '').toLowerCase().includes(query);
      const matchesType = (o.type || '').toLowerCase().includes(query);
      const matchesCleaned = (o.cleaned_type || '').toLowerCase().includes(query);
      const addrHex = (typeof o.address === 'number' ? '0x' + o.address.toString(16) : String(o.address || '')).toLowerCase();
      const matchesAddress = addrHex.includes(query) || Boolean(o.hex_address && o.hex_address.toLowerCase().includes(query));
      const matchesField = (o.fields || []).some((f) => {
        return (f.name || '').toLowerCase().includes(query) || String(f.value || '').toLowerCase().includes(query);
      });
      return matchesId || matchesSemantic || matchesDisplayName || matchesType || matchesCleaned || matchesAddress || matchesField;
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

  function pushNavHistory(objectId, fieldName = null) {
    if (!objectId) return;
    if (!state.navHistory) state.navHistory = [];
    state.navHistory.push({ objectId, fieldName });
    if (state.navHistory.length > 50) state.navHistory.shift();
    updateNavHistoryControls();
  }

  function navigateBack() {
    if (!state.navHistory || state.navHistory.length === 0) return;
    const prev = state.navHistory.pop();
    updateNavHistoryControls();
    if (prev && prev.objectId) {
      selectObject(prev.objectId, false, prev.fieldName);
    }
  }

  function updateNavHistoryControls() {
    if (el.btnNavBack) {
      el.btnNavBack.disabled = !state.navHistory || state.navHistory.length === 0;
    }
    if (el.navHistoryInfo) {
      el.navHistoryInfo.textContent = `History: ${state.navHistory ? state.navHistory.length : 0}`;
    }
  }

  function updateBreadcrumbs(obj, fieldName = null) {
    if (!el.navBreadcrumbsTrail) return;
    if (!obj) {
      el.navBreadcrumbsTrail.innerHTML = '<span class="crumb-item active">Explorer</span>';
      return;
    }
    const cleanType = obj.cleaned_type || obj.type || 'Object';
    const dispName = obj.display_name || obj.semantic_name || `${cleanType}@${obj.address ? '0x' + Number(obj.address).toString(16) : obj.object_id}`;

    let html = `<span class="crumb-item" id="crumb-root">Explorer</span><span class="crumb-sep">/</span>`;
    if (fieldName) {
      html += `<span class="crumb-item" id="crumb-obj">${escapeHtml(dispName)}</span><span class="crumb-sep">/</span>`;
      html += `<span class="crumb-item active mono text-accent"><code>${escapeHtml(fieldName)}</code></span>`;
    } else {
      html += `<span class="crumb-item active">${escapeHtml(dispName)}</span>`;
    }
    el.navBreadcrumbsTrail.innerHTML = html;

    const crumbObj = el.navBreadcrumbsTrail.querySelector('#crumb-obj');
    if (crumbObj) {
      crumbObj.addEventListener('click', () => {
        selectObject(obj.object_id, false, null);
      });
    }
  }

  let currentNavCandidates = [];

  async function renderCodeNavigation(obj, targetFieldName = null) {
    if (!el.cardCodeNavigation) return;
    if (!obj) {
      if (el.tbodyCandidateFunctions) {
        el.tbodyCandidateFunctions.innerHTML = '<tr><td colspan="5" class="text-muted text-center">Select an object or field to view candidate functions</td></tr>';
      }
      return;
    }

    const cleanType = obj.cleaned_type || obj.canonical_type || (obj.type ? obj.type.replace(/\b(struct|class|enum)\s+/g, '') : 'Unknown');
    const targetLabel = targetFieldName ? `${cleanType}.${targetFieldName}` : `${cleanType} (All)`;
    if (el.badgeCodeNavTarget) el.badgeCodeNavTarget.textContent = targetFieldName ? `Field: ${targetFieldName}` : 'All Object Functions';
    if (el.codeNavTargetName) el.codeNavTargetName.textContent = targetLabel;

    let targetLoc = '—';
    if (targetFieldName) {
      const f = (obj.fields || []).find(field => field.name === targetFieldName);
      if (f && f.decl_file && f.decl_line) {
        targetLoc = `${f.decl_file}:${f.decl_line}`;
      }
    }
    if (targetLoc === '—') {
      const oFile = obj.decl_file || obj.type_decl_file;
      const oLine = obj.decl_line || obj.type_decl_line;
      if (oFile && oLine) {
        targetLoc = `${oFile}:${oLine}`;
      }
    }
    if (el.codeNavTargetLoc) el.codeNavTargetLoc.textContent = targetLoc;

    if (el.codeNavTargetInterp) {
      const interp = obj.synthetic ? 'Interpreted' : 'Observed';
      el.codeNavTargetInterp.textContent = interp;
      el.codeNavTargetInterp.className = 'badge ' + (interp === 'Observed' ? 'badge-success' : 'badge-warning');
    }

    // Try fetching from API or fallback to preloaded
    let navData = null;
    try {
      const q = targetFieldName ? `?field=${encodeURIComponent(targetFieldName)}` : '';
      const snapQ = state.activeStateId ? `${q ? '&' : '?'}snapshot_id=${encodeURIComponent(state.activeStateId)}` : '';
      const res = await apiGet(`/api/objects/${encodeURIComponent(obj.object_id)}/code-navigation${q}${snapQ}`);
      if (res && res.success && res.data) {
        navData = res.data;
      }
    } catch (e) {
      console.warn('Could not fetch code-navigation endpoint:', e);
    }

    if (!navData) {
      navData = obj.code_navigation || { candidates: obj.function_candidates || [] };
    }

    currentNavCandidates = navData.candidates || [];

    // Update tier counts
    const counts = navData.counts_by_tier || {
      observed: currentNavCandidates.filter(c => c.evidence_level === 'observed').length,
      static: currentNavCandidates.filter(c => c.evidence_level === 'static').length,
      indirect: currentNavCandidates.filter(c => c.evidence_level === 'indirect').length,
      unknown: currentNavCandidates.filter(c => c.evidence_level === 'unknown').length,
    };

    if (el.countTierAll) el.countTierAll.textContent = currentNavCandidates.length;
    if (el.countTierObserved) el.countTierObserved.textContent = counts.observed || 0;
    if (el.countTierStatic) el.countTierStatic.textContent = counts.static || 0;
    if (el.countTierIndirect) el.countTierIndirect.textContent = counts.indirect || 0;
    if (el.countTierUnknown) el.countTierUnknown.textContent = counts.unknown || 0;

    applyCandidateFilter();
  }

  function applyCandidateFilter() {
    if (!el.tbodyCandidateFunctions) return;
    const filter = state.candidateTierFilter || 'all';
    const filtered = filter === 'all'
      ? currentNavCandidates
      : currentNavCandidates.filter(c => c.evidence_level === filter);

    if (filtered.length === 0) {
      el.tbodyCandidateFunctions.innerHTML = `<tr><td colspan="5" class="text-muted text-center">No candidate functions found for tier '${escapeHtml(filter)}'</td></tr>`;
      return;
    }

    el.tbodyCandidateFunctions.innerHTML = filtered.map(c => {
      const tier = c.evidence_level || 'unknown';
      const tierClass = tier === 'observed' ? 'tier-observed' : (tier === 'static' ? 'tier-static' : (tier === 'indirect' ? 'tier-indirect' : 'tier-unknown'));
      const loc = c.source_location || '—';
      return `
        <tr>
          <td><strong class="mono text-accent">${escapeHtml(c.function_name)}</strong></td>
          <td><span class="tier-chip ${tierClass}" title="Evidence Tier: ${escapeHtml(tier)}">${escapeHtml(tier)}</span></td>
          <td><span class="mono text-xs">${escapeHtml(loc)}</span></td>
          <td><span class="text-xs">${escapeHtml(c.reason || 'Correlated candidate')}</span></td>
          <td><span class="text-muted text-xs">${escapeHtml(c.limitations || 'Execution unverified')}</span></td>
        </tr>
      `;
    }).join('');
  }

  function selectObject(objectId, pushHistory = true, selectedFieldName = null) {
    if (!objectId) return;
    if (pushHistory && state.selectedObjectId && state.selectedObjectId !== objectId) {
      pushNavHistory(state.selectedObjectId, state.selectedFieldName);
    }
    state.selectedObjectId = objectId;
    state.selectedFieldName = selectedFieldName;

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

    // 2. Update Center Breadcrumb & Nav Toolbar
    if (el.bcCurrentName) {
      el.bcCurrentName.textContent = `${semanticName} (${cleanedType})`;
    }
    updateBreadcrumbs(obj, selectedFieldName);

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

    // DWARF Source Location and Interpretation
    const dwarfLoc = (obj.decl_file && obj.decl_line) ? `${obj.decl_file}:${obj.decl_line}` : (obj.type_decl_file && obj.type_decl_line ? `${obj.type_decl_file}:${obj.type_decl_line}` : '—');
    if (el.inspValDwarfLoc) el.inspValDwarfLoc.textContent = dwarfLoc;

    const interp = obj.synthetic ? 'Interpreted' : (obj.status === 'PARTIAL' ? 'Partial' : 'Observed');
    if (el.inspValInterpretation) {
      el.inspValInterpretation.textContent = interp;
      el.inspValInterpretation.className = 'badge ' + (interp === 'Observed' ? 'badge-success' : 'badge-warning');
    }

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
        el.tableSemanticFields.innerHTML = `<tr><td colspan="7" class="text-muted text-center">No fields defined for this object</td></tr>`;
      }
    } else {
      let fieldsHtml = '';
      fields.forEach((f) => {
        const isRef = Boolean(f.object_ref);
        const mutStatus = normalizeMutability(f.mutability);
        const isMut = mutStatus === 'mutable' || isFieldMutable(f.type, f.mutability);
        const valHtml = formatSemanticValue(f.value, f.type, f.object_ref);
        const cleanedFieldType = f.cleaned_type || (f.type ? f.type.replace(/\b(struct|class|enum)\s+/g, '') : '');
        const fLoc = (f.decl_file && f.decl_line) ? `${getBaseName(f.decl_file)}:${f.decl_line}` : '—';
        const fLocFull = (f.decl_file && f.decl_line) ? `${f.decl_file}:${f.decl_line}` : '';
        const isFieldSelected = Boolean(selectedFieldName && f.name === selectedFieldName);
        const rowStyle = isFieldSelected ? 'style="outline: 2px solid var(--accent);"' : '';

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
          <tr ${rowStyle}>
            <td><strong>${escapeHtml(f.name)}</strong></td>
            <td class="mono text-accent">${escapeHtml(cleanedFieldType)}</td>
            <td>${valHtml}</td>
            <td><span class="mono text-xs text-muted" title="${escapeHtml(fLocFull)}">${escapeHtml(fLoc)}</span></td>
            <td>${refChipHtml}</td>
            <td>${mutBadgeHtml}</td>
            <td>
              ${isMut ? `<button class="field-mutate-btn" data-object-id="${objectId}" data-field-name="${f.name}">⚡ Mutate</button>` : ''}
              <button class="field-code-btn" data-object-id="${objectId}" data-field-name="${f.name}" title="View candidate functions for this field">🔍 Code</button>
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

        // Field Code Navigation button handlers
        el.tableSemanticFields.querySelectorAll('.field-code-btn').forEach((btn) => {
          btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const fName = btn.getAttribute('data-field-name');
            selectObject(objectId, true, fName);
            if (el.cardCodeNavigation) {
              el.cardCodeNavigation.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
          });
        });
      }
    }

    // Render Code Navigation and Candidate Functions
    renderCodeNavigation(obj, selectedFieldName);

    // Update Raw JSON view if currently visible
    if (state.showingRawJson && el.preObjRawJson) {
      el.preObjRawJson.textContent = JSON.stringify(obj, null, 2);
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

  function jumpToObject(objectId, fieldName = null) {
    if (!objectId) return;
    selectObject(objectId, true, fieldName);

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

    // Explorer Nav Toolbar Back Button
    if (el.btnNavBack) {
      el.btnNavBack.addEventListener('click', () => {
        navigateBack();
      });
    }

    // Inspector Formatted vs Raw JSON View Toggle
    if (el.btnViewObjJson) {
      el.btnViewObjJson.addEventListener('click', () => {
        state.showingRawJson = !state.showingRawJson;
        if (el.inspectorScrollBody) {
          el.inspectorScrollBody.style.display = state.showingRawJson ? 'none' : 'block';
        }
        if (el.inspectorRawJsonBody) {
          el.inspectorRawJsonBody.style.display = state.showingRawJson ? 'block' : 'none';
        }
        el.btnViewObjJson.textContent = state.showingRawJson ? 'Formatted' : 'JSON';
        if (state.showingRawJson && el.preObjRawJson) {
          const obj = state.objects.find(o => o.object_id === state.selectedObjectId);
          el.preObjRawJson.textContent = obj ? JSON.stringify(obj, null, 2) : '// No object selected';
        }
      });
    }

    if (el.btnCopyObjJson) {
      el.btnCopyObjJson.addEventListener('click', () => {
        if (el.preObjRawJson && el.preObjRawJson.textContent) {
          navigator.clipboard.writeText(el.preObjRawJson.textContent).then(() => {
            showToast('Object JSON copied to clipboard', 'success');
          });
        }
      });
    }

    // Candidate Functions Tier Filter Chips
    if (el.codeNavTierChips) {
      el.codeNavTierChips.querySelectorAll('.tier-filter-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          el.codeNavTierChips.querySelectorAll('.tier-filter-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
          state.candidateTierFilter = chip.getAttribute('data-tier') || 'all';
          applyCandidateFilter();
        });
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
  // Investigation Overview (Phase C)
  // --------------------------------------------------------------------------

  // --------------------------------------------------------------------------
  // Investigation Overview (Modernized Investigation-First Workspace)
  // --------------------------------------------------------------------------

  function initInvestigationOverview() {
    if (el.btnRunInvestigation) {
      el.btnRunInvestigation.addEventListener('click', runInvestigation);
    }
    if (el.btnRunInvestigationCycle) {
      el.btnRunInvestigationCycle.addEventListener('click', runInvestigationCycle);
    }
    if (el.btnStepInvestigationCycle) {
      el.btnStepInvestigationCycle.addEventListener('click', stepInvestigationCycle);
    }
    if (el.btnRefreshInvestigation) {
      el.btnRefreshInvestigation.addEventListener('click', loadActiveInvestigation);
    }
    if (el.btnCloseDrilldown && el.invCardDrilldown) {
      el.btnCloseDrilldown.addEventListener('click', () => {
        el.invCardDrilldown.style.display = 'none';
      });
    }

    // Launchpad Entry Switcher (Offline Snapshot vs Live Process)
    if (el.btnEntrySnapshot && el.btnEntryLive) {
      el.btnEntrySnapshot.addEventListener('click', () => {
        el.btnEntrySnapshot.classList.add('active');
        el.btnEntryLive.classList.remove('active');
        if (el.panelEntrySnapshot) el.panelEntrySnapshot.style.display = 'block';
        if (el.panelEntryLive) el.panelEntryLive.style.display = 'none';
      });

      el.btnEntryLive.addEventListener('click', () => {
        el.btnEntryLive.classList.add('active');
        el.btnEntrySnapshot.classList.remove('active');
        if (el.panelEntryLive) el.panelEntryLive.style.display = 'block';
        if (el.panelEntrySnapshot) el.panelEntrySnapshot.style.display = 'none';
      });
    }

    // Inline Snapshot Comparison button
    if (el.btnRunInlineCompare) {
      el.btnRunInlineCompare.addEventListener('click', () => {
        const snapA = el.invCmpSelectA ? el.invCmpSelectA.value.trim() : '';
        const snapB = el.invCmpSelectB ? el.invCmpSelectB.value.trim() : '';
        if (!snapA || !snapB) {
          showToast('Please select both Baseline A and Observed B snapshots to compare.', 'warning');
          return;
        }
        if (snapA === snapB) {
          showToast('Select two different snapshots to compare state changes.', 'warning');
          return;
        }
        compareSnapshots(snapA, snapB);
      });
    }

    // Close Lineage Trace button
    if (el.btnCloseLineage && el.invLineageContainer) {
      el.btnCloseLineage.addEventListener('click', () => {
        el.invLineageContainer.style.display = 'none';
      });
    }

    // Filter pills for findings
    const filterPills = [
      { btn: document.getElementById('btn-filter-find-all'), filter: 'all' },
      { btn: document.getElementById('btn-filter-find-facts'), filter: 'fact' },
      { btn: document.getElementById('btn-filter-find-hypo'), filter: 'hypothesis' },
      { btn: document.getElementById('btn-filter-find-unknown'), filter: 'unknown' },
    ];
    filterPills.forEach(({ btn, filter }) => {
      if (btn) {
        btn.addEventListener('click', () => {
          filterPills.forEach(p => p.btn && p.btn.classList.toggle('active', p.filter === filter));
          state.investigationFindingFilter = filter;
          renderFindings();
        });
      }
    });

    if (el.btnDownloadLedger) {
      el.btnDownloadLedger.addEventListener('click', () => {
        if (!state.activeInvestigation || !state.activeInvestigation.evidence_ledger) {
          showToast('No evidence ledger to export.', 'warning');
          return;
        }
        const blob = new Blob([JSON.stringify(state.activeInvestigation.evidence_ledger, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `evidence_ledger_${state.activeInvestigation.investigation_id || 'session'}.json`;
        a.click();
        URL.revokeObjectURL(url);
      });
    }

    if (el.btnModalCompare) {
      el.btnModalCompare.addEventListener('click', () => {
        const snapA = prompt('Enter first snapshot ID or path to compare:');
        if (!snapA) return;
        const snapB = prompt('Enter second snapshot ID or path to compare:');
        if (!snapB) return;
        compareSnapshots(snapA.trim(), snapB.trim());
      });
    }
  }

  let investigationLoadSeq = 0;

  function renderRecentInvestigationSessions(sessionsList, activeId) {
    if (!el.invRecentSessionsContainer) return;
    if (Array.isArray(sessionsList) && sessionsList.length > 0) {
      el.invRecentSessionsContainer.style.display = 'flex';
      if (el.invRecentSessionsList) {
        el.invRecentSessionsList.innerHTML = sessionsList.slice(-6).reverse().map(sess => {
          const sid = sess.investigation_id || 'session';
          const isActive = sid === activeId;
          const statusBadge = sess.status === 'COMPLETED' ? 'badge-success' : (sess.status === 'PARTIAL' ? 'badge-warning' : (sess.status === 'BLOCKED' ? 'badge-danger' : 'badge-danger'));
          return `
            <span class="inv-session-pill ${isActive ? 'active' : ''}" onclick="window.__loadInvestigationSession('${escapeHtml(sid)}')">
              ${escapeHtml(sid.substring(0, 14))}... <span class="badge ${statusBadge} text-xs">${escapeHtml(sess.status || '')}</span>
            </span>
          `;
        }).join('');
      }
    } else {
      el.invRecentSessionsContainer.style.display = 'none';
      if (el.invRecentSessionsList) el.invRecentSessionsList.innerHTML = '';
    }
  }

  async function loadRecentInvestigationSessions() {
    try {
      const res = await apiGet('/api/investigations');
      if (res.success && Array.isArray(res.data)) {
        renderRecentInvestigationSessions(res.data, state.selectedInvestigationId);
      } else {
        renderRecentInvestigationSessions([], null);
      }
    } catch (_) {
      renderRecentInvestigationSessions([], null);
    }
  }

  window.__loadInvestigationSession = async function (investigationId) {
    if (!investigationId) return;
    await loadActiveInvestigation(investigationId);
  };

  async function loadActiveInvestigation(targetSessionId) {
    const seq = ++investigationLoadSeq;
    try {
      const res = await apiGet('/api/investigations');
      if (seq !== investigationLoadSeq) return;

      const sessions = (res.success && Array.isArray(res.data)) ? res.data : [];

      if (sessions.length === 0) {
        state.activeInvestigation = null;
        state.selectedInvestigationId = null;
        try { sessionStorage.removeItem('dynamicstate_selected_inv_id'); } catch (_) {}
        renderRecentInvestigationSessions([], null);
        renderEmptyInvestigationOverview();
        return;
      }

      // Preserve selection priority:
      // 1. Explicit targetSessionId passed into function
      // 2. state.selectedInvestigationId if it exists in sessions
      // 3. Stored session in sessionStorage if it exists in sessions
      // 4. Latest session in list
      let chosenId = targetSessionId;
      if (!chosenId && state.selectedInvestigationId && sessions.some(s => s.investigation_id === state.selectedInvestigationId)) {
        chosenId = state.selectedInvestigationId;
      }
      if (!chosenId) {
        try {
          const stored = sessionStorage.getItem('dynamicstate_selected_inv_id');
          if (stored && sessions.some(s => s.investigation_id === stored)) {
            chosenId = stored;
          }
        } catch (_) {}
      }
      if (!chosenId) {
        chosenId = sessions[sessions.length - 1].investigation_id;
      }

      const repRes = await apiGet(`/api/investigation/report?investigation_id=${encodeURIComponent(chosenId)}`);
      if (seq !== investigationLoadSeq) return;

      if (repRes.success && repRes.data) {
        state.activeInvestigation = repRes.data;
        state.selectedInvestigationId = chosenId;
        try { sessionStorage.setItem('dynamicstate_selected_inv_id', chosenId); } catch (_) {}
        renderRecentInvestigationSessions(sessions, chosenId);
        renderInvestigationOverview();
      } else {
        // Stale or deleted session ID: try latest session instead
        const fallback = sessions[sessions.length - 1].investigation_id;
        if (fallback !== chosenId) {
          const fbRes = await apiGet(`/api/investigation/report?investigation_id=${encodeURIComponent(fallback)}`);
          if (seq !== investigationLoadSeq) return;
          if (fbRes.success && fbRes.data) {
            state.activeInvestigation = fbRes.data;
            state.selectedInvestigationId = fallback;
            try { sessionStorage.setItem('dynamicstate_selected_inv_id', fallback); } catch (_) {}
            renderRecentInvestigationSessions(sessions, fallback);
            renderInvestigationOverview();
            return;
          }
        }
        state.activeInvestigation = null;
        state.selectedInvestigationId = null;
        try { sessionStorage.removeItem('dynamicstate_selected_inv_id'); } catch (_) {}
        renderRecentInvestigationSessions(sessions, null);
        renderEmptyInvestigationOverview();
      }
    } catch (e) {
      if (seq !== investigationLoadSeq) return;
      console.warn('Failed to load active investigation:', e);
      renderEmptyInvestigationOverview();
    }
  }

  async function runInvestigation() {
    const goal = (el.invInputGoal && el.invInputGoal.value.trim()) || 'General state investigation';
    
    // Check which entry panel is active (Snapshot vs Live)
    const isLive = el.panelEntryLive && el.panelEntryLive.style.display !== 'none';
    let snapshotId, debugImage, authorizeTarget, pid;

    if (isLive) {
      snapshotId = undefined;
      const rawPid = (el.invInputLiveTarget && el.invInputLiveTarget.value.trim()) || '';
      if (!rawPid) {
        showToast('Please specify a target PID for live capture.', 'warning');
        return;
      }
      // Strictly require a complete decimal integer without signs, letters, or decimals
      if (!/^\d+$/.test(rawPid)) {
        showToast(`Invalid PID format: "${rawPid}". Please enter a positive decimal integer without signs or letters.`, 'error');
        return;
      }
      pid = parseInt(rawPid, 10);
      if (isNaN(pid) || pid <= 0 || pid > 2147483647 || String(pid) !== rawPid) {
        showToast(`PID ${rawPid} is out of valid range (1 - 2147483647).`, 'error');
        return;
      }
      debugImage = (el.invInputLiveDebugImage && el.invInputLiveDebugImage.value.trim()) || undefined;
      authorizeTarget = el.invCheckAuthorize ? el.invCheckAuthorize.checked : false;
    } else {
      pid = undefined;
      snapshotId = (el.invSelectSnapshot && el.invSelectSnapshot.value) || undefined;
      debugImage = (el.invInputDebugImage && el.invInputDebugImage.value.trim()) || undefined;
      authorizeTarget = false;
    }

    if (el.btnRunInvestigation) {
      el.btnRunInvestigation.disabled = true;
      el.btnRunInvestigation.textContent = '⏳ Investigating...';
    }

    // Set intermediate running state
    if (el.invBadgeStatus) {
      el.invBadgeStatus.textContent = 'RUNNING';
      el.invBadgeStatus.className = 'badge badge-info';
    }
    if (el.hdrBadgeInvestigationState) {
      el.hdrBadgeInvestigationState.textContent = 'RUNNING';
      el.hdrBadgeInvestigationState.className = 'badge badge-info';
    }
    if (el.invFindingsList) {
      el.invFindingsList.innerHTML = '<div class="empty-state text-xs p-3">⏳ Investigation in progress... Analyzing runtime memory and verifying typed structures.</div>';
    }

    try {
      showToast('Starting evidence-first investigation...', 'info');
      const payload = {
        goal: goal,
        snapshot_id: snapshotId,
        pid: pid,
        debug_image: debugImage,
        authorize_target: authorizeTarget,
      };

      const res = await apiPost('/api/investigation/start', payload);
      if (res.success && res.data) {
        state.activeInvestigation = res.data;
        state.selectedInvestigationId = res.data.investigation_id;
        try { sessionStorage.setItem('dynamicstate_selected_inv_id', res.data.investigation_id); } catch (_) {}
        renderInvestigationOverview();
        await loadActiveInvestigation(res.data.investigation_id);
        if (res.data.status === 'BLOCKED') {
          showToast('Investigation blocked: Target authorization required', 'warning');
        } else {
          showToast('Investigation completed successfully!', 'success');
        }
      } else {
        const msg = (res.error && res.error.message) || 'Investigation failed';
        showToast(`Investigation error: ${msg}`, 'error');
        if (res.data) {
          state.activeInvestigation = res.data;
          state.selectedInvestigationId = res.data.investigation_id;
          try { sessionStorage.setItem('dynamicstate_selected_inv_id', res.data.investigation_id); } catch (_) {}
          renderInvestigationOverview();
          await loadActiveInvestigation(res.data.investigation_id);
        } else {
          renderFailedInvestigationOverview(msg);
        }
      }
    } catch (err) {
      showToast(`Investigation error: ${String(err)}`, 'error');
      renderFailedInvestigationOverview(String(err));
    } finally {
      if (el.btnRunInvestigation) {
        el.btnRunInvestigation.disabled = false;
        el.btnRunInvestigation.textContent = '🚀 Start Investigation';
      }
    }
  }

  async function compareSnapshots(snapA, snapB) {
    if (!state.activeInvestigation || !state.activeInvestigation.investigation_id) {
      showToast('Start an investigation first to record comparison evidence.', 'warning');
      return;
    }
    try {
      showToast(`Comparing ${snapA} and ${snapB}...`, 'info');
      const res = await apiPost('/api/investigation/compare', {
        investigation_id: state.activeInvestigation.investigation_id,
        snapshot_a: snapA,
        snapshot_b: snapB,
      });
      if (res.success) {
        showToast('Comparison completed!', 'success');
        await loadActiveInvestigation();
      } else {
        showToast(`Comparison error: ${res.error?.message || 'Failed'}`, 'error');
      }
    } catch (err) {
      showToast(`Comparison error: ${String(err)}`, 'error');
    }
  }

  function renderFailedInvestigationOverview(errorMsg) {
    if (el.invBadgeStatus) {
      el.invBadgeStatus.textContent = 'FAILED';
      el.invBadgeStatus.className = 'badge badge-danger';
    }
    if (el.hdrBadgeInvestigationState) {
      el.hdrBadgeInvestigationState.textContent = 'FAILED';
      el.hdrBadgeInvestigationState.className = 'badge badge-danger';
    }
    if (el.invAlertBanner) {
      el.invAlertBanner.className = 'banner banner-danger mb-3';
      el.invAlertBanner.style.display = 'flex';
      if (el.invAlertIcon) el.invAlertIcon.textContent = '❌';
      if (el.invAlertMessage) el.invAlertMessage.innerHTML = `<strong>Investigation Failed:</strong> ${escapeHtml(errorMsg)}`;
    }
    if (el.invFindingsList) {
      el.invFindingsList.innerHTML = `<div class="empty-state text-xs p-3 text-danger">Investigation failed: ${escapeHtml(errorMsg)}</div>`;
    }
  }

  function renderEmptyInvestigationOverview() {
    if (el.invBadgeStatus) {
      el.invBadgeStatus.textContent = t('badge_status_idle', 'IDLE / READY');
      el.invBadgeStatus.className = 'badge badge-info';
    }
    if (el.hdrBadgeInvestigationState) {
      el.hdrBadgeInvestigationState.textContent = 'NOT_STARTED';
      el.hdrBadgeInvestigationState.className = 'badge badge-neutral';
    }
    if (el.invTxtId) el.invTxtId.textContent = t('ready_investigation_goal', 'Ready for investigation goal');
    if (el.invAlertBanner) el.invAlertBanner.style.display = 'none';

    if (el.invFindingsList) {
      el.invFindingsList.innerHTML = `<div class="empty-state text-xs p-3">${t('inv_empty_findings_init', 'Investigation not started. Select an entry path above, enter an objective, and click "Start Investigation".')}</div>`;
    }
    if (el.invStepsContainer) {
      el.invStepsContainer.innerHTML = `<div class="empty-state text-xs p-3">${t('empty_next_steps_init', 'Start an investigation to receive evidence-driven recommendations.')}</div>`;
    }
    if (el.invComparisonsContent) {
      el.invComparisonsContent.innerHTML = `<div class="empty-state text-xs p-3">${t('empty_no_comparison', 'No comparison performed yet. Select two snapshots above to isolate state diffs.')}</div>`;
    }
    if (el.invStaticLinksList) {
      el.invStaticLinksList.innerHTML = `<div class="empty-state text-xs p-3">${t('empty_static_links_init', 'No static code links resolved yet. Provide a valid debug image to correlate runtime objects to source symbols.')}</div>`;
    }
    populateInvestigationSnapshots();
  }

  function populateInvestigationSnapshots() {
    const snapshots = (state.states && state.states.length > 0) ? state.states : [];
    
    // 1. Populate Target Snapshot select
    if (el.invSelectSnapshot) {
      const currVal = el.invSelectSnapshot.value;
      el.invSelectSnapshot.innerHTML = '<option value="">(Current / Active State)</option>';
      snapshots.forEach(s => {
        const sid = s.state_id || s.snapshot_id || s;
        const opt = document.createElement('option');
        opt.value = sid;
        opt.textContent = `Snapshot: ${sid}`;
        if (sid === currVal) opt.selected = true;
        el.invSelectSnapshot.appendChild(opt);
      });
    }

    // 2. Populate Comparison Snapshot A and Snapshot B selects
    if (el.invCmpSelectA) {
      const currA = el.invCmpSelectA.value;
      el.invCmpSelectA.innerHTML = '<option value="">(Select Snapshot)</option>';
      snapshots.forEach((s, idx) => {
        const sid = s.state_id || s.snapshot_id || s;
        const opt = document.createElement('option');
        opt.value = sid;
        opt.textContent = `${sid}`;
        if (sid === currA || (!currA && idx === 0)) opt.selected = true;
        el.invCmpSelectA.appendChild(opt);
      });
    }

    if (el.invCmpSelectB) {
      const currB = el.invCmpSelectB.value;
      el.invCmpSelectB.innerHTML = '<option value="">(Select Snapshot)</option>';
      snapshots.forEach((s, idx) => {
        const sid = s.state_id || s.snapshot_id || s;
        const opt = document.createElement('option');
        opt.value = sid;
        opt.textContent = `${sid}`;
        if (sid === currB || (!currB && idx === 1)) opt.selected = true;
        el.invCmpSelectB.appendChild(opt);
      });
    }
  }

  function renderInvestigationOverview() {
    populateInvestigationSnapshots();
    const inv = state.activeInvestigation;
    if (!inv) {
      renderEmptyInvestigationOverview();
      return;
    }

    const st = inv.status || 'UNKNOWN';

    // Status Banner & Header Pill
    if (el.invBadgeStatus) {
      el.invBadgeStatus.textContent = st;
      el.invBadgeStatus.className = `badge ${st === 'COMPLETED' ? 'badge-success' : (st === 'PARTIAL' ? 'badge-warning' : (st === 'BLOCKED' ? 'badge-danger' : 'badge-danger'))}`;
    }
    if (el.hdrBadgeInvestigationState) {
      el.hdrBadgeInvestigationState.textContent = st;
      el.hdrBadgeInvestigationState.className = `badge ${st === 'COMPLETED' ? 'badge-success' : (st === 'PARTIAL' ? 'badge-warning' : (st === 'BLOCKED' ? 'badge-danger' : 'badge-info'))}`;
    }
    if (el.invTxtId) {
      el.invTxtId.textContent = `Session: ${inv.investigation_id || 'N/A'}`;
    }

    // Stage progress pills
    const stages = inv.stages || {};
    const updateStagePill = (id, stageName) => {
      const p = document.getElementById(id);
      if (p) {
        const s = stages[stageName]?.status || 'PENDING';
        p.className = `stage-pill ${s.toLowerCase()}`;
        p.title = `${stageName}: ${s}`;
      }
    };
    updateStagePill('pill-stage-identity', 'target_identity');
    updateStagePill('pill-stage-quality', 'capture_quality');
    updateStagePill('pill-stage-semantic', 'semantic_interpretation');
    updateStagePill('pill-stage-comparison', 'observation_comparison');
    updateStagePill('pill-stage-static', 'static_code_link');
    updateStagePill('pill-stage-synthesis', 'report_synthesis');

    // Dynamic Alert Banner Handling
    const idInfo = stages.target_identity?.details || inv.target_identity || {};
    const qInfo = stages.capture_quality?.details || inv.capture_quality || {};
    const bStatus = idInfo.build_id_status || 'NOT_AVAILABLE';

    let totalFindings = 0;
    if (inv.findings && typeof inv.findings === 'object' && !Array.isArray(inv.findings)) {
      totalFindings = (inv.findings.observed_facts?.length || 0) + (inv.findings.hypotheses?.length || 0) + (inv.findings.unknowns?.length || 0);
    } else if (Array.isArray(inv.findings)) {
      totalFindings = inv.findings.length;
    } else if (inv.findings_count !== undefined) {
      totalFindings = inv.findings_count;
    }

    if (el.invAlertBanner) {
      if (st === 'BLOCKED') {
        el.invAlertBanner.className = 'banner banner-danger mb-3';
        el.invAlertBanner.style.display = 'flex';
        if (el.invAlertIcon) el.invAlertIcon.textContent = '🛑';
        const pidVal = idInfo.pid || inv.target_ref?.pid;
        const errText = idInfo.error || stages.target_identity?.details?.error || inv.summary?.error || '';
        let msg = 'Target process authorization required for live process capture.';
        if (pidVal) {
          msg = `Target process authorization required for live capture of PID ${escapeHtml(pidVal)}. Inspection blocked without stopping the process.`;
        }
        if (errText) msg = escapeHtml(errText);
        if (el.invAlertMessage) {
          el.invAlertMessage.innerHTML = `<strong>Investigation Blocked:</strong> ${msg}`;
        }
      } else if (bStatus === 'MISMATCH') {
        el.invAlertBanner.className = 'banner banner-warning mb-3';
        el.invAlertBanner.style.display = 'flex';
        if (el.invAlertIcon) el.invAlertIcon.textContent = '🛑';
        if (el.invAlertMessage) {
          el.invAlertMessage.innerHTML = `<strong>Investigation Blocked:</strong> Build-ID or identity mismatch detected (${escapeHtml(idInfo.build_id_reason || 'Target binary does not match debug artifact')}). Semantic reconstruction stopped to prevent false interpretations.`;
        }
      } else if (st === 'FAILED') {
        el.invAlertBanner.className = 'banner banner-danger mb-3';
        el.invAlertBanner.style.display = 'flex';
        if (el.invAlertIcon) el.invAlertIcon.textContent = '❌';
        const failMsg = inv.summary?.error || stages.target_identity?.details?.error || stages.capture_quality?.details?.error || 'Investigation stage failed.';
        if (el.invAlertMessage) {
          el.invAlertMessage.innerHTML = `<strong>Investigation Failed:</strong> ${escapeHtml(failMsg)}`;
        }
      } else if (st === 'PARTIAL' || qInfo.consistency_level === 'NON_ATOMIC') {
        el.invAlertBanner.className = 'banner banner-warning mb-3';
        el.invAlertBanner.style.display = 'flex';
        if (el.invAlertIcon) el.invAlertIcon.textContent = '⚠️';
        if (el.invAlertMessage) {
          el.invAlertMessage.innerHTML = `<strong>Partial Reconstruction Notice:</strong> Zero-stop non-atomic capture or missing memory regions. Some object fields or symbol links may be incomplete or reflect cross-region execution skew.`;
        }
      } else if (st === 'COMPLETED' && totalFindings === 0) {
        el.invAlertBanner.className = 'banner banner-info mb-3';
        el.invAlertBanner.style.display = 'flex';
        if (el.invAlertIcon) el.invAlertIcon.textContent = 'ℹ️';
        const sc = inv.summary?.scope || {};
        const objCount = sc.objects_examined ?? (stages.semantic_interpretation?.details?.objects_count || 0);
        const rootCount = sc.roots_examined ?? (stages.semantic_interpretation?.details?.roots_count || 0);
        const scopeDesc = objCount > 0 ? `inspected ${objCount} objects, ${rootCount} roots` : 'inspected scope';
        const notice = inv.summary?.zero_findings_notice || `No anomalies detected in inspected scope (${scopeDesc}). Unexamined memory regions, private symbols, and uninspected code paths remain unverified.`;
        if (el.invAlertMessage) {
          el.invAlertMessage.innerHTML = `<strong>Investigation Completed (0 Findings):</strong> ${escapeHtml(notice)}`;
        }
      } else {
        el.invAlertBanner.style.display = 'none';
      }
    }

    // 1. Target & Build Identity Card
    if (el.invTxtExec) el.invTxtExec.textContent = idInfo.executable || 'offline_artifact';
    if (el.invTxtTargetBid) el.invTxtTargetBid.textContent = idInfo.target_build_id || 'N/A';
    if (el.invTxtDebugImage) el.invTxtDebugImage.textContent = idInfo.debug_image || 'None';
    if (el.invTxtDebugBid) el.invTxtDebugBid.textContent = idInfo.debug_build_id || 'N/A';
    if (el.invTxtPid) {
      const pidVal = idInfo.pid || inv.target_ref?.pid;
      el.invTxtPid.textContent = pidVal ? `PID ${pidVal}` : 'Offline';
    }
    if (el.invBadgeBuildStatus) {
      el.invBadgeBuildStatus.textContent = bStatus;
      const isOk = bStatus === 'VERIFIED_MATCH' || bStatus === 'VERIFIED';
      const isMismatch = bStatus === 'MISMATCH';
      el.invBadgeBuildStatus.className = `badge ${isOk ? 'badge-success' : (isMismatch ? 'badge-danger' : 'badge-warning')}`;
    }
    const reasonEl = document.getElementById('inv-txt-build-reason');
    if (reasonEl) reasonEl.textContent = idInfo.build_id_reason || '';
    const persistEl = document.getElementById('inv-txt-persistence');
    if (persistEl) persistEl.textContent = inv.persistence || 'EPHEMERAL_PROCESS_LOCAL';

    // Update Header Target & Quality pills
    if (el.hdrTxtTarget) {
      const pidVal = idInfo.pid || inv.target_ref?.pid;
      if (inv.snapshot_id) el.hdrTxtTarget.textContent = `Snapshot: ${inv.snapshot_id}`;
      else if (pidVal) el.hdrTxtTarget.textContent = `Live PID: ${pidVal}`;
      else if (idInfo.executable) el.hdrTxtTarget.textContent = idInfo.executable;
      else el.hdrTxtTarget.textContent = 'Target: Offline';
    }
    if (el.hdrBadgeCaptureQuality && qInfo.consistency_level) {
      el.hdrBadgeCaptureQuality.textContent = qInfo.consistency_level;
      el.hdrBadgeCaptureQuality.className = `badge ${qInfo.consistency_level === 'STOPPED' || qInfo.consistency_level === 'ATOMIC' ? 'badge-success' : (qInfo.consistency_level === 'NON_ATOMIC' ? 'badge-warning' : 'badge-neutral')}`;
    }

    // 2. Capture Quality & Consistency Card
    const consLevel = qInfo.consistency_level || 'UNKNOWN';
    if (el.invTxtConsistency) el.invTxtConsistency.textContent = consLevel;
    if (el.invBadgeConsistency) {
      el.invBadgeConsistency.textContent = consLevel;
      el.invBadgeConsistency.className = `badge ${consLevel === 'STOPPED' || consLevel === 'SIGNAL_STOPPED' || consLevel === 'ATOMIC' ? 'badge-success' : (consLevel === 'NON_ATOMIC' ? 'badge-warning' : '')}`;
    }
    if (el.invConsistencyWarning) {
      el.invConsistencyWarning.style.display = consLevel === 'NON_ATOMIC' ? 'block' : 'none';
    }
    const backendName = idInfo.capture_backend || inv.target_ref?.capture_backend || 'offline';
    const fallbackNotice = inv.target_ref?.backend_fallback ? ' (fallback)' : '';
    if (el.invTxtBackend) el.invTxtBackend.textContent = `${backendName}${fallbackNotice}`;
    if (el.invTxtStopMech) {
      const stopMech = qInfo.stop_mechanism || 'NONE';
      const stopStatus = qInfo.stopped_threads ? ' (confirmed)' : (stopMech !== 'NONE' ? ' (unconfirmed)' : '');
      el.invTxtStopMech.textContent = `${stopMech}${stopStatus}`;
    }
    if (el.invTxtDuration) {
      el.invTxtDuration.textContent = qInfo.duration_us ? `${(qInfo.duration_us / 1000).toFixed(2)} ms` : 'N/A';
    }
    if (el.invTxtBytes) {
      const bCap = qInfo.bytes_captured ?? 0;
      const bReq = qInfo.bytes_requested ?? bCap;
      const bOmit = qInfo.bytes_omitted ? ` (${qInfo.bytes_omitted}B omitted)` : '';
      el.invTxtBytes.textContent = `${bCap}B / ${bReq}B${bOmit}`;
    }
    if (el.invTxtRegions) {
      const rRead = qInfo.regions_read ?? 0;
      const rAtt = qInfo.regions_attempted ?? 0;
      el.invTxtRegions.textContent = `${rRead} / ${rAtt}`;
    }
    if (el.invTxtReadStatus) {
      const pReads = qInfo.partial_reads || 0;
      const fReads = qInfo.failed_reads || 0;
      const oRegions = qInfo.omitted_regions_count || 0;
      el.invTxtReadStatus.textContent = `${pReads} / ${fReads} / ${oRegions}`;
    }
    if (el.invTxtPartialReads) el.invTxtPartialReads.textContent = String(qInfo.partial_reads || 0);
    if (el.invTxtFailedReads) el.invTxtFailedReads.textContent = String(qInfo.failed_reads || 0);
    if (el.invLimitationsContainer) {
      const lims = qInfo.limitations || [];
      if (lims.length > 0) {
        el.invLimitationsContainer.innerHTML = lims.map(l => `<div>&bull; ${escapeHtml(l)}</div>`).join('');
      } else {
        el.invLimitationsContainer.innerHTML = '<em>No known limitations recorded.</em>';
      }
    }

    // 3. Render Comparisons
    renderComparisons(inv.comparisons || inv.comparison_results || []);

    // 4. Render Recommended Next Steps
    renderNextSteps(inv.recommended_next_steps || inv.next_steps || []);

    // 5. Render Findings
    renderFindings();

    // 6. Render Static Links
    const staticInfo = stages.static_code_link?.details || inv.static_code_links || {};
    renderStaticLinks(staticInfo);

    // 7. Render Raw Evidence
    const ledger = inv.evidence_ledger || {};
    renderRawEvidence(ledger);

    // 8. Render Audit Timeline
    renderTimeline(inv.timeline || []);
  }

  function renderFindings() {
    if (!el.invFindingsList) return;
    const inv = state.activeInvestigation;
    if (!inv) {
      el.invFindingsList.innerHTML = '<div class="empty-state text-xs p-3">Investigation not started. Select an entry path and click "Start Investigation".</div>';
      return;
    }

    let findings = [];
    if (inv.findings && typeof inv.findings === 'object' && !Array.isArray(inv.findings)) {
      findings = [
        ...(inv.findings.observed_facts || []),
        ...(inv.findings.hypotheses || []),
        ...(inv.findings.unknowns || []),
      ];
    } else if (Array.isArray(inv.findings)) {
      findings = inv.findings;
    }

    const filter = state.investigationFindingFilter || 'all';
    const filtered = filter === 'all' ? findings : findings.filter(f => f.category === filter);

    if (filtered.length === 0) {
      if (inv.status === 'COMPLETED' && findings.length === 0) {
        const sc = inv.summary?.scope || {};
        const objCount = sc.objects_examined ?? (stages.semantic_interpretation?.details?.objects_count || 0);
        const rootCount = sc.roots_examined ?? (stages.semantic_interpretation?.details?.roots_count || 0);
        const scopeText = objCount > 0 
          ? (state.currentLang === 'ko' ? `${objCount}개 객체 및 ${rootCount}개 루트 검사 완료.` : `Inspected ${objCount} objects and ${rootCount} roots.`) 
          : (state.currentLang === 'ko' ? '사용 가능한 대상 메모리 검사 완료.' : 'Inspected available target memory.');
        const unresolvedList = Array.isArray(sc.unresolved_checks) && sc.unresolved_checks.length > 0 
          ? `<ul class="mt-2 text-muted" style="padding-left: 18px; margin-bottom: 0;">${sc.unresolved_checks.map(u => `<li>${escapeHtml(u)}</li>`).join('')}</ul>`
          : `<div class="text-muted mt-1">${t('zero_findings_unverified_fallback', 'Unmapped heap allocations, private symbols, and uninspected runtime invariants remain unverified.')}</div>`;

        el.invFindingsList.innerHTML = `
          <div class="empty-state-clean text-xs p-3" style="background-color: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.25); border-radius: 6px;">
            <strong style="color: var(--accent); font-size: 0.95rem;">ℹ️ ${t('clean_completed_title', 'Completed: 0 Findings in Inspected Scope')}</strong>
            <div class="mt-1">${scopeText} ${t('clean_completed_no_disc', 'No discrepancies identified within inspected structures.')}</div>
            <div class="mt-2" style="font-weight: 600; color: var(--text-secondary);">${t('scope_boundaries_header', 'Scope Boundaries &amp; Uninspected Checks:')}</div>
            ${unresolvedList}
          </div>
        `;
      } else if (inv.status === 'PARTIAL' && findings.length === 0) {
        const partialReason = stages.semantic_interpretation?.details?.error 
          || stages.target_identity?.details?.build_id_reason 
          || stages.capture_quality?.details?.error 
          || inv.summary?.error 
          || (state.currentLang === 'ko' ? '대상 스냅샷을 완전히 해결할 수 없거나 디버그 아티팩트가 불완전합니다.' : 'Target snapshot could not be fully resolved or debug artifacts were incomplete.');
        el.invFindingsList.innerHTML = `
          <div class="empty-state text-xs p-3" style="background-color: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 6px;">
            <strong style="color: var(--warning); font-size: 0.95rem;">⚠️ ${t('partial_0_findings_title', 'Partial Analysis: 0 Findings Recorded')}</strong>
            <div class="text-muted mt-1">${t('analysis_scope_incomplete', 'Analysis scope was incomplete:')} ${escapeHtml(partialReason)}</div>
            <div class="text-muted mt-1">${t('zero_findings_not_clean', 'Zero findings recorded does NOT indicate clean state; inspection was restricted.')}</div>
          </div>
        `;
      } else if (inv.status === 'BLOCKED') {
        const blockReason = stages.target_identity?.details?.error || inv.summary?.error || (state.currentLang === 'ko' ? '대상 권한 승인 또는 식별 검증으로 인해 분석이 차단되었습니다.' : 'Target authorization or identity validation blocked analysis.');
        el.invFindingsList.innerHTML = `
          <div class="empty-state text-xs p-3" style="background-color: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 6px;">
            <strong style="color: var(--danger); font-size: 0.95rem;">🛑 ${t('inv_blocked_title', 'Investigation Blocked')}</strong>
            <div class="text-muted mt-1">${escapeHtml(blockReason)}</div>
          </div>
        `;
      } else if (inv.status === 'FAILED') {
        const failReason = inv.summary?.error || stages.target_identity?.details?.error || stages.capture_quality?.details?.error || (state.currentLang === 'ko' ? '조사 단계 실행 실패.' : 'Investigation stage failed.');
        el.invFindingsList.innerHTML = `
          <div class="empty-state text-xs p-3" style="background-color: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 6px;">
            <strong style="color: var(--danger); font-size: 0.95rem;">❌ ${t('inv_failed_title', 'Investigation Failed')}</strong>
            <div class="text-muted mt-1">${escapeHtml(failReason)}</div>
          </div>
        `;
      } else {
        el.invFindingsList.innerHTML = `<div class="empty-state text-xs p-3">${state.currentLang === 'ko' ? `'${escapeHtml(filter)}' 조건과 일치하는 발견 사항이 없습니다.` : `No findings matching '${escapeHtml(filter)}'.`}</div>`;
      }
      return;
    }

    let conclusionsHtml = '';
    if (inv.causal_conclusions && (filter === 'all' || filter === 'hypothesis')) {
      const cc = inv.causal_conclusions;
      const proofBadge = cc.causal_proof_established
        ? '<span class="badge badge-success text-xs">CAUSAL PROOF ESTABLISHED</span>'
        : '<span class="badge badge-warning text-xs">HYPOTHESIS / CANDIDATE STAGE</span>';
      
      conclusionsHtml = `
        <div style="background-color: rgba(31, 41, 55, 0.4); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px; margin-bottom: 12px;" class="text-xs">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <strong>Causal Conclusions Summary</strong>
            ${proofBadge}
          </div>
          <div style="display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 6px;">
            <span>Hypotheses: <strong>${cc.hypotheses_count || 0}</strong></span>
            <span>Supported: <strong style="color: var(--accent);">${cc.supported_hypotheses_count || 0}</strong></span>
            <span>Validated: <strong style="color: var(--success);">${cc.validated_causal_count || 0}</strong></span>
            <span>Contradicted: <strong style="color: var(--danger);">${cc.contradicted_count || 0}</strong></span>
            <span>Inconclusive: <strong style="color: var(--warning);">${cc.inconclusive_count || 0}</strong></span>
          </div>
          ${cc.causal_limitation_notice ? `<div class="text-muted" style="font-size: 0.75rem;">⚠️ ${escapeHtml(cc.causal_limitation_notice)}</div>` : ''}
        </div>
      `;
    }

    const renderedFindings = filtered.map(f => {
      const cat = f.category || 'fact';
      const badgeClass = cat === 'fact' ? 'badge-fact' : (cat === 'hypothesis' ? 'badge-hypothesis' : 'badge-unknown');
      const catLabel = cat === 'fact' ? t('observed_fact', 'Observed Fact') : (cat === 'hypothesis' ? t('hypothesis', 'Hypothesis') : t('unknown', 'Unknown'));
      const cPathHtml = f.c_type_path ? `<span class="finding-path">${escapeHtml(f.c_type_path)}</span>` : '';
      const jumpHtml = f.object_id ? `<button type="button" class="jump-link" onclick="window.__jumpToObject('${escapeHtml(f.object_id)}', '${escapeHtml(f.field_name || '')}')">${t('inspect_in_obj_explorer', 'Inspect in Object Explorer ➔')}</button>` : '';

      if (cat === 'hypothesis') {
        const hypo = (inv.hypotheses || []).find(h => h.hypothesis_id === f.finding_id || h.hypothesis_id === f.title || (f.title && f.title.includes(h.hypothesis_id)));
        const hypoStatus = (hypo ? hypo.status : f.status) || 'PROPOSED';
        let statusBadgeClass = 'badge-neutral';
        if (hypoStatus === 'VALIDATED') statusBadgeClass = 'badge-success';
        else if (hypoStatus === 'SUPPORTED') statusBadgeClass = 'badge-info';
        else if (hypoStatus === 'CONTRADICTED') statusBadgeClass = 'badge-danger';
        else if (hypoStatus === 'INCONCLUSIVE') statusBadgeClass = 'badge-warning';

        const conf = hypo?.confidence || f.confidence || 'SPECULATIVE';
        let confBadgeClass = 'badge-neutral';
        if (conf === 'HIGH') confBadgeClass = 'badge-success';
        else if (conf === 'MEDIUM') confBadgeClass = 'badge-info';
        else if (conf === 'LOW') confBadgeClass = 'badge-warning';

        // Function Candidates
        const funcCandidates = hypo?.function_candidates || [];
        let funcCandidatesHtml = '';
        if (funcCandidates.length > 0) {
          funcCandidatesHtml = `
            <div style="margin-top: 8px; padding-top: 6px; border-top: 1px dashed var(--border-color);">
              <div style="font-weight: 600; font-size: 0.8rem; margin-bottom: 4px; color: var(--text-secondary);">Function Candidates:</div>
              ${funcCandidates.map(fc => {
                const tier = fc.candidate_tier || (fc.confirmed_root_cause ? 'VALIDATED_CAUSAL_FUNCTION' : 'STATIC_CANDIDATE');
                let tierBadge = '<span class="badge badge-warning text-xs">STATIC CANDIDATE (UNPROVEN)</span>';
                if (tier === 'VALIDATED_CAUSAL_FUNCTION') {
                  tierBadge = '<span class="badge badge-success text-xs">VALIDATED CAUSAL FUNCTION</span>';
                } else if (tier === 'EVIDENCE_SUPPORTED_CANDIDATE') {
                  tierBadge = '<span class="badge badge-info text-xs">EVIDENCE-SUPPORTED CANDIDATE</span>';
                }
                const fnName = fc.function_name || fc.name || 'unknown_fn';
                const fileLoc = fc.source_file ? ` <span class="mono text-muted text-xs">(${escapeHtml(fc.source_file)}:${fc.source_line || 0})</span>` : '';
                return `<div style="margin-bottom: 4px;"><strong class="mono" style="color: var(--accent);">${escapeHtml(fnName)}</strong>${fileLoc} ${tierBadge}</div>`;
              }).join('')}
              <div class="text-xs text-muted" style="margin-top: 2px;">ℹ️ Static DWARF association alone does not constitute proven causality.</div>
            </div>
          `;
        }

        // Suggested Observations
        const observations = hypo?.suggested_observations || [];
        let obsHtml = '';
        if (observations.length > 0) {
          obsHtml = `
            <div style="margin-top: 8px; padding-top: 6px; border-top: 1px dashed var(--border-color);">
              <div style="font-weight: 600; font-size: 0.8rem; margin-bottom: 4px; color: var(--text-secondary);">Follow-Up Observation Plans:</div>
              ${observations.map(obs => {
                const isExec = obs.is_executed;
                const obsBadge = isExec ? '<span class="badge badge-success text-xs">EXECUTED</span>' : '<span class="badge badge-neutral text-xs">SUGGESTED</span>';
                const disc = obs.discriminating_criteria ? `<div class="text-xs text-muted" style="margin-top: 2px;"><strong>Discriminating Criteria:</strong> ${escapeHtml(obs.discriminating_criteria)}</div>` : '';
                const safety = (obs.safety_constraints && obs.safety_constraints.length > 0) ? `<div class="text-xs text-muted" style="margin-top: 2px;"><strong>Safety Constraints:</strong> ${escapeHtml(obs.safety_constraints.join(', '))}</div>` : '';
                const execBtn = (!isExec && inv.investigation_id) ? `<button type="button" class="btn btn-xs btn-outline mt-1" onclick="window.__executeObservation('${escapeHtml(inv.investigation_id)}', '${escapeHtml(obs.observation_id)}')">Execute Observation</button>` : '';
                return `
                  <div style="background: rgba(0,0,0,0.25); border: 1px solid var(--border-color); padding: 6px 8px; border-radius: 4px; margin-bottom: 6px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                      <span class="mono text-xs font-semibold" style="color: var(--text-main);">${escapeHtml(obs.observation_id || '')}: ${escapeHtml(obs.question || '')}</span>
                      ${obsBadge}
                    </div>
                    ${disc}
                    ${safety}
                    ${execBtn}
                  </div>
                `;
              }).join('')}
            </div>
          `;
        }

        // Validation History Trail
        const history = hypo?.status_history || [];
        let histHtml = '';
        if (history.length > 0) {
          histHtml = `
            <details style="margin-top: 8px;">
              <summary style="cursor: pointer; font-size: 0.8rem; color: var(--accent);">📜 Validation History (${history.length} transition${history.length > 1 ? 's' : ''})</summary>
              <div style="padding: 6px 8px; font-size: 0.75rem; background: rgba(0,0,0,0.25); border: 1px solid var(--border-color); border-radius: 4px; margin-top: 4px;">
                ${history.map(h => `
                  <div style="margin-bottom: 4px; border-bottom: 1px dashed rgba(255,255,255,0.1); padding-bottom: 2px;">
                    <span class="mono text-muted">${escapeHtml(h.timestamp || '')}</span>: 
                    <strong>${escapeHtml(h.from_status || 'INIT')} &rarr; ${escapeHtml(h.to_status || '')}</strong>
                    <div class="text-muted" style="margin-top: 1px;">&mdash; <em>${escapeHtml(h.transition_reason || '')}</em></div>
                  </div>
                `).join('')}
              </div>
            </details>
          `;
        }

        const evalBtn = (inv.investigation_id && hypo?.hypothesis_id) ? `
          <button type="button" class="btn btn-xs btn-secondary" onclick="window.__evaluateHypothesis('${escapeHtml(inv.investigation_id)}', '${escapeHtml(hypo.hypothesis_id)}')">
            Evaluate Hypothesis
          </button>
        ` : '';

        return `
          <div class="finding-card hypothesis">
            <div class="finding-header">
              <span class="finding-title">${escapeHtml(f.title || hypo?.claim || 'Hypothesis')}</span>
              <div style="display: flex; gap: 6px; align-items: center;">
                <span class="badge ${statusBadgeClass}">${escapeHtml(hypoStatus)}</span>
                <span class="${badgeClass}">${catLabel}</span>
              </div>
            </div>
            ${cPathHtml ? `<div style="margin-bottom: 6px;">${cPathHtml}</div>` : ''}
            <div class="finding-desc">${escapeHtml(hypo?.proposed_mechanism || f.description || '')}</div>
            <div style="margin-top: 6px;" class="text-xs">
              <strong>Confidence:</strong> <span class="badge ${confBadgeClass}">${escapeHtml(conf)}</span>
              ${hypo?.confidence_rationale ? `<span class="text-muted" style="margin-left: 6px;">(${escapeHtml(hypo.confidence_rationale)})</span>` : ''}
            </div>
            ${funcCandidatesHtml}
            ${obsHtml}
            ${histHtml}
            <div class="finding-footer" style="margin-top: 8px;">
              <span class="text-xs text-muted">Hypothesis ID: <strong>${escapeHtml(hypo?.hypothesis_id || f.finding_id || '')}</strong></span>
              <div style="display: flex; gap: 6px;">
                ${evalBtn}
                ${f.finding_id ? `<button type="button" class="btn btn-xs btn-outline" onclick="window.__showFindingDrilldown('${escapeHtml(f.finding_id)}')">🔬 Drill-Down</button>` : ''}
                ${jumpHtml}
              </div>
            </div>
          </div>
        `;
      }

      return `
        <div class="finding-card ${cat}">
          <div class="finding-header">
            <span class="finding-title">${escapeHtml(f.title || 'Finding')}</span>
            <span class="${badgeClass}">${catLabel}</span>
          </div>
          ${cPathHtml ? `<div style="margin-bottom: 6px;">${cPathHtml}</div>` : ''}
          <div class="finding-desc">${escapeHtml(f.description || '')}</div>
          <div class="finding-footer">
            <span class="text-xs text-muted">Status: <strong>${escapeHtml(f.status || 'CONFIRMED')}</strong></span>
            <div style="display: flex; gap: 6px;">
              ${f.finding_id ? `<button type="button" class="btn btn-xs btn-outline" onclick="window.__showFindingDrilldown('${escapeHtml(f.finding_id)}')">🔬 Drill-Down</button>` : ''}
              ${jumpHtml}
            </div>
          </div>
        </div>
      `;
    }).join('');

    el.invFindingsList.innerHTML = conclusionsHtml + renderedFindings;
  }

  function renderNextSteps(steps) {
    if (!el.invStepsContainer) return;
    if (el.invStepsCount) el.invStepsCount.textContent = `${steps.length} steps`;
    if (!steps || steps.length === 0) {
      el.invStepsContainer.innerHTML = '<div class="empty-state text-xs p-3">No next steps formulated yet.</div>';
      return;
    }

    el.invStepsContainer.innerHTML = steps.map((s, idx) => {
      const riskColor = s.risk_level === 'MUTATION' ? 'var(--danger)' : 'var(--text-muted)';
      return `
        <div class="step-card">
          <div class="step-header">
            <span class="step-suggestion-badge">${s.is_suggestion ? 'SUGGESTION' : 'EXECUTED'}</span>
            <span class="step-desc">${idx + 1}. ${escapeHtml(s.description)}</span>
          </div>
          <div class="step-rationale">${escapeHtml(s.rationale)} <span style="color: ${riskColor}; font-size: 0.75rem;">(Risk: ${escapeHtml(s.risk_level || 'READ_ONLY')})</span></div>
        </div>
      `;
    }).join('');
  }

  function renderComparisons(comparisons) {
    if (!el.invComparisonsContent) return;
    if (!comparisons || comparisons.length === 0) {
      el.invComparisonsContent.innerHTML = '<div class="empty-state text-xs p-3">No comparisons recorded. Select two snapshots above to isolate state diffs.</div>';
      return;
    }

    el.invComparisonsContent.innerHTML = comparisons.map(c => {
      const summary = c.diff_summary || c.summary || {};
      const uncHtml = c.uncertainty ? `<div class="banner banner-warning text-xs mb-2" style="padding: 4px 8px;">${escapeHtml(c.uncertainty)}</div>` : '';
      
      // Render detailed differences list if available
      const changes = c.changes || [];
      let changesHtml = '';
      if (changes && changes.length > 0) {
        changesHtml = `
          <div style="margin-top: 10px;">
            <div style="font-weight: 600; margin-bottom: 4px;">Changed & Unavailable Fields:</div>
            <table class="diff-table">
              <thead>
                <tr>
                  <th>Field / Path</th>
                  <th>Baseline A</th>
                  <th>Observed B</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                ${changes.map(chg => {
                  const kind = chg.kind || 'value_change';
                  let beforeVal = escapeHtml(String(chg.before !== undefined ? chg.before : ''));
                  let afterVal = escapeHtml(String(chg.after !== undefined ? chg.after : ''));
                  let badge = '<span class="diff-badge-modified">MODIFIED</span>';

                  if (kind === 'field_unavailable') {
                    badge = '<span class="diff-badge-unavailable">UNAVAILABLE IN SNAPSHOT</span>';
                    afterVal = '<span class="text-warning">Unavailable (Not Unchanged)</span>';
                  } else if (kind === 'field_added') {
                    badge = '<span class="diff-badge-added">FIELD ADDED</span>';
                    beforeVal = '<span class="text-muted">None</span>';
                  } else if (kind === 'object_added' || kind === 'object_created') {
                    badge = '<span class="diff-badge-added">OBJECT CREATED</span>';
                  } else if (kind === 'object_removed') {
                    badge = '<span class="badge badge-danger">OBJECT REMOVED</span>';
                  }

                  return `
                    <tr>
                      <td class="mono" style="color: var(--accent);">${escapeHtml(chg.path || chg.field || 'unknown')}</td>
                      <td class="mono">${beforeVal}</td>
                      <td class="mono">${afterVal}</td>
                      <td>${badge}</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        `;
      }

      return `
        <div style="background-color: rgba(31, 41, 55, 0.4); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px; margin-bottom: 8px;" class="text-xs">
          <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
            <strong>${escapeHtml(c.snapshot_a || 'A')} &harr; ${escapeHtml(c.snapshot_b || 'B')}</strong>
            <span class="badge badge-info">Diff</span>
          </div>
          ${uncHtml}
          <div style="display: flex; gap: 12px; flex-wrap: wrap;">
            <span>Value changes: <strong>${summary.value_changes || 0}</strong></span>
            <span>Objects added: <strong>${summary.objects_created || 0}</strong></span>
            <span>Objects removed: <strong>${summary.objects_removed || 0}</strong></span>
            <span>Unavailable fields: <strong>${summary.fields_unavailable || 0}</strong></span>
            <span>Added fields: <strong>${summary.fields_added || 0}</strong></span>
            <span>Ref changes: <strong>${summary.reference_changes || 0}</strong></span>
          </div>
          ${changesHtml}
        </div>
      `;
    }).join('');
  }

  function renderStaticLinks(staticDetails) {
    if (!el.invStaticLinksList) return;
    const lStatus = staticDetails.linkage_status || 'UNKNOWN';
    if (el.invBadgeStaticProvider) {
      el.invBadgeStaticProvider.textContent = `${staticDetails.provider || 'DWARF'} (${lStatus})`;
      el.invBadgeStaticProvider.className = `badge ${lStatus === 'VERIFIED' ? 'badge-success' : (lStatus === 'MISMATCH' ? 'badge-danger' : 'badge-warning')}`;
    }
    const resolved = staticDetails.resolved_links || [];
    let noticeHtml = '';
    if (lStatus === 'UNVERIFIED' || lStatus === 'MISMATCH' || lStatus === 'UNAVAILABLE') {
      const msg = staticDetails.reason || (lStatus === 'MISMATCH' ? 'Build ID mismatch prevents verified static code correlation.' : 'Module build ID unverified or debug image unavailable.');
      noticeHtml = `<div class="banner banner-warning text-xs mb-2" style="padding: 6px 10px;"><strong>Static Linkage ${escapeHtml(lStatus)}:</strong> ${escapeHtml(msg)}</div>`;
    }

    if (!resolved || resolved.length === 0) {
      el.invStaticLinksList.innerHTML = `${noticeHtml}<div class="empty-state text-xs p-3">No static links resolved. Check debug artifact path and symbol tables.</div>`;
      return;
    }

    el.invStaticLinksList.innerHTML = resolved.map(l => {
      const loc = (l.decl_file ? `${l.decl_file}:${l.decl_line}` : '') || (l.static_address || '');
      const kind = l.link_kind || (l.type ? 'TYPE_DEFINITION' : 'GLOBAL_VARIABLE');
      const isType = kind === 'TYPE_DEFINITION';
      const isVerified = l.is_verified 
        ? '<span class="badge badge-success text-xs" style="margin-left: 6px;">VERIFIED SYMBOL</span>' 
        : '<span class="badge badge-warning text-xs" style="margin-left: 6px;">CANDIDATE REFERENCE</span>';
      
      const typeNoticeHtml = isType 
        ? '<div class="text-xs text-muted" style="margin-top: 2px;">ℹ️ Type match defines layout only; does NOT prove which function created or modified this object.</div>' 
        : '';
      const limHtml = l.relationship_limitation ? `<div class="text-xs text-warning" style="margin-top: 2px;">⚠️ ${escapeHtml(l.relationship_limitation)}</div>` : '';

      return `
        <div style="padding: 6px 8px; border-bottom: 1px solid var(--border-color);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <span class="mono" style="color: var(--accent); font-weight: 600;">${escapeHtml(l.symbol_name || l.type || 'Symbol')}</span>
              <span class="badge badge-secondary text-xs" style="margin-left: 6px;">${escapeHtml(kind)}</span>
              ${isVerified}
            </div>
            <span class="mono text-xs text-muted">${escapeHtml(loc)}</span>
          </div>
          <div class="text-xs text-muted" style="margin-top: 2px;">Basis: ${escapeHtml(l.link_basis || 'exact_match')}</div>
          ${typeNoticeHtml}
          ${limHtml}
        </div>
      `;
    }).join('');
  }

  function renderRawEvidence(ledger) {
    if (!el.tbodyRawEvidence) return;
    const records = ledger.records || [];
    if (el.invTxtLedgerCount) el.invTxtLedgerCount.textContent = String(records.length);

    if (records.length === 0) {
      el.tbodyRawEvidence.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Ledger empty.</td></tr>';
      return;
    }

    el.tbodyRawEvidence.innerHTML = records.map(r => {
      const parentsHtml = r.parent_evidence_ids && r.parent_evidence_ids.length > 0
        ? `<div class="text-xs text-muted" style="margin-top: 2px;">Parents: ${r.parent_evidence_ids.map(p => `<button type="button" class="jump-link mono" onclick="window.__followEvidence('${escapeHtml(p)}')">${escapeHtml(p)}</button>`).join(', ')}</div>`
        : '';
      return `
        <tr>
          <td class="mono">${escapeHtml(r.evidence_id || '')}${parentsHtml}</td>
          <td><span class="badge">${escapeHtml(r.evidence_type || '')}</span></td>
          <td><span class="badge ${r.nature === 'observation' ? 'badge-fact' : (r.nature === 'inference' ? 'badge-hypothesis' : 'badge-warning')}">${escapeHtml(r.nature || 'observation')}</span></td>
          <td class="text-muted">${escapeHtml(r.source || '')}</td>
          <td>${escapeHtml(r.observation || JSON.stringify(r.provenance || {}))}</td>
        </tr>
      `;
    }).join('');
  }

  // Global helper for tracing provenance lineage for evidence
  window.__followEvidence = async function (evidenceId) {
    if (!evidenceId || !state.activeInvestigation || !state.activeInvestigation.investigation_id) return;
    const invId = state.activeInvestigation.investigation_id;
    try {
      showToast(`Tracing provenance lineage for evidence ${evidenceId}...`, 'info');
      const res = await apiGet(`/api/investigation/follow?investigation_id=${invId}&evidence_id=${evidenceId}`);
      if (res.success && res.data) {
        const lineage = res.data.provenance_chain || [];
        if (el.invLineageContainer && el.invLineageContent) {
          el.invLineageContainer.style.display = 'block';
          if (lineage.length === 0) {
            el.invLineageContent.innerHTML = `<div>Evidence record <span class="mono">${escapeHtml(evidenceId)}</span> has no recorded ancestor lineage.</div>`;
          } else {
            el.invLineageContent.innerHTML = lineage.map((node, i) => {
              const isCycle = node.status === 'CYCLE_DETECTED';
              const isMissing = node.status === 'UNRESOLVED_PARENT';
              const cls = isCycle ? 'lineage-step lineage-cycle' : 'lineage-step';
              return `
                <div class="${cls}">
                  <strong>Step ${i + 1}:</strong> <span class="mono">${escapeHtml(node.evidence_id)}</span>
                  ${isCycle ? '<span class="badge badge-danger text-xs">CYCLE DETECTED</span>' : ''}
                  ${isMissing ? '<span class="badge badge-warning text-xs">UNRESOLVED PARENT</span>' : ''}
                  <div class="text-muted text-xs">${escapeHtml(node.reason || `${node.nature || 'record'} from ${node.source || 'unknown'}`)}</div>
                </div>
              `;
            }).join('');
          }
          el.invLineageContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      } else {
        showToast(`Could not trace evidence: ${res.error?.message || 'Record not found'}`, 'warning');
      }
    } catch (e) {
      showToast(`Lineage trace failed: ${String(e)}`, 'error');
    }
  };

  // Global helper for jumping to object and highlighting field in Explorer tab
  window.__jumpToObject = function (objectId, fieldName) {
    if (!objectId) return;
    switchTab('tab-object-explorer');
    selectObject(objectId, true, fieldName);
    if (fieldName && el.tableSemanticFields) {
      setTimeout(() => {
        const rows = el.tableSemanticFields.querySelectorAll('tr');
        rows.forEach(r => {
          const nameCell = r.querySelector('td strong');
          if (nameCell && nameCell.textContent.trim() === fieldName) {
            r.scrollIntoView({ behavior: 'smooth', block: 'center' });
            r.style.outline = '2px solid var(--accent)';
            setTimeout(() => { r.style.outline = ''; }, 2500);
          }
        });
      }, 100);
    }
    showToast(`Focused on object ${objectId}${fieldName ? ` (${fieldName})` : ''}`, 'info');
  };

  // Global helper for evaluating hypothesis
  window.__evaluateHypothesis = async function (invId, hypoId) {
    if (!invId || !hypoId) return;
    try {
      showToast(`Evaluating hypothesis ${hypoId}...`, 'info');
      const res = await apiPost('/api/investigation/hypotheses/evaluate', {
        investigation_id: invId,
        hypothesis_id: hypoId,
      });
      if (res.success) {
        showToast(`Hypothesis evaluated: ${res.data?.status || 'updated'}`, 'success');
        await loadActiveInvestigation(invId);
      } else {
        showToast(`Evaluation failed: ${res.error?.message || 'Error'}`, 'error');
      }
    } catch (e) {
      showToast(`Evaluation error: ${String(e)}`, 'error');
    }
  };

  // Global helper for executing follow-up observation
  window.__executeObservation = async function (invId, obsId) {
    if (!invId || !obsId) return;
    try {
      showToast(`Executing observation ${obsId}...`, 'info');
      const res = await apiPost('/api/investigation/observe', {
        investigation_id: invId,
        observation_id: obsId,
      });
      if (res.success) {
        showToast(`Observation recorded: ${obsId}`, 'success');
        await loadActiveInvestigation(invId);
      } else {
        showToast(`Observation failed: ${res.error?.message || 'Error'}`, 'error');
      }
    } catch (e) {
      showToast(`Observation error: ${String(e)}`, 'error');
    }
  };

  function renderTimeline(timeline) {
    if (!el.invTimelineContainer) return;
    const countEl = el.invTimelineCount;
    if (!timeline || timeline.length === 0) {
      if (countEl) countEl.textContent = '0 events';
      el.invTimelineContainer.innerHTML = '<div class="empty-state text-xs p-3">Timeline empty. Start an investigation cycle to view audit trail.</div>';
      return;
    }
    if (countEl) countEl.textContent = `${timeline.length} events`;
    el.invTimelineContainer.innerHTML = timeline.map(evt => {
      const type = evt.event_type || 'EVENT';
      let badgeClass = 'badge-neutral';
      if (type.includes('SUPPORTED') || type.includes('VALIDATED')) badgeClass = 'badge-success';
      else if (type.includes('CONTRADICTED') || type.includes('FAILED')) badgeClass = 'badge-danger';
      else if (type.includes('INCONCLUSIVE')) badgeClass = 'badge-warning';
      else if (type.includes('OBSERVATION')) badgeClass = 'badge-info';

      const ts = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '';
      const summary = evt.summary || JSON.stringify(evt.details || {});
      return `
        <div style="padding: 6px 8px; border-bottom: 1px solid var(--border-color); font-size: 0.75rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
            <span class="badge ${badgeClass}" style="font-size: 0.7rem;">${escapeHtml(type)}</span>
            <span class="text-muted mono">${escapeHtml(ts)}</span>
          </div>
          <div>${escapeHtml(summary)}</div>
        </div>
      `;
    }).join('');
  }

  async function loadDrilldown(findingId) {
    if (!state.activeInvestigation || !state.activeInvestigation.investigation_id) return;
    const invId = state.activeInvestigation.investigation_id;
    try {
      const res = await apiGet(`/api/investigation/drilldown?investigation_id=${encodeURIComponent(invId)}&finding_id=${encodeURIComponent(findingId)}`);
      if (!res.success) {
        showToast(res.error?.message || 'Failed to load drilldown', 'error');
        return;
      }
      renderDrilldown(res.data?.drilldown || res.data);
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  function renderDrilldown(drill) {
    if (!el.invCardDrilldown || !el.invDrilldownContent) return;
    el.invCardDrilldown.style.display = 'block';
    if (!drill) {
      el.invDrilldownContent.innerHTML = '<div class="empty-state text-xs p-2">No drilldown data available.</div>';
      return;
    }
    const finding = drill.finding || {};
    const obj = drill.target_object || {};
    const dwarf = drill.dwarf_symbol || {};
    const candidates = drill.candidate_functions || [];
    const attrRecords = drill.attribution_records || [];
    const limitations = drill.limitations || [];

    el.invDrilldownContent.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 8px;">
        <div style="background: rgba(0,0,0,0.2); padding: 6px; border-radius: 4px;">
          <strong>Finding:</strong> <span class="mono">${escapeHtml(finding.finding_id || '')}</span> - ${escapeHtml(finding.title || '')}
          <div class="text-muted" style="margin-top: 2px;">Path: <span class="mono">${escapeHtml(finding.c_type_path || finding.field_path || 'N/A')}</span> | Class: <span class="badge badge-info text-xs">${escapeHtml(finding.classification || 'FACT')}</span></div>
        </div>
        <div style="background: rgba(0,0,0,0.2); padding: 6px; border-radius: 4px;">
          <strong>Target Object & DWARF:</strong>
          <div>Type: <span class="mono">${escapeHtml(obj.type || dwarf.type_name || 'N/A')}</span></div>
          <div>Decl: <span class="mono">${escapeHtml(dwarf.decl_file || 'unknown')}:${escapeHtml(String(dwarf.decl_line || 0))}</span></div>
        </div>
        <div style="background: rgba(0,0,0,0.2); padding: 6px; border-radius: 4px;">
          <strong>Candidate Functions (${candidates.length}):</strong>
          ${candidates.length > 0 ? candidates.map(c => `
            <div style="margin-top: 4px; padding-left: 6px; border-left: 2px solid var(--accent);">
              <span class="mono font-semibold" style="color: var(--accent);">${escapeHtml(c.function_name || c.name || '')}</span>
              <span class="badge badge-neutral text-xs">${escapeHtml(c.candidate_tier || 'STATIC_CANDIDATE')}</span>
              <div class="text-muted text-xs">Source: ${escapeHtml(c.source_file || 'unknown')}:${escapeHtml(String(c.source_line || 0))}</div>
            </div>
          `).join('') : '<div class="text-muted">No candidate functions linked via DWARF/static analysis.</div>'}
        </div>
        ${attrRecords.length > 0 ? `
          <div style="background: rgba(0,0,0,0.2); padding: 6px; border-radius: 4px;">
            <strong>Attribution Verification Records:</strong>
            ${attrRecords.map(r => `<div>&bull; <span class="mono">${escapeHtml(r.evidence_id || '')}</span>: ${escapeHtml(r.summary || '')}</div>`).join('')}
          </div>
        ` : ''}
        ${limitations.length > 0 ? `
          <div class="text-muted" style="font-size: 0.75rem; border-top: 1px dashed var(--border-color); padding-top: 4px;">
            ⚠️ Limitations: ${escapeHtml(limitations.join('; '))}
          </div>
        ` : ''}
      </div>
    `;
    el.invCardDrilldown.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function runInvestigationCycle() {
    if (!state.activeInvestigation || !state.activeInvestigation.investigation_id) {
      showToast('Please start an investigation first.', 'warning');
      return;
    }
    const invId = state.activeInvestigation.investigation_id;
    try {
      showToast('Running autonomous investigation cycle...', 'info');
      const res = await apiPost('/api/investigation/cycle', {
        investigation_id: invId,
        max_iterations: 5,
        max_observations: 10
      });
      if (!res.success) {
        showToast(res.error?.message || 'Cycle failed', 'error');
        return;
      }
      showToast('Investigation cycle completed.', 'success');
      if (res.data?.session) {
        state.activeInvestigation = res.data.session;
        renderInvestigationSession(state.activeInvestigation);
      } else {
        await loadActiveInvestigation(invId);
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  async function stepInvestigationCycle() {
    if (!state.activeInvestigation || !state.activeInvestigation.investigation_id) {
      showToast('Please start an investigation first.', 'warning');
      return;
    }
    const invId = state.activeInvestigation.investigation_id;
    try {
      const res = await apiPost('/api/investigation/step', { investigation_id: invId });
      if (!res.success) {
        showToast(res.error?.message || 'Step failed', 'error');
        return;
      }
      showToast('Executed cycle step.', 'success');
      await loadActiveInvestigation(invId);
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  window.__showFindingDrilldown = loadDrilldown;

  // --------------------------------------------------------------------------
  // Application Bootstrap
  // --------------------------------------------------------------------------

  async function init() {
    initTabs();
    initModeToggle();
    initI18n();
    initMutationPreview();
    initJsonViewerButtons();
    initObserveDialog();
    initFastCaptureModal();
    initSnapshotMutateModal();
    initLabBranchAndReplay();
    initInvestigationOverview();
    bindEvents();

    await loadRuntimeOverview();
    await loadStatesAndGraph();
    await loadStateLabTree();
    await loadActiveInvestigation();
  }

  window.addEventListener('DOMContentLoaded', init);
})();
