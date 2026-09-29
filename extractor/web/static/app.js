/**
 * dynamicState — Human-Centric Runtime Memory Explorer Frontend
 * Single-Page Application communicating via AgentRuntime REST API.
 */

(function () {
  'use strict';

  // Global Application State
  const state = {
    runtime: null,
    states: [],
    selectedStateId: null,
    objects: [],
    selectedObjectId: null,
    storageFilter: 'all',
    searchQuery: '',
    candidates: [],
    stateGraphData: { nodes: [], edges: [] },
    activeTab: 'tab-memory',
    activeSubtab: 'subtab-dag',
    jsonViewerCache: {},
  };

  // DOM Elements Cache
  const el = {
    // Header & Badges
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

    // Main Nav Tabs
    navTabs: document.querySelectorAll('.nav-tab'),
    tabPanes: document.querySelectorAll('.tab-pane'),

    // Tab 1: Memory Explorer Hero Summary
    heroMode: document.getElementById('hero-mode'),
    heroStatus: document.getElementById('hero-status'),
    heroCompleteness: document.getElementById('hero-completeness'),
    heroTargetTitle: document.getElementById('hero-target-title'),
    heroTargetSubtitle: document.getElementById('hero-target-subtitle'),
    selectMemoryState: document.getElementById('select-memory-state'),
    heroObjCount: document.getElementById('hero-obj-count'),
    heroPtrCount: document.getElementById('hero-ptr-count'),
    heroModCount: document.getElementById('hero-mod-count'),
    heroDebugInfo: document.getElementById('hero-debug-info'),

    // Tab 1: Directory & Inspector
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

    // Tab 2: Topology
    svgTopologyGraph: document.getElementById('topology-graph-svg'),
    btnResetTopology: document.getElementById('btn-reset-topology'),

    // Tab 3: Advanced Exploration Subnav
    subnavPills: document.querySelectorAll('.subnav-pill'),
    subtabContents: document.querySelectorAll('.subtab-content'),

    // Tab 3: State DAG
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

    // Tab 3: Mutation Proposals
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

    // Tab 3: State Diff
    inputDiffA: document.getElementById('input-diff-a'),
    inputDiffB: document.getElementById('input-diff-b'),
    btnRunDiff: document.getElementById('btn-run-diff'),
    diffResults: document.getElementById('diff-results'),
    diffValChanges: document.getElementById('diff-val-changes'),
    diffRefChanges: document.getElementById('diff-ref-changes'),
    diffObjCreated: document.getElementById('diff-obj-created'),
    diffObjRemoved: document.getElementById('diff-obj-removed'),
    tableDiffChanges: document.querySelector('#table-diff-changes tbody'),

    // Tab 3: Autonomous Explore
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

    // Tab 4: Provenance & System
    ovStatus: document.getElementById('ov-status'),
    ovPid: document.getElementById('ov-pid'),
    ovMode: document.getElementById('ov-mode'),
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
  // API Transport Helpers
  // --------------------------------------------------------------------------

  async function apiGet(endpoint) {
    try {
      const res = await fetch(endpoint);
      const data = await res.json();
      return data;
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
      const data = await res.json();
      return data;
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

  function getBaseName(path) {
    if (!path) return 'N/A';
    const parts = path.split('/');
    return parts[parts.length - 1] || path;
  }

  // --------------------------------------------------------------------------
  // Tab & Subtab Navigation
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
        switchSubtab(targetSubtab);
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

    if (tabId === 'tab-topology') {
      renderObjectTopology();
    } else if (tabId === 'tab-exploration') {
      if (state.activeSubtab === 'subtab-dag') {
        renderStateGraph();
      }
    }
  }

  function switchSubtab(subtabId) {
    state.activeSubtab = subtabId;
    el.subnavPills.forEach((p) => {
      p.classList.toggle('active', p.getAttribute('data-subtab') === subtabId);
    });
    el.subtabContents.forEach((c) => {
      c.classList.toggle('active', c.id === subtabId);
    });

    if (subtabId === 'subtab-dag') {
      renderStateGraph();
    } else if (subtabId === 'subtab-mutations') {
      loadCandidates();
    }
  }

  // --------------------------------------------------------------------------
  // Runtime Overview & Hero Summary
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

    // Show/hide low-impact banner
    if (mode === 'LOW_IMPACT') {
      el.lowImpactBanner.style.display = 'flex';
      el.btnStartExplore.disabled = true;
      el.btnStartExplore.title = 'Exploration unsupported in LOW_IMPACT mode';
    } else {
      el.lowImpactBanner.style.display = 'none';
      el.btnStartExplore.disabled = false;
      el.btnStartExplore.title = '';
    }

    el.tagPid.textContent = data.pid ? `PID: ${data.pid}` : 'PID: N/A';
    el.tagArch.textContent = `Arch: ${data.architecture || 'UNKNOWN'}`;
    el.tagEndian.textContent = `Endian: ${data.endianness || 'UNKNOWN'}`;
    el.tagElf.textContent = `ELF: ${data.elf_class || 'UNKNOWN'}`;

    // Tab 1 Hero Runtime Summary
    el.heroMode.textContent = mode;
    el.heroMode.className = 'badge ' + (mode === 'LOW_IMPACT' ? 'badge-warning' : 'badge-info');
    el.heroStatus.textContent = status;
    el.heroStatus.className = 'badge ' + (status === 'STOPPED' ? 'badge-success' : status === 'RUNNING' ? 'badge-info' : 'badge-neutral');
    el.heroCompleteness.textContent = mode === 'LOW_IMPACT' ? 'OFFLINE SNAPSHOT' : 'COMPLETE DWARF';

    const binName = getBaseName(data.executable);
    el.heroTargetTitle.textContent = data.pid ? `${binName} (PID ${data.pid})` : binName;
    el.heroTargetSubtitle.textContent = data.executable || 'No executable path reported';
    el.heroModCount.textContent = data.module_count || 0;

    let debugSummary = 'None';
    if (data.debug_image) {
      const dbgName = getBaseName(data.debug_image);
      const dbgStatus = data.debug_image_status || 'UNVERIFIED';
      const bId = data.build_id ? `[${data.build_id.substring(0, 8)}...]` : '';
      debugSummary = `${dbgName} · ${dbgStatus} ${bId}`;
    }
    el.heroDebugInfo.textContent = debugSummary;

    // Tab 4: System Overview & Provenance Cards
    el.ovStatus.textContent = status;
    el.ovPid.textContent = data.pid || 'None';
    el.ovMode.innerHTML = `<span class="badge ${mode === 'LOW_IMPACT' ? 'badge-warning' : 'badge-info'}">${mode}</span>`;
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

    // Safety limits
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

  // --------------------------------------------------------------------------
  // States & Corpus DAG Management
  // --------------------------------------------------------------------------

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

      // Auto-select latest or first state if none selected
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
    const options = ['<option value="">(Select a State)</option>'];
    statesList.forEach((s) => {
      const shortHash = (s.state_hash || '').substring(0, 8);
      const isSeed = !s.metadata || !s.metadata.parent_state_id;
      const tag = isSeed ? '[Seed]' : '';
      options.push(`<option value="${s.state_id}">${s.state_id} ${tag} (${shortHash})</option>`);
    });
    el.selectMemoryState.innerHTML = options.join('');

    if (state.selectedStateId) {
      el.selectMemoryState.value = state.selectedStateId;
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

    // Synchronize selector dropdowns
    if (el.selectMemoryState.value !== stateId) {
      el.selectMemoryState.value = stateId;
    }

    // Update list selection highlight
    el.listStates.querySelectorAll('.state-list-item').forEach((item) => {
      item.classList.toggle('selected', item.getAttribute('data-state-id') === stateId);
    });

    // Update DAG graph highlight
    renderStateGraph();

    // Load objects for this state into Memory Explorer & Topology
    await loadObjectsForState(stateId);

    // Fetch state details for Tab 3 DAG panel
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
  // Tab 1: Human-Centric Runtime Memory Explorer & Inspector
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

    // Metrics in hero banner
    el.heroObjCount.textContent = objects.length;
    let ptrCount = 0;
    objects.forEach((o) => {
      const fields = o.fields || [];
      fields.forEach((f) => {
        if (f.object_ref) ptrCount++;
      });
    });
    el.heroPtrCount.textContent = ptrCount;

    // Render object directory list
    renderMemoryObjectsList();

    // Render Topology graph
    renderObjectTopology();

    // Preserve or auto-select object
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
      // Storage filter
      const st = (o.storage || 'unknown').toLowerCase();
      if (filter !== 'all' && st !== filter) return false;

      // Text query
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

    // Highlight item in object directory
    el.listMemoryObjects.querySelectorAll('.mem-obj-item').forEach((item) => {
      item.classList.toggle('selected', item.getAttribute('data-object-id') === objectId);
    });

    const obj = state.objects.find((o) => o.object_id === objectId);
    if (!obj) return;
    state.jsonViewerCache[`object_${objectId}`] = obj;

    // Header info
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

    // Render Semantic Fields Table
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

      // Referenced target object name & type lookup
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

    // Attach click events on pointer chips to jump directly to referenced object
    el.tableSemanticFields.querySelectorAll('.pointer-chip').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const refId = btn.getAttribute('data-ref-id');
        jumpToObject(refId);
      });
    });

    // Attach click events to jump into mutation proposing
    el.tableSemanticFields.querySelectorAll('.btn-inspect-cand').forEach((btn) => {
      btn.addEventListener('click', () => {
        const oid = btn.getAttribute('data-object-id');
        const fld = btn.getAttribute('data-field-name');
        switchTab('tab-exploration');
        switchSubtab('subtab-mutations');
        loadCandidates(oid, fld);
      });
    });
  }

  function jumpToObject(objectId) {
    if (!objectId) return;
    selectObject(objectId);

    // Scroll object into view in the left list
    const listItem = el.listMemoryObjects.querySelector(`[data-object-id="${objectId}"]`);
    if (listItem) {
      listItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function formatSemanticValue(val, typeStr, objectRef) {
    if (val === null || val === undefined) return '<span class="text-muted">None</span>';

    // Booleans
    if (typeof val === 'boolean' || val === 'true' || val === 'false') {
      const boolVal = val === true || val === 'true';
      return `<span class="val-badge-bool-${boolVal}">${boolVal ? 'TRUE' : 'FALSE'}</span>`;
    }

    // Unavailable / Unknown markers
    if (val === 'UNAVAILABLE' || val === 'UNKNOWN') {
      return `<span class="val-badge-unavailable">⚠️ ${val}</span>`;
    }

    // Enums (contains :: or all uppercase with underscores)
    const strVal = String(val);
    if (strVal.includes('::') || (strVal.length > 2 && /^[A-Z][A-Z0-9_]+$/.test(strVal))) {
      return `<span class="val-badge-enum">${escapeHtml(strVal)}</span>`;
    }

    // Pointer reference value
    if (objectRef) {
      return `<span class="mono text-accent">${escapeHtml(strVal)}</span>`;
    }

    // Regular scalar / string value
    return `<span class="mono">${escapeHtml(strVal)}</span>`;
  }

  function isFieldMutable(typeStr) {
    if (!typeStr) return false;
    const lower = typeStr.toLowerCase();
    if (lower.includes('const')) return false;
    return ['int', 'bool', 'enum', 'float', 'double', 'char', '*'].some((t) => lower.includes(t));
  }

  // --------------------------------------------------------------------------
  // Tab 2: Semantic Object Topology & Reference Graph
  // --------------------------------------------------------------------------

  function renderObjectTopology() {
    const svg = el.svgTopologyGraph;
    const objects = state.objects || [];

    if (!svg || objects.length === 0) {
      if (svg) svg.innerHTML = '<text x="50%" y="50%" fill="#6b7280" text-anchor="middle">No objects in current snapshot</text>';
      return;
    }

    // Build graph adjacency
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

    // Roots: global, stack, or objects with 0 incoming references
    const levels = {};
    objects.forEach((o) => {
      const st = (o.storage || '').toLowerCase();
      if (st === 'global' || st === 'stack' || incomingEdges[o.object_id] === 0) {
        levels[o.object_id] = 0;
      }
    });

    // BFS to assign hierarchy levels
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

    // Default remaining disconnected nodes to level 0
    objects.forEach((o) => {
      if (levels[o.object_id] === undefined) levels[o.object_id] = 0;
    });

    // Group nodes by level
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

    // Render Edges
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

    // Render Nodes
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

    // Attach click events to nodes
    svg.querySelectorAll('.topo-node').forEach((nodeEl) => {
      nodeEl.addEventListener('click', () => {
        const oid = nodeEl.getAttribute('data-object-id');
        selectObject(oid);
        switchTab('tab-memory');
      });
    });
  }

  // --------------------------------------------------------------------------
  // Tab 3: Advanced Exploration — State DAG
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

    // Render Edges
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

    // Render Nodes
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

  // --------------------------------------------------------------------------
  // Tab 3: Mutation Candidates & Execution
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

    // Refresh states and graph
    await loadStatesAndGraph();
  }

  // --------------------------------------------------------------------------
  // Tab 3: Semantic State Diff
  // --------------------------------------------------------------------------

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
  // Tab 3: Autonomous Exploration Loop
  // --------------------------------------------------------------------------

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
      showToast(res.error ? res.error.message : 'Exploration loop failed', 'error');
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

  // --------------------------------------------------------------------------
  // JSON Viewer Modal
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

  // --------------------------------------------------------------------------
  // Observation Dialog Modal
  // --------------------------------------------------------------------------

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
  // Event Bindings
  // --------------------------------------------------------------------------

  function bindEvents() {
    el.btnRefresh.addEventListener('click', async () => {
      showToast('Refreshing runtime state...', 'info');
      await loadRuntimeOverview();
      await loadStatesAndGraph();
    });

    el.selectMemoryState.addEventListener('change', (e) => {
      const sid = e.target.value;
      if (sid) selectState(sid);
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
      switchTab('tab-topology');
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
        switchTab('tab-memory');
      }
    });

    el.btnStateDiffParent.addEventListener('click', () => {
      if (state.selectedStateId) {
        switchSubtab('subtab-diff');
        computeDiff(el.inputDiffA.value, el.inputDiffB.value);
      }
    });

    el.btnStateMutate.addEventListener('click', () => {
      switchSubtab('subtab-mutations');
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
