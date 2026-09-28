/**
 * dynamicState — Runtime State Explorer Frontend (Single-Page App)
 * Communicates strictly via thin Web API mapping to AgentRuntime.
 */

(function () {
  'use strict';

  // Global App State
  const state = {
    runtime: null,
    states: [],
    selectedStateId: null,
    objects: [],
    selectedObjectId: null,
    candidates: [],
    stateGraphData: { nodes: [], edges: [] },
    activeTab: 'tab-overview',
    jsonViewerCache: {},
  };

  // DOM Elements
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

    // Nav Tabs
    navTabs: document.querySelectorAll('.nav-tab'),
    tabPanes: document.querySelectorAll('.tab-pane'),

    // Tab 1: Overview
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

    // Tab 2: State Graph & Explorer
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

    // Tab 3: Object Graph
    selectObjectState: document.getElementById('select-object-state'),
    badgeObjectsCount: document.getElementById('badge-objects-count'),
    listObjects: document.getElementById('list-objects'),
    graphTruncatedWarning: document.getElementById('graph-truncated-warning'),
    txtTruncatedCount: document.getElementById('txt-truncated-count'),
    objDetailId: document.getElementById('obj-detail-id'),
    objDetailType: document.getElementById('obj-detail-type'),
    objDetailStorage: document.getElementById('obj-detail-storage'),
    objDetailAddr: document.getElementById('obj-detail-addr'),
    tableFields: document.querySelector('#table-fields tbody'),
    btnViewObjJson: document.getElementById('btn-view-obj-json'),

    // Tab 4: Mutations
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

    // Tab 5: State Diff
    inputDiffA: document.getElementById('input-diff-a'),
    inputDiffB: document.getElementById('input-diff-b'),
    btnRunDiff: document.getElementById('btn-run-diff'),
    diffResults: document.getElementById('diff-results'),
    diffValChanges: document.getElementById('diff-val-changes'),
    diffRefChanges: document.getElementById('diff-ref-changes'),
    diffObjCreated: document.getElementById('diff-obj-created'),
    diffObjRemoved: document.getElementById('diff-obj-removed'),
    tableDiffChanges: document.querySelector('#table-diff-changes tbody'),

    // Tab 6: Explore
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
  // API Helper
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
    t.innerHTML = `<span>${type === 'success' ? '✓' : type === 'error' ? '⚠️' : 'ℹ'}</span> <span>${escapeHtml(message)}</span>`;
    el.toastContainer.appendChild(t);
    setTimeout(() => {
      t.style.opacity = '0';
      setTimeout(() => t.remove(), 200);
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

  // --------------------------------------------------------------------------
  // Tab Navigation
  // --------------------------------------------------------------------------

  function initTabs() {
    el.navTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const targetTab = tab.getAttribute('data-tab');
        switchTab(targetTab);
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

    if (tabId === 'tab-state-graph') {
      renderStateGraph();
    } else if (tabId === 'tab-object-graph' && state.selectedStateId) {
      loadObjectsForState(state.selectedStateId);
    }
  }

  // --------------------------------------------------------------------------
  // TAB 1: Runtime Overview & Modules
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

    // Overview cards
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
      <span class="tag">Max states: ${limits.max_corpus_states || 100}</span>
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
  // TAB 2: State Graph & Explorer
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
    }

    if (graphRes.success) {
      state.stateGraphData = graphRes.data || { nodes: [], edges: [] };
      state.jsonViewerCache['state-graph'] = state.stateGraphData;
      renderStateGraph();
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

    // Attach click handlers
    el.listStates.querySelectorAll('.state-list-item').forEach((item) => {
      item.addEventListener('click', () => {
        const sid = item.getAttribute('data-state-id');
        selectState(sid);
      });
    });
  }

  function updateStateSelectors(statesList) {
    const options = ['<option value="">(Select a State)</option>'];
    statesList.forEach((s) => {
      const shortHash = (s.state_hash || '').substring(0, 8);
      options.push(`<option value="${s.state_id}">${s.state_id} (${shortHash})</option>`);
    });
    el.selectObjectState.innerHTML = options.join('');
  }

  async function selectState(stateId) {
    state.selectedStateId = stateId;

    // Update list selection highlight
    el.listStates.querySelectorAll('.state-list-item').forEach((item) => {
      item.classList.toggle('selected', item.getAttribute('data-state-id') === stateId);
    });

    // Update graph selection highlight
    renderStateGraph();

    // Fetch state details
    const res = await apiGet(`/api/states/${stateId}`);
    if (res.success) {
      const s = res.data;
      state.jsonViewerCache[`state_${stateId}`] = s;

      el.cardStateDetail.style.display = 'block';
      el.detailStateId.textContent = stateId;
      el.detailStateHash.textContent = s.state_hash || 'UNKNOWN';

      const parentState = s.parent_state || 'None (Seed)';
      el.detailParentState.textContent = parentState;
      el.detailCreatedAt.textContent = s.timestamp || 'N/A';
      el.detailObservations.textContent = (s.observations && s.observations.length) || 1;

      // Enable diff with parent if parent exists
      if (s.parent_state) {
        el.btnStateDiffParent.disabled = false;
        el.inputDiffA.value = s.parent_state;
        el.inputDiffB.value = stateId;
      } else {
        el.btnStateDiffParent.disabled = true;
      }
    }
  }

  // Hierarchical SVG State Graph Renderer
  function renderStateGraph() {
    const svg = el.svgStateGraph;
    const data = state.stateGraphData;
    if (!svg || !data.nodes || data.nodes.length === 0) {
      if (svg) svg.innerHTML = '<text x="50%" y="50%" fill="#6b7280" text-anchor="middle">No states discovered yet</text>';
      return;
    }

    const nodes = data.nodes;
    const edges = data.edges;

    // Compute layout levels using simple BFS from seed nodes
    const levels = {};
    const parents = {};
    edges.forEach((e) => {
      parents[e.to] = e.from;
    });

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

    // Group nodes by level
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
      const y = 50 + lvl * levelSpacing;
      group.forEach((n, idx) => {
        const x = 60 + idx * (nodeWidth + siblingSpacing);
        coords[n.id] = { x, y };
        if (x + nodeWidth + 60 > maxSvgWidth) maxSvgWidth = x + nodeWidth + 60;
        if (y + nodeHeight + 60 > maxSvgHeight) maxSvgHeight = y + nodeHeight + 60;
      });
    });

    svg.setAttribute('width', maxSvgWidth);
    svg.setAttribute('height', maxSvgHeight);

    // Build SVG Content
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

      // Curved Bezier path
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

    // Attach click events on nodes
    svg.querySelectorAll('.graph-node').forEach((nodeEl) => {
      nodeEl.addEventListener('click', () => {
        const nid = nodeEl.getAttribute('data-node-id');
        selectState(nid);
      });
    });
  }

  // --------------------------------------------------------------------------
  // TAB 3: Object Graph & Inspector
  // --------------------------------------------------------------------------

  async function loadObjectsForState(stateId) {
    if (!stateId) return;
    const res = await apiGet(`/api/states/${stateId}/objects`);
    if (!res.success) {
      el.listObjects.innerHTML = `<div class="text-muted text-center p-3">${escapeHtml(res.error.message)}</div>`;
      return;
    }

    const objects = res.data || [];
    state.objects = objects;
    state.jsonViewerCache['objects'] = objects;
    el.badgeObjectsCount.textContent = objects.length;

    // Truncation guard: if > 100 objects, limit display and show banner
    const maxDisplay = 100;
    const displayObjects = objects.slice(0, maxDisplay);
    if (objects.length > maxDisplay) {
      el.graphTruncatedWarning.style.display = 'block';
      el.txtTruncatedCount.textContent = `Graph truncated: ${objects.length - maxDisplay} additional objects`;
    } else {
      el.graphTruncatedWarning.style.display = 'none';
    }

    renderObjectsList(displayObjects);

    // Auto-select first object if available
    if (displayObjects.length > 0) {
      selectObject(displayObjects[0].object_id);
    }
  }

  function renderObjectsList(objs) {
    if (!objs || objs.length === 0) {
      el.listObjects.innerHTML = `<div class="text-muted text-center p-3">No semantic objects in this state</div>`;
      return;
    }

    let html = '';
    objs.forEach((o) => {
      const isSelected = o.object_id === state.selectedObjectId;
      html += `
        <div class="object-list-item ${isSelected ? 'selected' : ''}" data-object-id="${o.object_id}">
          <div class="state-item-header">
            <span class="mono" style="font-weight: 600;">${escapeHtml(o.object_id)}</span>
            <span class="badge badge-info">${escapeHtml(o.type || 'Unknown')}</span>
          </div>
          <div class="state-item-hash">storage: ${o.storage || 'UNKNOWN'}</div>
        </div>
      `;
    });
    el.listObjects.innerHTML = html;

    el.listObjects.querySelectorAll('.object-list-item').forEach((item) => {
      item.addEventListener('click', () => {
        const oid = item.getAttribute('data-object-id');
        selectObject(oid);
      });
    });
  }

  async function selectObject(objectId) {
    state.selectedObjectId = objectId;
    el.listObjects.querySelectorAll('.object-list-item').forEach((item) => {
      item.classList.toggle('selected', item.getAttribute('data-object-id') === objectId);
    });

    const obj = state.objects.find((o) => o.object_id === objectId);
    if (!obj) return;
    state.jsonViewerCache[`object_${objectId}`] = obj;

    el.objDetailId.textContent = objectId;
    el.objDetailType.textContent = obj.type || 'Unknown';
    el.objDetailStorage.textContent = obj.storage || 'UNKNOWN';
    el.objDetailAddr.textContent = obj.address ? '0x' + Number(obj.address).toString(16) : 'N/A';

    // Render Fields Table
    const fields = obj.fields || [];
    if (fields.length === 0) {
      el.tableFields.innerHTML = `<tr><td colspan="6" class="text-muted text-center">No fields defined</td></tr>`;
      return;
    }

    let fieldsHtml = '';
    fields.forEach((f) => {
      const isRef = Boolean(f.object_ref);
      const isMutable = isFieldMutable(f.type);
      const valStr = formatFieldValue(f.value);

      fieldsHtml += `
        <tr>
          <td><strong>${escapeHtml(f.name)}</strong></td>
          <td class="mono">${escapeHtml(f.type || '')}</td>
          <td class="mono ${valStr === 'UNAVAILABLE' ? 'text-warning' : ''}">${escapeHtml(valStr)}</td>
          <td>${isRef ? `<a href="#" class="ref-link" data-ref-id="${f.object_ref}">${escapeHtml(f.object_ref)}</a>` : '<span class="text-muted">None</span>'}</td>
          <td><span class="badge ${isMutable ? 'badge-success' : 'badge-neutral'}">${isMutable ? 'mutable' : 'read_only'}</span></td>
          <td>
            ${isMutable ? `<button class="btn btn-primary btn-sm btn-inspect-cand" data-object-id="${objectId}" data-field-name="${f.name}">Candidates</button>` : ''}
          </td>
        </tr>
      `;
    });
    el.tableFields.innerHTML = fieldsHtml;

    // Attach field action handlers
    el.tableFields.querySelectorAll('.ref-link').forEach((link) => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const refId = link.getAttribute('data-ref-id');
        selectObject(refId);
      });
    });

    el.tableFields.querySelectorAll('.btn-inspect-cand').forEach((btn) => {
      btn.addEventListener('click', () => {
        const oid = btn.getAttribute('data-object-id');
        const fld = btn.getAttribute('data-field-name');
        switchTab('tab-mutations');
        loadCandidates(oid, fld);
      });
    });
  }

  function isFieldMutable(typeStr) {
    if (!typeStr) return false;
    const lower = typeStr.toLowerCase();
    if (lower.includes('const')) return false;
    return ['int', 'bool', 'enum', 'float', 'double', '*'].some((t) => lower.includes(t));
  }

  function formatFieldValue(val) {
    if (val === null || val === undefined) return 'None';
    if (typeof val === 'object') return JSON.stringify(val);
    return String(val);
  }

  // --------------------------------------------------------------------------
  // TAB 4: Mutations & Transitions
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
          <td class="mono">${escapeHtml(formatFieldValue(c.current_value))}</td>
          <td class="mono text-accent"><strong>${escapeHtml(formatFieldValue(c.proposed_value))}</strong></td>
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

    // Attach Execute Click Handlers
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

    // Display Transition Card
    el.cardExecutionResult.style.display = 'block';
    el.execTransId.textContent = trans.transition_id || 'Transition Complete';

    const execStatus = (trans.execution && trans.execution.status) || 'STOPPED';
    el.execStatusText.textContent = execStatus;
    el.execStatusBadge.textContent = execStatus;
    el.execStatusBadge.className = 'badge ' + (execStatus === 'CRASHED' ? 'badge-danger' : execStatus === 'TIMEOUT' ? 'badge-warning' : 'badge-success');

    el.execChildState.textContent = trans.child_state || 'None';
    el.execChildHash.textContent = trans.state_hash || 'N/A';

    // List changed fields
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
  // TAB 5: State Diff
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
          <td class="mono text-muted">${escapeHtml(formatFieldValue(c.before))}</td>
          <td class="mono text-accent"><strong>${escapeHtml(formatFieldValue(c.after))}</strong></td>
          <td><span class="tag">${escapeHtml(c.category || 'value')}</span></td>
        </tr>
      `;
    });
    el.tableDiffChanges.innerHTML = html;
  }

  // --------------------------------------------------------------------------
  // TAB 6: Autonomous Explore
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

    // Refresh states and graph
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
  // Observe Dialog Modal
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

    el.inputSearchStates.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      const filtered = state.states.filter((s) => {
        return s.state_id.toLowerCase().includes(q) || (s.state_hash || '').toLowerCase().includes(q);
      });
      renderStatesList(filtered);
    });

    el.btnResetGraph.addEventListener('click', () => {
      renderStateGraph();
    });

    el.btnInspectStateObjects.addEventListener('click', () => {
      if (state.selectedStateId) {
        el.selectObjectState.value = state.selectedStateId;
        switchTab('tab-object-graph');
        loadObjectsForState(state.selectedStateId);
      }
    });

    el.btnStateDiffParent.addEventListener('click', () => {
      if (state.selectedStateId) {
        switchTab('tab-diff');
        computeDiff(el.inputDiffA.value, el.inputDiffB.value);
      }
    });

    el.btnStateMutate.addEventListener('click', () => {
      switchTab('tab-mutations');
      loadCandidates();
    });

    el.selectObjectState.addEventListener('change', (e) => {
      const sid = e.target.value;
      if (sid) {
        loadObjectsForState(sid);
      }
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

    // Initial data fetch
    await loadRuntimeOverview();
    await loadStatesAndGraph();
    loadCandidates();
  }

  window.addEventListener('DOMContentLoaded', init);
})();
