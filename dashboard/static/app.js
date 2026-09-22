/**
 * IAM-XAI Phase 10 Interactive Dashboard Frontend Application Logic
 */

let state = {
  scenarios: [],
  currentData: null,
  selectedPathId: null,
  activeFilter: 'ALL',
  activeTab: 'choke',
};

// DOM Elements
const scenarioSelect = document.getElementById('scenarioSelect');
const fileInput = document.getElementById('fileInput');
const btnAnalyze = document.getElementById('btnAnalyze');
const btnRemediate = document.getElementById('btnRemediate');

const scenarioTag = document.getElementById('scenarioTag');
const scenarioDesc = document.getElementById('scenarioDesc');
const statRiskBadge = document.getElementById('statRiskBadge');
const statNodes = document.getElementById('statNodes');
const statEdges = document.getElementById('statEdges');
const statPaths = document.getElementById('statPaths');
const statChokePoints = document.getElementById('statChokePoints');

const graphSvg = document.getElementById('graphSvg');
const graphEmptyState = document.getElementById('graphEmptyState');
const pathsList = document.getElementById('pathsList');
const pathCountText = document.getElementById('pathCountText');
const shapChart = document.getElementById('shapChart');
const selectedPathIdText = document.getElementById('selectedPathIdText');

const chokePointsList = document.getElementById('chokePointsList');
const policyDiffViewer = document.getElementById('policyDiffViewer');
const playbookViewer = document.getElementById('playbookViewer');
const btnCopyPlaybook = document.getElementById('btnCopyPlaybook');

const nodeModal = document.getElementById('nodeModal');
const modalNodeTitle = document.getElementById('modalNodeTitle');
const modalNodeBody = document.getElementById('modalNodeBody');
const modalCloseBtn = document.getElementById('modalCloseBtn');

// Initialize App
document.addEventListener('DOMContentLoaded', async () => {
  setupTabs();
  setupFilterPills();
  setupModal();
  await loadScenariosList();

  scenarioSelect.addEventListener('change', () => {
    if (scenarioSelect.value) {
      loadScenario(scenarioSelect.value);
    }
  });

  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (evt) => {
        try {
          const raw = JSON.parse(evt.target.result);
          analyzeScenario(raw);
        } catch (err) {
          alert("Failed to parse JSON file: " + err.message);
        }
      };
      reader.readAsText(file);
    }
  });

  btnAnalyze.addEventListener('click', () => {
    if (scenarioSelect.value) {
      loadScenario(scenarioSelect.value);
    } else if (state.currentData && state.currentData.raw_scenario) {
      analyzeScenario(state.currentData.raw_scenario);
    }
  });

  btnRemediate.addEventListener('click', execute1ClickRemediation);
  if (btnCopyPlaybook) {
    btnCopyPlaybook.addEventListener('click', () => {
      navigator.clipboard.writeText(playbookViewer.textContent);
      alert("Remediation Playbook copied to clipboard!");
    });
  }
});

function setupModal() {
  modalCloseBtn.addEventListener('click', () => nodeModal.classList.remove('active'));
  nodeModal.addEventListener('click', (e) => {
    if (e.target === nodeModal) nodeModal.classList.remove('active');
  });
}

function showNodeModal(node) {
  modalNodeTitle.textContent = `${node.name} (${node.type.toUpperCase()})`;
  modalNodeBody.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:0.6rem; font-size:0.9rem;">
      <div><strong>ID:</strong> <code>${node.id}</code></div>
      <div><strong>Type:</strong> ${node.type}</div>
      ${node.arn ? `<div><strong>ARN:</strong> <code>${node.arn}</code></div>` : ''}
      ${node.resource_type ? `<div><strong>Resource Type:</strong> ${node.resource_type}</div>` : ''}
    </div>
  `;
  nodeModal.classList.add('active');
}

function setupTabs() {
  const tabs = [
    { btn: 'tabChoke', content: 'tabContentChoke', key: 'choke' },
    { btn: 'tabDiff', content: 'tabContentDiff', key: 'diff' },
    { btn: 'tabPlaybook', content: 'tabContentPlaybook', key: 'playbook' },
  ];

  tabs.forEach(tab => {
    document.getElementById(tab.btn).addEventListener('click', () => {
      tabs.forEach(t => {
        document.getElementById(t.btn).classList.remove('active');
        document.getElementById(t.content).classList.remove('active');
      });
      document.getElementById(tab.btn).classList.add('active');
      document.getElementById(tab.content).classList.add('active');
      state.activeTab = tab.key;
    });
  });
}

function setupFilterPills() {
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.activeFilter = btn.dataset.filter;
      if (state.currentData) {
        renderPathsList(state.currentData.paths, state.currentData.predictions);
      }
    });
  });
}

async function loadScenariosList() {
  try {
    const res = await fetch('/api/scenarios');
    const data = await res.json();
    state.scenarios = data.scenarios || [];

    scenarioSelect.innerHTML = '<option value="">-- Select Built-in Scenario --</option>';
    state.scenarios.forEach(scen => {
      const opt = document.createElement('option');
      opt.value = scen.id;
      opt.textContent = `${scen.id}: ${scen.description}`;
      scenarioSelect.appendChild(opt);
    });

    if (state.scenarios.length > 0) {
      scenarioSelect.value = state.scenarios[0].id;
      loadScenario(state.scenarios[0].id);
    }
  } catch (err) {
    console.error("Error loading scenarios list:", err);
  }
}

async function loadScenario(scenarioId) {
  try {
    btnAnalyze.disabled = true;
    btnAnalyze.textContent = "⌛ Analyzing...";
    const res = await fetch(`/api/scenario/${scenarioId}`);
    const data = await res.json();
    renderAnalysisData(data);
  } catch (err) {
    alert("Error fetching scenario analysis: " + err.message);
  } finally {
    btnAnalyze.disabled = false;
    btnAnalyze.textContent = "⚡ Analyze Risk";
  }
}

async function analyzeScenario(rawScenario) {
  try {
    btnAnalyze.disabled = true;
    btnAnalyze.textContent = "⌛ Analyzing...";
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rawScenario),
    });
    const data = await res.json();
    renderAnalysisData(data);
  } catch (err) {
    alert("Error analyzing scenario: " + err.message);
  } finally {
    btnAnalyze.disabled = false;
    btnAnalyze.textContent = "⚡ Analyze Risk";
  }
}

async function execute1ClickRemediation() {
  if (!state.currentData || !state.currentData.choke_points || state.currentData.choke_points.length === 0) {
    alert("No choke points available to remediate.");
    return;
  }

  const topChoke = state.currentData.choke_points[0];
  try {
    btnRemediate.disabled = true;
    btnRemediate.textContent = "🪄 Applying Fix...";
    const res = await fetch('/api/remediate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scenario: state.currentData.raw_scenario,
        choke_point: topChoke,
      }),
    });
    const data = await res.json();
    renderAnalysisData(data);
  } catch (err) {
    alert("Error applying remediation: " + err.message);
  } finally {
    btnRemediate.disabled = false;
    btnRemediate.textContent = "🪄 1-Click Remediate";
  }
}

function renderAnalysisData(data) {
  state.currentData = data;
  state.selectedPathId = data.paths.length > 0 ? data.paths[0].path_id : null;

  scenarioTag.textContent = `SCENARIO: ${data.scenario_id.toUpperCase()}`;
  scenarioDesc.textContent = data.raw_scenario.description || `Attack graph analysis for ${data.scenario_id}`;

  // Update Stats Bar
  updateBadge(statRiskBadge, data.total_paths > 0 ? (data.overall_risk_label || 'LOW') : 'SECURE');
  statNodes.textContent = data.total_nodes || 0;
  statEdges.textContent = data.total_edges || 0;
  statPaths.textContent = data.total_paths || 0;
  statChokePoints.textContent = data.choke_points ? data.choke_points.length : 0;
  pathCountText.textContent = data.total_paths || 0;

  btnRemediate.disabled = !(data.choke_points && data.choke_points.length > 0);

  // Render Graph, Paths, SHAP, & Choke Points
  renderGraph(data.graph, data.choke_points);
  renderPathsList(data.paths, data.predictions);
  renderShapChart();
  renderRemediationHub(data.choke_points, data.remediation);
}

function updateBadge(element, label) {
  element.className = `badge badge-${label.toLowerCase()}`;
  element.textContent = label === 'SECURE' ? '🛡️ VERIFIED SECURE' : label;
}

// Graph Layout & SVG Rendering Engine
function renderGraph(graph, chokePoints) {
  graphSvg.innerHTML = '';
  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    graphEmptyState.style.display = 'block';
    return;
  }
  graphEmptyState.style.display = 'none';

  // Add SVG Defs for Arrow Markers
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
    </marker>
    <marker id="arrow-choke" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
    </marker>
  `;
  graphSvg.appendChild(defs);

  const chokeEdgeKeys = new Set((chokePoints || []).map(cp => cp.edge_key));

  const width = graphSvg.clientWidth || 700;
  const height = 450;
  const padding = 70;

  // Layout Nodes by Entity Type in Columns
  const nodesByType = { user: [], role: [], group: [], service: [], resource: [] };
  graph.nodes.forEach(n => {
    const type = (n.type || 'resource').toLowerCase();
    if (nodesByType[type]) nodesByType[type].push(n);
    else nodesByType.resource.push(n);
  });

  const columns = ['user', 'role', 'group', 'service', 'resource'].filter(t => nodesByType[t].length > 0);
  const colWidth = (width - 2 * padding) / Math.max(1, columns.length - 1);

  const posMap = {};
  columns.forEach((colType, colIdx) => {
    const list = nodesByType[colType];
    const x = columns.length === 1 ? width / 2 : padding + colIdx * colWidth;
    const rowHeight = (height - 2 * padding) / Math.max(1, list.length + 1);
    list.forEach((node, rowIdx) => {
      const y = padding + (rowIdx + 1) * rowHeight;
      posMap[node.id] = { x, y, ...node };
    });
  });

  // Edge type color map
  const edgeColorMap = {
    CAN_ASSUME: '#c084fc',
    CAN_PASS_ROLE: '#fb923c',
    CAN_ACCESS: '#34d399',
    CAN_MODIFY: '#f87171',
  };

  // Render Edges
  (graph.edges || []).forEach(edge => {
    const src = posMap[edge.source];
    const tgt = posMap[edge.target];
    if (src && tgt) {
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', src.x);
      line.setAttribute('y1', src.y);
      line.setAttribute('x2', tgt.x);
      line.setAttribute('y2', tgt.y);

      const ekey = `${edge.source}->${edge.target}:${edge.edge_type}[${(edge.actions || []).sort().join(',')}]`;
      const isChoke = chokeEdgeKeys.has(ekey);

      line.setAttribute('class', `graph-edge ${isChoke ? 'choke-edge' : ''}`);
      line.setAttribute('stroke', isChoke ? '#ef4444' : (edgeColorMap[edge.edge_type] || '#334155'));
      line.setAttribute('marker-end', isChoke ? 'url(#arrow-choke)' : 'url(#arrow)');
      line.setAttribute('data-edge-key', ekey);
      line.setAttribute('data-source', edge.source);
      line.setAttribute('data-target', edge.target);

      graphSvg.appendChild(line);
    }
  });

  // Render Nodes
  Object.values(posMap).forEach(node => {
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('class', 'graph-node');
    g.setAttribute('transform', `translate(${node.x}, ${node.y})`);

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('r', '15');

    const typeStr = (node.type || 'resource').toLowerCase();
    const colorMap = { user: '#38bdf8', role: '#c084fc', resource: '#34d399', group: '#fbbf24' };
    circle.setAttribute('fill', colorMap[typeStr] || '#34d399');
    circle.setAttribute('stroke', '#0f172a');
    circle.setAttribute('stroke-width', '2.5');

    g.addEventListener('click', () => showNodeModal(node));

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', '20');
    text.setAttribute('y', '4');
    text.textContent = node.name;

    g.appendChild(circle);
    g.appendChild(text);
    graphSvg.appendChild(g);
  });
}

function highlightPathOnGraph(path) {
  if (!path) return;
  const pathNodeSet = new Set(path.nodes);
  document.querySelectorAll('.graph-edge').forEach(edge => {
    const src = edge.getAttribute('data-source');
    const tgt = edge.getAttribute('data-target');
    if (pathNodeSet.has(src) && pathNodeSet.has(tgt)) {
      edge.classList.add('highlighted-edge');
    } else {
      edge.classList.remove('highlighted-edge');
    }
  });
}

function renderPathsList(paths, predictions) {
  pathsList.innerHTML = '';
  if (!paths || paths.length === 0) {
    pathsList.innerHTML = '<p class="placeholder-text">🛡️ Zero active attack paths discovered.</p>';
    return;
  }

  const predLookup = {};
  (predictions || []).forEach(p => predLookup[p.path_id] = p);

  const filtered = paths.filter(p => {
    if (state.activeFilter === 'ALL') return true;
    const pred = predLookup[p.path_id] || {};
    return pred.predicted_label === state.activeFilter;
  });

  if (filtered.length === 0) {
    pathsList.innerHTML = '<p class="placeholder-text">No paths match selected risk filter.</p>';
    return;
  }

  filtered.forEach(p => {
    const pred = predLookup[p.path_id] || { predicted_label: 'MEDIUM', predicted_score: 0.5 };
    const card = document.createElement('div');
    card.className = `path-card ${p.path_id === state.selectedPathId ? 'active' : ''}`;
    card.innerHTML = `
      <div class="path-info">
        <span class="path-chain">${p.nodes.join(' ➔ ')}</span>
        <span class="subtext">${p.hop_count} hops • ${p.source} to ${p.target}</span>
      </div>
      <span class="badge badge-${pred.predicted_label.toLowerCase()}">${pred.predicted_label} (${(pred.predicted_score * 100).toFixed(0)}%)</span>
    `;

    card.addEventListener('click', () => {
      document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      state.selectedPathId = p.path_id;
      highlightPathOnGraph(p);
      renderShapChart();
    });

    pathsList.appendChild(card);
  });

  if (state.selectedPathId) {
    const initialPath = paths.find(p => p.path_id === state.selectedPathId);
    highlightPathOnGraph(initialPath);
  }
}

function renderShapChart() {
  shapChart.innerHTML = '';
  if (!state.selectedPathId || !state.currentData || !state.currentData.explanations) {
    shapChart.innerHTML = '<p class="placeholder-text">Select an attack path from the left panel to inspect SHAP feature attributions.</p>';
    selectedPathIdText.textContent = "Select Path";
    return;
  }

  selectedPathIdText.textContent = state.selectedPathId;
  const exp = state.currentData.explanations.find(e => e.path_id === state.selectedPathId);
  const factors = exp ? exp.top_factors : [];

  if (factors.length === 0) {
    shapChart.innerHTML = '<p class="placeholder-text">No feature factors calculated for this path.</p>';
    return;
  }

  const maxImpact = Math.max(...factors.map(f => Math.abs(f.impact)), 0.01);

  factors.forEach(f => {
    const row = document.createElement('div');
    row.className = 'bar-row';
    const percent = Math.min(100, Math.round((Math.abs(f.impact) / maxImpact) * 100));

    row.innerHTML = `
      <div class="bar-meta">
        <span><code>${f.feature}</code></span>
        <span>${f.impact >= 0 ? '+' : ''}${f.impact.toFixed(4)}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${percent}%;"></div>
      </div>
    `;
    shapChart.appendChild(row);
  });
}

function renderRemediationHub(chokePoints, remediation) {
  chokePointsList.innerHTML = '';
  if (!chokePoints || chokePoints.length === 0) {
    chokePointsList.innerHTML = '<p class="placeholder-text">🛡️ No choke points required. System is completely secure.</p>';
  } else {
    chokePoints.forEach(cp => {
      const item = document.createElement('div');
      item.className = 'choke-item';
      item.innerHTML = `
        <div class="choke-title">📍 Choke Point ${cp.choke_point_id}: ${cp.source} ➔ ${cp.target} (${cp.edge_type})</div>
        <div>${cp.reasoning}</div>
        <div class="subtext" style="margin-top:0.3rem;">Score: ${cp.choke_score} | Paths Severed: ${cp.paths_blocked}</div>
      `;
      chokePointsList.appendChild(item);
    });
  }

  if (remediation && remediation.diff) {
    policyDiffViewer.innerHTML = `<pre class="code-block">${JSON.stringify(remediation.diff, null, 2)}</pre>`;
  } else {
    policyDiffViewer.innerHTML = '<p class="placeholder-text">No policy diff generated.</p>';
  }

  if (remediation && remediation.playbook) {
    playbookViewer.textContent = remediation.playbook;
  } else {
    playbookViewer.textContent = "No playbook generated.";
  }
}
