/**
 * ADAM Mutation Test Console Controller
 * Subscribes to SSE stream from /api/v1/mutation-tests/{session_id}/stream
 * Updates live event console, mutation inspector, and validation results.
 */

let activeEventSource = null;
let isStreamPaused = false;
let currentSessionId = "";
let currentManifest = null;
let loadedMutations = new Map();
let causalEventsList = [];

document.addEventListener('DOMContentLoaded', async () => {
  const sessionIdInput = document.getElementById('input-session-id');
  if (sessionIdInput) {
    currentSessionId = sessionIdInput.value.trim();
  }

  await loadManifest();
  initCommandSelectors();
  initActionButtons();
  initConsoleControls();
  
  if (currentSessionId) {
    connectSseStream(currentSessionId);
  }
});

async function loadManifest() {
  try {
    const res = await fetch('/api/v1/mutation-tests/commands');
    if (res.ok) {
      currentManifest = await res.json();
      updateExpectedSpec();
    }
  } catch (err) {
    console.error("Failed to load command manifest:", err);
  }
}

function initCommandSelectors() {
  const selectCmd = document.getElementById('select-command');
  const filterPills = document.querySelectorAll('.filter-pill');

  if (selectCmd) {
    selectCmd.addEventListener('change', () => {
      updateExpectedSpec();
    });
  }

  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      const sev = pill.dataset.sev;
      filterCommandsBySeverity(sev);
    });
  });
}

function filterCommandsBySeverity(sev) {
  const selectCmd = document.getElementById('select-command');
  if (!selectCmd || !currentManifest) return;

  selectCmd.innerHTML = '';
  const commands = currentManifest.commands || [];
  const filtered = sev === 'ALL' ? commands : commands.filter(c => c.severity === sev);

  filtered.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c.id;
    opt.textContent = `${c.severity} | ${c.name}`;
    selectCmd.appendChild(opt);
  });

  updateExpectedSpec();
}

function updateExpectedSpec() {
  const selectCmd = document.getElementById('select-command');
  if (!selectCmd || !currentManifest) return;

  const cmdId = selectCmd.value;
  const cmd = (currentManifest.commands || []).find(c => c.id === cmdId);
  if (!cmd) return;

  document.getElementById('exp-desc').textContent = cmd.description || '--';
  document.getElementById('exp-intent').textContent = cmd.expected_intent || '--';
  document.getElementById('exp-action').textContent = cmd.expected_policy_action || '--';
  document.getElementById('exp-verdict').textContent = cmd.expected_verdict || '--';
  document.getElementById('exp-primitive').textContent = cmd.expected_primitive || 'NONE';
}

function initActionButtons() {
  const injectBtn = document.getElementById('btn-inject-harness');
  const stopBtn = document.getElementById('btn-stop-session');
  const execBtn = document.getElementById('btn-execute-command');

  if (injectBtn) {
    injectBtn.addEventListener('click', async () => {
      const sessionIdInput = document.getElementById('input-session-id');
      const sid = sessionIdInput ? sessionIdInput.value.trim() : "";
      
      injectBtn.disabled = true;
      injectBtn.textContent = 'Injecting...';

      try {
        const res = await fetch('/api/v1/mutation-tests/inject', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: sid || undefined })
        });
        const data = await res.json();
        if (res.ok) {
          currentSessionId = data.session_id;
          if (sessionIdInput) sessionIdInput.value = currentSessionId;

          const badge = document.getElementById('harness-injected-badge');
          badge.textContent = 'Active (Test Mode)';
          badge.style.background = 'rgba(57,255,20,0.2)';
          badge.style.color = '#39ff14';
          badge.style.borderColor = '#39ff14';

          connectSseStream(currentSessionId);
          alert(`Test harness active on session: ${currentSessionId}`);
        } else {
          alert(`Injection failed: ${data.detail || JSON.stringify(data)}`);
        }
      } catch (err) {
        alert(`Network error during injection: ${err}`);
      } finally {
        injectBtn.disabled = false;
        injectBtn.innerHTML = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg> Inject Executable`;
      }
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener('click', async () => {
      if (!currentSessionId) return;
      try {
        await fetch(`/api/v1/mutation-tests/${currentSessionId}/stop`, { method: 'POST' });
        if (activeEventSource) activeEventSource.close();
        const badge = document.getElementById('harness-injected-badge');
        badge.textContent = 'Stopped';
        badge.style.background = 'rgba(255,0,60,0.2)';
        badge.style.color = '#ff003c';
        badge.style.borderColor = '#ff003c';
      } catch (e) {
        console.error("Stop session note:", e);
      }
    });
  }

  if (execBtn) {
    execBtn.addEventListener('click', async () => {
      if (!currentSessionId) {
        alert("Please inject test harness or provide a valid Session ID first.");
        return;
      }
      const selectCmd = document.getElementById('select-command');
      const cmdId = selectCmd.value;
      if (!cmdId) return;

      execBtn.disabled = true;
      execBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"></path></svg> Executing stimulus...`;

      try {
        const res = await fetch(`/api/v1/mutation-tests/${currentSessionId}/execute`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command_id: cmdId })
        });
        const data = await res.json();
        if (res.ok) {
          const cmdEvt = {
            event_type: 'COMMAND',
            timestamp: new Date().toISOString(),
            id: `cmd_${cmdId}`,
            details: `[TEST TRIGGER DISPATCHED] Executing '${data.command_name}' (${data.severity})`
          };
          appendConsoleLog(cmdEvt);
          causalEventsList.push(cmdEvt);
          updateCausalTimeline(causalEventsList);

          // Fetch evaluation result after closed loop completes
          setTimeout(() => pollTestResults(currentSessionId), 600);
          setTimeout(() => pollTestResults(currentSessionId), 1500);
        } else {
          alert(`Execution error: ${data.detail || 'Failed'}`);
        }
      } catch (err) {
        alert(`Execution network error: ${err}`);
      } finally {
        execBtn.disabled = false;
        execBtn.innerHTML = `<svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"></path></svg> Execute Test Stimulus`;
      }
    });
  }
}

async function pollTestResults(sessionId) {
  try {
    const res = await fetch(`/api/v1/mutation-tests/${sessionId}/results`);
    if (res.ok) {
      const data = await res.json();
      updateResultCard(data);
    }
  } catch (err) {
    console.error("Result fetch error:", err);
  }
}

function updateResultCard(res) {
  const badge = document.getElementById('result-verdict-badge');
  const card = document.getElementById('test-result-card');
  const verdict = res.verdict || 'READY';

  badge.textContent = verdict;
  if (verdict === 'PASS') {
    badge.style.background = '#39ff14';
    badge.style.color = '#000';
    card.style.borderLeftColor = '#39ff14';
  } else if (verdict === 'PARTIAL') {
    badge.style.background = '#ffea00';
    badge.style.color = '#000';
    card.style.borderLeftColor = '#ffea00';
  } else {
    badge.style.background = '#ff003c';
    badge.style.color = '#fff';
    card.style.borderLeftColor = '#ff003c';
  }

  document.getElementById('res-intent-match').textContent = res.observed?.intent || 'None';
  document.getElementById('res-policy-match').textContent = `${res.observed?.policy_action || 'None'} (${res.observed?.policy_verdict || '--'})`;
  document.getElementById('res-mutation-match').textContent = res.observed?.mutation_status || 'N/A';
  document.getElementById('res-latency').textContent = res.observed?.latency_ms ? `${Math.round(res.observed.latency_ms)} ms` : '--';
}

function updateCausalTimeline(events) {
  const container = document.getElementById('causal-timeline-container');
  if (!container) return;

  container.innerHTML = '';
  events.forEach((evt, idx) => {
    const step = document.createElement('div');
    step.style.background = 'rgba(0,0,0,0.5)';
    step.style.border = '1px solid rgba(57,255,20,0.2)';
    step.style.padding = '8px 12px';
    step.style.borderRadius = '4px';
    step.style.minWidth = '140px';
    step.style.display = 'flex';
    step.style.flexDirection = 'column';
    step.style.gap = '2px';

    const timeStr = evt.timestamp ? evt.timestamp.substring(11, 19) : '--:--:--';
    step.innerHTML = `
      <div style="font-size: 0.65rem; color: var(--text-muted);">${timeStr}</div>
      <div style="font-weight: 700; color: #39ff14;">${evt.event_type || 'STAGE'}</div>
      <div style="font-size: 0.72rem; color: #fff;">${evt.id || evt.intent || evt.action || evt.primitive || ''}</div>
    `;
    container.appendChild(step);

    if (idx < events.length - 1) {
      const arrow = document.createElement('div');
      arrow.style.color = '#39ff14';
      arrow.style.display = 'flex';
      arrow.style.alignItems = 'center';
      arrow.innerHTML = '&rarr;';
      container.appendChild(arrow);
    }
  });
}

function initConsoleControls() {
  const pauseBtn = document.getElementById('btn-pause-stream');
  const clearBtn = document.getElementById('btn-clear-console');

  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      isStreamPaused = !isStreamPaused;
      document.getElementById('pause-stream-text').textContent = isStreamPaused ? 'Resume Stream' : 'Pause Stream';
      pauseBtn.style.color = isStreamPaused ? '#ffea00' : 'inherit';
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      document.getElementById('live-console-feed').innerHTML = '';
      causalEventsList = [];
      updateCausalTimeline(causalEventsList);
    });
  }
}

function connectSseStream(sessionId) {
  if (activeEventSource) {
    activeEventSource.close();
  }

  const url = `/api/v1/mutation-tests/${sessionId}/stream`;
  activeEventSource = new EventSource(url);

  const statusBadge = document.getElementById('connection-status-badge');
  if (statusBadge) {
    statusBadge.textContent = 'SSE: Connected';
    statusBadge.style.color = '#39ff14';
  }

  activeEventSource.onmessage = (event) => {
    if (isStreamPaused) return;
    try {
      const data = JSON.parse(event.data);
      appendConsoleLog(data);
      causalEventsList.push(data);
      updateCausalTimeline(causalEventsList);

      if (data.event_type === 'MUTATION') {
        openMutationInspector(data);
        if (currentSessionId) {
          pollTestResults(currentSessionId);
        }
      }
    } catch (e) {
      console.error("SSE parse error", e);
    }
  };

  activeEventSource.onerror = (err) => {
    if (statusBadge) {
      statusBadge.textContent = 'SSE: Reconnecting...';
      statusBadge.style.color = '#ffea00';
    }
  };
}

function appendConsoleLog(evt) {
  const container = document.getElementById('live-console-feed');
  if (!container) return;

  // Remove welcome banner if present
  const welcome = container.querySelector('.console-welcome');
  if (welcome) welcome.remove();

  const type = evt.event_type || 'EVENT';
  const typeLower = type.toLowerCase();
  const timeStr = evt.timestamp ? evt.timestamp.substring(11, 23) : new Date().toISOString().substring(11, 23);

  const card = document.createElement('div');
  card.className = `console-event-card event-${typeLower}`;

  let headerHtml = `
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span class="tag-badge tag-${typeLower}">${type}</span>
        <span style="color: #ffffff; font-weight: 600;">${evt.id || ''}</span>
      </div>
      <span style="color: var(--text-muted); font-size: 0.75rem;">${timeStr}</span>
    </div>
  `;

  let bodyHtml = '';

  if (type === 'RAW') {
    bodyHtml = `<div style="color: #00e5ff; font-size: 0.8rem;">[${evt.category}] ${evt.details || ''}</div>`;
  } else if (type === 'SEMANTIC') {
    const causalAttr = evt.caused_by_mutation ? `<span style="color: #39ff14; font-weight: 700;">[CAUSED BY: ${evt.caused_by_mutation}]</span>` : '';
    bodyHtml = `
      <div style="display: flex; justify-content: space-between; align-items: center; color: #39ff14;">
        <span><strong>Intent:</strong> ${evt.intent} (Conf: ${evt.confidence ? Math.round(evt.confidence * 100) : 0}%)</span>
        <span class="badge badge-sm" style="background: rgba(57,255,20,0.1); color: #39ff14;">${evt.severity}</span>
      </div>
      ${causalAttr ? `<div style="font-size: 0.75rem; margin-top: 2px;">${causalAttr}</div>` : ''}
    `;
  } else if (type === 'POLICY') {
    bodyHtml = `
      <div style="color: #ffaa00;">
        <strong>Rule:</strong> ${evt.rule_id} &rarr; <strong>Action:</strong> ${evt.action} [${evt.verdict}]
      </div>
      <div style="color: var(--text-muted); font-size: 0.75rem;">${evt.rationale || ''}</div>
    `;
  } else if (type === 'MUTATION') {
    loadedMutations.set(evt.id, evt);
    bodyHtml = `
      <div style="color: #ff0077; font-weight: 700;">
        &gt;&gt; PRIMITIVE APPLIED: ${evt.primitive} (${Math.round(evt.latency_ms || 0)}ms)
      </div>
      <div style="color: #fff; font-size: 0.75rem; display: flex; justify-content: space-between;">
        <span>Plausibility: ${evt.plausibility_score} | Changes: ${evt.changes ? evt.changes.length : 0}</span>
        <span style="text-decoration: underline; color: #ff0077;">Click to Inspect &rarr;</span>
      </div>
    `;
    card.addEventListener('click', () => openMutationInspector(evt));
  } else {
    bodyHtml = `<div style="color: #aaa;">${evt.details || ''}</div>`;
  }

  card.innerHTML = headerHtml + bodyHtml;
  container.appendChild(card);

  const autoscroll = document.getElementById('chk-autoscroll');
  if (autoscroll && autoscroll.checked) {
    container.scrollTop = container.scrollHeight;
  }
}

function openMutationInspector(mut) {
  document.getElementById('inspector-placeholder').style.display = 'none';
  const content = document.getElementById('inspector-content');
  content.style.display = 'block';

  document.getElementById('insp-badge-status').style.display = 'inline-block';
  document.getElementById('insp-badge-status').textContent = mut.status || 'APPLIED';

  document.getElementById('insp-primitive').textContent = mut.primitive;
  document.getElementById('insp-corr-id').textContent = mut.correlation_id || 'corr_unknown';
  document.getElementById('insp-plausibility').textContent = `${mut.plausibility_score} (Rationale: ${mut.plausibility_notes || 'Verified'})`;
  document.getElementById('insp-latency-window').textContent = `${Math.round(mut.latency_ms || 0)} ms / ${mut.causal_window_ms || 30000} ms`;

  const expl = mut.explanation || {};
  document.getElementById('insp-expl-title').textContent = expl.title || 'Generated Synthetic Environment';
  document.getElementById('insp-expl-summary').textContent = expl.summary || 'Deception primitive executed in sandbox.';

  const artContainer = document.getElementById('insp-expl-artifacts');
  artContainer.innerHTML = '';
  if (expl.artifacts) {
    Object.entries(expl.artifacts).forEach(([k, v]) => {
      const row = document.createElement('div');
      row.style.display = 'flex';
      row.style.gap = '8px';
      
      const keySpan = document.createElement('span');
      keySpan.style.color = '#39ff14';
      keySpan.minWidth = '160px';
      keySpan.textContent = `${k}:`;
      
      const valSpan = document.createElement('span');
      valSpan.style.color = '#ffffff';
      valSpan.textContent = Array.isArray(v) ? v.join(', ') : String(v);

      row.appendChild(keySpan);
      row.appendChild(valSpan);
      artContainer.appendChild(row);
    });
  }

  const tbody = document.getElementById('insp-changes-tbody');
  tbody.innerHTML = '';
  (mut.changes || []).forEach(c => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge badge-sm" style="background: rgba(0,229,255,0.1); color: #00e5ff;">${c.kind}</span></td>
      <td><strong>${c.operation}</strong></td>
      <td><code>${c.target}</code></td>
      <td style="color: #ffea00;">${c.value || '--'}</td>
    `;
    tbody.appendChild(tr);
  });

  // Update Transformation Before/After Card
  updateTransformationState(mut);

  document.getElementById('mutation-inspector-card').scrollIntoView({ behavior: 'smooth' });
}

function updateTransformationState(mut) {
  const label = document.getElementById('trans-mutation-label');
  if (label) label.textContent = mut.primitive || 'ADAM MUTATION';

  const expl = mut.explanation || {};
  const artifacts = expl.artifacts || {};

  const domainEl = document.getElementById('trans-after-domain');
  const dcsEl = document.getElementById('trans-after-dcs');
  const sharesEl = document.getElementById('trans-after-shares');
  const artEl = document.getElementById('trans-after-artifacts');

  if (domainEl) domainEl.textContent = artifacts.domain || artifacts["Primary Domain"] || 'CORP.LOCAL';
  if (dcsEl) dcsEl.textContent = artifacts.domain_controllers ? artifacts.domain_controllers.join(', ') : (artifacts["Domain Controllers"] || 'DC01.CORP.LOCAL (10.0.0.10)');
  if (sharesEl) sharesEl.textContent = artifacts.network_shares ? artifacts.network_shares.join(', ') : (artifacts["Decoy Shares"] || '\\\\127.0.0.1\\Financials');
  if (artEl) artEl.textContent = expl.summary || `${mut.changes ? mut.changes.length : 1} dynamic environment modifications applied`;
}
