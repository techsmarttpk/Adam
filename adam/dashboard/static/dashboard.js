/**
 * ADAM Dashboard Frontend Controller
 * Minimal vanilla JS for SSE telemetry streams, filtering, tabs, and actions.
 * Highly customizable - add your custom button handlers at the bottom!
 */

document.addEventListener('DOMContentLoaded', () => {
  initSplash();
  initTabs();
  initTelemetryFilters();
  initCorrelationTracer();
  initHeaderClock();
  
  // Custom button placeholders will be initialized here
  initCustomButtons();
});

/**
 * Live system header clock update
 */
function initHeaderClock() {
  const clockEl = document.getElementById('live-header-timestamp');
  if (!clockEl) return;
  
  function updateClock() {
    const now = new Date();
    let hours = now.getHours();
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12;
    clockEl.textContent = `${hours}:${minutes} ${ampm}`;
  }
  
  updateClock();
  setInterval(updateClock, 1000);
}

/**
 * 0. WELCOME SPLASH SCREEN
 * Toggles visibility of the fullscreen welcome animation when the user
 * visits the dashboard for the first time in the current session.
 */
function initSplash() {
  const overlay = document.getElementById('splash-overlay');
  const enterBtn = document.getElementById('btn-enter-dashboard');
  if (!overlay) return;

  if (sessionStorage.getItem('adam_splash_shown')) {
    overlay.style.display = 'none';
  } else {
    overlay.style.display = 'flex'; // Ensure it displays
    if (enterBtn) {
      enterBtn.addEventListener('click', () => {
        overlay.classList.add('fade-out');
        sessionStorage.setItem('adam_splash_shown', 'true');
        // Hide overlay element fully after fade-out transition completes
        setTimeout(() => {
          overlay.style.display = 'none';
        }, 800);
      });
    }
  }
}

/**
 * 1. WORKSPACE TAB NAVIGATION
 * Switches between Live Feed, Decision Ledger, and Mutation Timeline
 */
function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  const contents = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      
      tabs.forEach(t => t.classList.remove('active'));
      contents.forEach(c => c.classList.remove('active'));
      
      tab.classList.add('active');
      const targetContent = document.getElementById(`${target}-tab`);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });
}

/**
 * 2. TELEMETRY FILTERING
 * Allows operators to show/hide raw events, semantic intent detections,
 * policy decisions, or applied VM mutations in the live feed window.
 */
function initTelemetryFilters() {
  const filterBtns = document.querySelectorAll('.filter-btn');
  const feedBox = document.getElementById('telemetry-feed-container') || document.querySelector('.feed-box');
  const clearBtn = document.getElementById('btn-clear-feed');

  if (!feedBox || filterBtns.length === 0) return;

  const validTypes = ['raw', 'semantic', 'decision', 'mutation'];

  function applyFilterState() {
    const activeTypes = Array.from(document.querySelectorAll('.filter-btn.active'))
      .map(b => b.dataset.filter)
      .filter(t => validTypes.includes(t));

    const allRows = feedBox.querySelectorAll('.feed-row');
    allRows.forEach(row => {
      if (activeTypes.length === 0) {
        row.style.setProperty('display', 'flex', 'important');
        return;
      }

      let isMatch = false;
      for (const type of activeTypes) {
        if (row.classList.contains(type)) {
          isMatch = true;
          break;
        }
      }
      row.style.setProperty('display', isMatch ? 'flex' : 'none', 'important');
    });
  }

  filterBtns.forEach(btn => {
    btn.onclick = function(e) {
      e.preventDefault();
      e.stopPropagation();
      btn.classList.toggle('active');
      applyFilterState();
    };
  });

  if (clearBtn) {
    clearBtn.onclick = function(e) {
      e.preventDefault();
      e.stopPropagation();
      filterBtns.forEach(b => b.classList.remove('active'));
      applyFilterState();
    };
  }

  applyFilterState();
}

/**
 * 3. CORRELATION ID TRACING
 * Traces a semantic event, policy decision, or mutation back to the raw events that caused it.
 * Clicking a correlation ID highlights all other telemetry items with the same correlation ID.
 */
function initCorrelationTracer() {
  const feedBox = document.querySelector('.feed-box');
  if (!feedBox) return;

  feedBox.addEventListener('click', (e) => {
    const traceLink = e.target.closest('.trace-link');
    if (!traceLink) return;

    e.preventDefault();
    const corrId = traceLink.dataset.correlation;
    if (!corrId) return;

    // Remove existing highlights
    document.querySelectorAll('.feed-row').forEach(row => {
      row.classList.remove('highlighted-event');
    });

    // Highlight all elements matching this correlation ID
    const matchingElements = document.querySelectorAll(`[data-corr-id="${corrId}"]`);
    matchingElements.forEach(el => {
      el.classList.add('highlighted-event');
    });

    // Scroll the first highlighted element into view if desired
    if (matchingElements.length > 0) {
      matchingElements[0].scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  });
}

/**
 * 4. LIVE EVENTS INGESTION (SSE Client Template)
 * Example hook for connecting to the FastAPI Server-Sent Events stream.
 * In a real run, this binds to: `/api/v1/sessions/{session_id}/stream`
 */
class TelemetryStream {
  constructor(sessionId, feedElementId) {
    this.sessionId = sessionId;
    this.feedElement = document.getElementById(feedElementId);
    this.eventSource = null;
  }

  connect() {
    if (!this.feedElement) return;

    const streamUrl = `/api/v1/sessions/${this.sessionId}/stream`;
    this.eventSource = new EventSource(streamUrl);

    this.eventSource.onmessage = (event) => {
      try {
        const envelope = JSON.parse(event.data);
        this.appendEvent(envelope);
      } catch (err) {
        console.error('Failed to parse telemetry envelope:', err);
      }
    };

    this.eventSource.onerror = (err) => {
      console.warn('Telemetry SSE connection lost. Reconnecting...', err);
    };
  }

  disconnect() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  appendEvent(envelope) {
    const { message_type, correlation_id, emitted_at, payload } = envelope;
    const row = document.createElement('div');
    row.className = `feed-row ${message_type.toLowerCase()}`;
    row.dataset.corrId = correlation_id;

    let meta = `[${emitted_at}] | Type: ${message_type}`;
    if (correlation_id) {
      meta += ` | Corr: <a href="#" class="trace-link" data-correlation="${correlation_id}">${correlation_id}</a>`;
    }

    let bodyText = JSON.stringify(payload, null, 2);

    row.innerHTML = `
      <div class="feed-row-meta">${meta}</div>
      <pre class="feed-row-content">${bodyText}</pre>
    `;

    this.feedElement.appendChild(row);
    this.feedElement.scrollTop = this.feedElement.scrollHeight; // Auto-scroll
  }
}

/**
 * 5. CUSTOM USER BUTTONS & INTEGRATIONS
 * Put your customized buttons and handlers here! 
 * When adding new interactive features, register them inside this function.
 */
function initCustomButtons() {
  console.log("ADAM Custom Buttons Initializer ready.");

  /* 
     Example custom button hook:
     
     const myCustomBtn = document.getElementById('btn-custom-action');
     if (myCustomBtn) {
       myCustomBtn.addEventListener('click', async () => {
         const sessionId = myCustomBtn.dataset.sessionId;
         try {
           const response = await fetch(`/api/v1/sessions/${sessionId}/custom-action`, {
             method: 'POST',
             headers: { 'Content-Type': 'application/json' }
           });
           const result = await response.json();
           alert(`Action complete: ${result.status}`);
         } catch (error) {
           console.error('Custom action failed:', error);
         }
       });
     }
  */
}
