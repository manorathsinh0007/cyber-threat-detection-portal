/**
 * Application Master Controller & State Orchestrator
 * Connects all 12 modules, controls view routing, DEFCON state, real-time live ticker, and event bindings.
 */

class App {
  constructor() {
    this.currentView = 'dashboard';
    this.defconLevel = 2;
    this.totalPackets = 142850;
    this.threatCount = 1420;
    this.tickerInterval = null;
    this.attackMap = null;
  }

  async init() {
    console.log('[*] Initializing AI Cyber Threat Detection SOC Portal...');

    // 1. Initialize Authentication UI
    window.authService.updateUI();

    // 2. Initialize Datasets
    await window.datasetService.init();

    // 3. Initialize Attack Map
    this.attackMap = new window.AttackMap('attack-map-canvas');

    // 4. Initialize Analytics Charts
    window.analyticsService.init();

    // 5. Render Threat Logs Table
    window.threatLogsService.renderTable();

    // 6. Setup Event Listeners & Navigation
    this.bindEvents();

    // 7. Start Live Network Telemetry Ticker
    this.startLiveStream();

    // 8. Render Datasets UI
    this.renderDatasetSelector();
    this.renderPreprocessingView();

    // 9. Initialize Real-World Network Backend Client
    if (window.realTimeNetwork) {
      window.realTimeNetwork.init();
    }

    // 10. Initialize Mini Cyber Attacker & Verification Bench
    if (window.cyberAttacker) {
      window.cyberAttacker.init();
    }

    console.log('[✓] Portal Operational.');
  }

  /**
   * View Navigation
   */
  switchView(viewName) {
    this.currentView = viewName;

    // Update nav active styles
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-view') === viewName) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update section visibility
    document.querySelectorAll('.view-section').forEach(sec => {
      sec.classList.remove('active');
    });

    const targetSection = document.getElementById(`view-${viewName}`);
    if (targetSection) {
      targetSection.classList.add('active');
    }

    // Trigger chart or map resize if needed
    if (viewName === 'dashboard' && this.attackMap) {
      this.attackMap.resize();
    } else if (viewName === 'analytics') {
      window.analyticsService.drawRocCurve();
    } else if (viewName === 'cyber_attacker' && window.cyberAttacker) {
      window.cyberAttacker.checkWebsiteHealth(false);
    }
  }

  /**
   * Set DEFCON Alert Posture (1 to 5)
   */
  setDefcon(level) {
    this.defconLevel = level;
    const defconBadge = document.getElementById('defcon-badge-text');
    const defconPill = document.getElementById('defcon-pill-box');

    if (defconBadge) {
      defconBadge.textContent = `DEFCON ${level}`;
    }

    if (defconPill) {
      if (level === 1) {
        defconPill.style.borderColor = 'var(--alert-red)';
        defconPill.style.color = 'var(--alert-red)';
        window.alertsService.showToast('DEFCON 1 IMMINENT', 'Maximum readiness posture engaged. Active cyber warfare protocols initiated.', 'danger');
      } else if (level === 2) {
        defconPill.style.borderColor = 'var(--warning-amber)';
        defconPill.style.color = 'var(--warning-amber)';
      } else {
        defconPill.style.borderColor = 'var(--neon-cyan)';
        defconPill.style.color = 'var(--neon-cyan)';
      }
    }
  }

  /**
   * Real-Time Stream Ticker for SOC Live Feed
   */
  startLiveStream() {
    if (this.tickerInterval) clearInterval(this.tickerInterval);

    this.tickerInterval = setInterval(() => {
      this.totalPackets += Math.floor(15 + Math.random() * 35);
      const totalPktEl = document.getElementById('hud-total-packets');
      if (totalPktEl) totalPktEl.textContent = this.totalPackets.toLocaleString();

      // 40% chance of generating an incoming live threat
      if (Math.random() < 0.45) {
        const livePkt = window.datasetService.generateLivePacket();
        const pred = window.mlEngine.predict(livePkt);

        if (pred.prediction !== 'Benign Traffic') {
          this.threatCount++;
          const threatCountEl = document.getElementById('hud-active-threats');
          if (threatCountEl) threatCountEl.textContent = this.threatCount.toLocaleString();

          // Add to live stream ticker list in Dashboard
          this.addLiveStreamItem(livePkt, pred);

          // Add to log service
          window.threatLogsService.addIncident({
            sourceIp: livePkt.Source_IP,
            destIp: livePkt.Dest_IP,
            destPort: livePkt.Dest_Port,
            protocol: livePkt.Protocol,
            category: pred.prediction,
            riskLevel: pred.riskLevel,
            confidence: pred.confidence,
            payloadSnippet: livePkt.Payload_Signature,
            model: pred.modelUsed,
            rawPacket: livePkt
          });

          // Trigger sound if Critical
          if (pred.riskLevel === 'CRITICAL' && Math.random() < 0.3) {
            window.alertsService.playAlertSound('critical');
          }
        }
      }
    }, 2200);
  }

  addLiveStreamItem(pkt, pred) {
    const list = document.getElementById('threat-stream-list');
    if (!list) return;

    const div = document.createElement('div');
    const sevClass = pred.riskLevel === 'CRITICAL' ? '' : pred.riskLevel === 'HIGH' ? 'medium-sev' : 'low-sev';
    div.className = `threat-stream-item ${sevClass}`;
    
    div.innerHTML = `
      <div class="stream-item-top">
        <span class="stream-item-category"><i class="fas fa-biohazard"></i> ${pred.prediction}</span>
        <span class="stream-item-time">${new Date().toLocaleTimeString()}</span>
      </div>
      <div class="stream-item-details">
        <span>SRC: ${pkt.Source_IP}</span>
        <span>→</span>
        <span>DST: ${pkt.Dest_IP}:${pkt.Dest_Port}</span>
      </div>
      <div class="stream-item-meta">
        <span class="severity-badge ${pred.riskLevel === 'CRITICAL' ? 'severity-critical' : 'severity-high'}">${pred.riskLevel}</span>
        <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--neon-cyan); font-weight: 600;">
          AI Conf: ${pred.confidence}%
        </span>
      </div>
    `;

    div.onclick = () => {
      // Find latest incident and open investigation
      if (window.threatLogsService.logs.length > 0) {
        window.forensicInvestigator.openInvestigation(window.threatLogsService.logs[0].id);
      }
    };

    list.prepend(div);

    // Keep only top 20 items
    if (list.children.length > 20) {
      list.removeChild(list.lastChild);
    }
  }

  /**
   * Render Dataset Selector Cards
   */
  renderDatasetSelector() {
    const grid = document.getElementById('preset-datasets-grid');
    if (!grid) return;

    grid.innerHTML = '';
    window.datasetService.datasets.forEach(d => {
      const isSelected = window.datasetService.activeDataset && window.datasetService.activeDataset.id === d.id;
      const card = document.createElement('div');
      card.className = `dataset-card ${isSelected ? 'selected' : ''}`;
      card.innerHTML = `
        <div class="title"><i class="fas fa-database" style="color: var(--neon-cyan); margin-right: 6px;"></i> ${d.name}</div>
        <div class="desc">${d.description}</div>
        <div class="dataset-card-meta">
          <span><i class="fas fa-list-ol"></i> ${d.recordsCount || d.sampleRows.length} Rows</span>
          <span><i class="fas fa-bolt"></i> ${isSelected ? 'ACTIVE BENCHMARK' : 'CLICK TO LOAD'}</span>
        </div>
      `;
      card.onclick = () => {
        window.datasetService.selectDataset(d.id);
        this.renderDatasetSelector();
        this.renderPreprocessingView();
        window.alertsService.showToast('Dataset Loaded', `Switched to "${d.name}" with ${d.sampleRows.length} flow samples.`, 'info');
      };
      grid.appendChild(card);
    });
  }

  /**
   * Render Preprocessing Pipeline Steps & Data Previews
   */
  renderPreprocessingView() {
    const data = window.datasetService.runPreprocessingPipeline();
    if (!data) return;

    // Render Preview Table for Active Step
    const tableContainer = document.getElementById('preprocessing-table-preview');
    if (!tableContainer) return;

    const step = window.datasetService.currentStep;
    let previewRows = [];
    let headers = [];

    if (step === 1) {
      previewRows = data.raw.slice(0, 5);
      headers = ['ID', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Entropy', 'Payload Signature', 'Label'];
    } else if (step === 2) {
      previewRows = data.cleaned.slice(0, 5);
      headers = ['ID', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Clean_Entropy', 'SYN_Count', 'Label'];
    } else if (step === 3) {
      previewRows = data.encoded.slice(0, 5);
      headers = ['ID', 'Source IP', 'Port', 'Protocol_Encoded', 'Is_WellKnown_Port', 'Clean_Entropy'];
    } else {
      previewRows = data.normalized.slice(0, 5);
      headers = ['ID', 'Scaled_Duration', 'Scaled_Fwd_Pkts', 'Scaled_Entropy', 'SYN_ACK_Ratio', 'Outlier_Flag'];
    }

    let html = `
      <table class="cyber-table">
        <thead>
          <tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr>
        </thead>
        <tbody>
    `;

    previewRows.forEach(r => {
      html += `<tr>`;
      if (step === 1) {
        html += `<td>${r.id}</td><td>${r.Source_IP}</td><td>${r.Dest_IP}</td><td>${r.Dest_Port}</td><td>${r.Protocol}</td><td>${r.Packet_Entropy}</td><td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${r.Payload_Signature}</td><td style="color: var(--neon-cyan);">${r.Actual_Label}</td>`;
      } else if (step === 2) {
        html += `<td>${r.id}</td><td>${r.Source_IP}</td><td>${r.Dest_IP}</td><td>${r.Dest_Port}</td><td>${r.Protocol}</td><td>${r.Packet_Entropy}</td><td>${r.SYN_Flag_Count}</td><td style="color: var(--neon-cyan);">${r.Actual_Label}</td>`;
      } else if (step === 3) {
        html += `<td>${r.id}</td><td>${r.Source_IP}</td><td>${r.Dest_Port}</td><td>${r.Protocol_Encoded}</td><td>${r.Is_WellKnown_Port}</td><td>${r.Packet_Entropy}</td>`;
      } else {
        html += `<td>${r.id}</td><td>${r.Scaled_Flow_Duration}</td><td>${r.Scaled_Fwd_Packets}</td><td>${r.Scaled_Entropy}</td><td>${r.SYN_to_ACK_Ratio}</td><td style="color: ${r.Outlier_Flag.includes('ANOMALOUS') ? '#ff3366' : '#00ff66'}; font-weight: 600;">${r.Outlier_Flag}</td>`;
      }
      html += `</tr>`;
    });

    html += `</tbody></table>`;
    tableContainer.innerHTML = html;
  }

  /**
   * Run Real-Time AI Detection Sandbox Form
   */
  runSandboxPrediction() {
    const srcIp = document.getElementById('sandbox-src-ip').value;
    const destIp = document.getElementById('sandbox-dest-ip').value;
    const destPort = parseInt(document.getElementById('sandbox-dest-port').value) || 80;
    const protocol = document.getElementById('sandbox-protocol').value;
    const fwdPackets = parseInt(document.getElementById('sandbox-fwd-pkts').value) || 10;
    const synCount = parseInt(document.getElementById('sandbox-syn-count').value) || 1;
    const duration = parseInt(document.getElementById('sandbox-duration').value) || 500;
    const payload = document.getElementById('sandbox-payload').value;

    const inputData = {
      Source_IP: srcIp,
      Dest_IP: destIp,
      Dest_Port: destPort,
      Protocol: protocol,
      Total_Fwd_Packets: fwdPackets,
      SYN_Flag_Count: synCount,
      Flow_Duration_ms: duration,
      Payload_Signature: payload
    };

    const pred = window.mlEngine.predict(inputData);

    // Update Result View
    document.getElementById('sandbox-result-prediction').textContent = pred.prediction;
    document.getElementById('sandbox-result-confidence').textContent = `${pred.confidence}%`;
    document.getElementById('sandbox-result-model').textContent = pred.modelUsed;

    const riskBadge = document.getElementById('sandbox-result-risk');
    if (riskBadge) {
      riskBadge.textContent = pred.riskLevel;
      riskBadge.className = `severity-badge ${pred.riskLevel === 'CRITICAL' ? 'severity-critical' : pred.riskLevel === 'HIGH' ? 'severity-high' : pred.riskLevel === 'MEDIUM' ? 'severity-medium' : 'severity-info'}`;
    }

    const cvssEl = document.getElementById('sandbox-result-cvss');
    if (cvssEl) {
      cvssEl.textContent = `Score ${pred.cvss.score} (${pred.cvss.vector})`;
    }

    // Render SHAP Feature Importance Bars
    const shapContainer = document.getElementById('sandbox-shap-container');
    if (shapContainer) {
      shapContainer.innerHTML = pred.shapBreakdown.map(s => `
        <div class="shap-feature-row">
          <div class="shap-label-row">
            <span>${s.feature}</span>
            <span style="color: ${s.isDanger ? 'var(--alert-red)' : 'var(--neon-cyan)'}; font-weight: 600;">${s.impact}</span>
          </div>
          <div class="shap-bar-track">
            <div class="shap-bar-fill ${s.isDanger ? 'danger' : ''}" style="width: ${parseInt(s.impact)}%"></div>
          </div>
        </div>
      `).join('');
    }

    // Play Audio FX
    if (pred.riskLevel === 'CRITICAL') {
      window.alertsService.playAlertSound('critical');
    } else {
      window.alertsService.playAlertSound('blip');
    }
  }

  /**
   * Bind DOM Events & Navigation Handlers
   */
  bindEvents() {
    // Navigation items
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        const href = item.getAttribute('href');
        if (href) {
          window.location.href = href;
          return;
        }
        e.preventDefault();
        const view = item.getAttribute('data-view');
        if (view) this.switchView(view);
      });
    });

    // DEFCON Buttons
    document.querySelectorAll('.defcon-select-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const level = parseInt(btn.getAttribute('data-level'));
        this.setDefcon(level);
      });
    });

    // Model Selector Pills
    document.querySelectorAll('.model-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        document.querySelectorAll('.model-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        const model = pill.getAttribute('data-model');
        window.mlEngine.setModel(model);
        window.alertsService.showToast('AI Model Switched', `Active model: ${window.mlEngine.getModelInfo().name}`, 'info');
      });
    });

    // Preprocessing Pipeline Stepper Clicks
    document.querySelectorAll('.pipeline-step').forEach(stepEl => {
      stepEl.addEventListener('click', () => {
        const stepNum = parseInt(stepEl.getAttribute('data-step'));
        window.datasetService.currentStep = stepNum;
        document.querySelectorAll('.pipeline-step').forEach(s => {
          const num = parseInt(s.getAttribute('data-step'));
          if (num < stepNum) {
            s.classList.add('completed');
            s.classList.remove('active');
          } else if (num === stepNum) {
            s.classList.add('active');
            s.classList.remove('completed');
          } else {
            s.classList.remove('active', 'completed');
          }
        });
        this.renderPreprocessingView();
      });
    });

    // Dataset Dropzone & File Input
    const dropzone = document.getElementById('dataset-dropzone');
    const fileInput = document.getElementById('dataset-file-input');

    if (dropzone && fileInput) {
      dropzone.onclick = () => fileInput.click();

      fileInput.onchange = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (event) => {
          try {
            const csvText = event.target.result;
            const newDs = window.datasetService.parseCSV(csvText);
            this.renderDatasetSelector();
            this.renderPreprocessingView();
            window.alertsService.showToast('Custom Dataset Ingested', `Successfully loaded ${newDs.recordsCount} rows from ${file.name}`, 'success');
          } catch (err) {
            window.alertsService.showToast('Upload Error', err.message, 'danger');
          }
        };
        reader.readAsText(file);
      };

      dropzone.ondragover = (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      };
      dropzone.ondragleave = () => dropzone.classList.remove('dragover');
      dropzone.ondrop = (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
          fileInput.files = e.dataTransfer.files;
          fileInput.dispatchEvent(new Event('change'));
        }
      };
    }

    // Threat Log Table Search & Filters
    const searchInput = document.getElementById('table-search-input');
    if (searchInput) {
      searchInput.oninput = (e) => {
        window.threatLogsService.searchQuery = e.target.value;
        window.threatLogsService.currentPage = 1;
        window.threatLogsService.renderTable();
      };
    }

    const sevFilter = document.getElementById('table-severity-filter');
    if (sevFilter) {
      sevFilter.onchange = (e) => {
        window.threatLogsService.filterSeverity = e.target.value;
        window.threatLogsService.currentPage = 1;
        window.threatLogsService.renderTable();
      };
    }

    const statFilter = document.getElementById('table-status-filter');
    if (statFilter) {
      statFilter.onchange = (e) => {
        window.threatLogsService.filterStatus = e.target.value;
        window.threatLogsService.currentPage = 1;
        window.threatLogsService.renderTable();
      };
    }

    // Pagination buttons
    const prevPageBtn = document.getElementById('log-prev-page');
    if (prevPageBtn) {
      prevPageBtn.onclick = () => {
        if (window.threatLogsService.currentPage > 1) {
          window.threatLogsService.currentPage--;
          window.threatLogsService.renderTable();
        }
      };
    }

    const nextPageBtn = document.getElementById('log-next-page');
    if (nextPageBtn) {
      nextPageBtn.onclick = () => {
        const total = window.threatLogsService.getPaginatedLogs().totalPages;
        if (window.threatLogsService.currentPage < total) {
          window.threatLogsService.currentPage++;
          window.threatLogsService.renderTable();
        }
      };
    }

    // Audio Mute Toggle
    const soundToggle = document.getElementById('header-sound-toggle');
    if (soundToggle) {
      soundToggle.onclick = () => {
        const enabled = window.alertsService.toggleSound();
        soundToggle.innerHTML = `<i class="fas ${enabled ? 'fa-volume-high' : 'fa-volume-xmark'}"></i>`;
        soundToggle.style.color = enabled ? 'var(--neon-cyan)' : 'var(--text-muted)';
      };
    }

    // Quick Login Role Selector
    document.querySelectorAll('.login-role-btn').forEach(btn => {
      btn.onclick = () => {
        const role = btn.getAttribute('data-role');
        const loginModal = document.getElementById('login-modal');
        if (loginModal) loginModal.classList.remove('active');
        window.authService.startLogin(role);
      };
    });
  }
}

// Instantiate and initialize on DOM content load
document.addEventListener('DOMContentLoaded', () => {
  window.app = new App();
  window.app.init();
});
