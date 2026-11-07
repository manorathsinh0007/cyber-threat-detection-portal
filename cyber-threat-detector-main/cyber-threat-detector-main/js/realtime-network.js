/**
 * AEGIS Real-World Network & High-Level Backend Service
 * Manages WebSocket live streaming, active connection correlation,
 * real network adapter monitoring, port scanning, and active firewall defense.
 */

class RealTimeNetworkService {
  constructor() {
    this.ws = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.backendBaseUrl = this.determineBackendUrl();
    this.wsUrl = this.determineWsUrl();

    this.latestMetrics = null;
    this.activeConnections = [];
    this.networkInterfaces = [];
    this.selectedInterface = null;
    this.quarantinedIps = [];

    this.autoRefreshInterval = null;
  }

  determineBackendUrl() {
    // If running from FastAPI or web server on port 8000/3000
    if (window.location.protocol.startsWith('http')) {
      return `${window.location.protocol}//${window.location.host}`;
    }
    return 'http://localhost:8000';
  }

  determineWsUrl() {
    if (window.location.protocol === 'https:') {
      return `wss://${window.location.host}/ws/live-feed`;
    } else if (window.location.protocol === 'http:') {
      return `ws://${window.location.host}/ws/live-feed`;
    }
    return 'ws://localhost:8000/ws/live-feed';
  }

  init() {
    console.log('[*] Initializing AEGIS Real-World Network Service...');
    this.connectWebSocket();
    this.fetchInterfaces();
    this.fetchDefenseStatus();

    // Bind UI actions
    this.bindEvents();
  }

  /**
   * Connect WebSocket for bi-directional live telemetry
   */
  connectWebSocket() {
    try {
      console.log(`[*] Connecting to Real Network WebSocket: ${this.wsUrl}`);
      this.ws = new WebSocket(this.wsUrl);

      this.ws.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        console.log('[✓] Real Network Backend WebSocket Connected.');
        this.updateConnectionStatus(true);
        if (window.alertsService) {
          window.alertsService.showToast(
            'REAL NETWORK ONLINE',
            'Connected to high-level system network telemetry engine & socket sniffer.',
            'success'
          );
        }
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          this.handleWebSocketMessage(msg);
        } catch (e) {
          console.error('[!] Error parsing WebSocket message:', e);
        }
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        this.updateConnectionStatus(false);
        this.scheduleReconnect();
      };

      this.ws.onerror = (err) => {
        console.warn('[!] WebSocket connection failed or backend offline.', err);
        this.isConnected = false;
        this.updateConnectionStatus(false);
      };
    } catch (err) {
      console.warn('[!] WebSocket creation error:', err);
      this.updateConnectionStatus(false);
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = Math.min(2000 * Math.pow(1.5, this.reconnectAttempts), 15000);
      console.log(`[*] Retrying backend connection in ${Math.round(delay / 1000)}s (Attempt ${this.reconnectAttempts})...`);
      setTimeout(() => this.connectWebSocket(), delay);
    }
  }

  updateConnectionStatus(online) {
    const badge = document.getElementById('backend-status-pill');
    const navBadge = document.getElementById('backend-status-badge');
    const headerIndicator = document.getElementById('header-backend-indicator');

    if (badge) {
      if (online) {
        badge.innerHTML = `<span class="cyber-pulse-dot" style="background: var(--matrix-green); box-shadow: 0 0 10px var(--matrix-green);"></span> <span>REAL NETWORK: ACTIVE</span>`;
        badge.style.borderColor = 'rgba(0, 255, 136, 0.4)';
        badge.style.color = 'var(--matrix-green)';
      } else {
        badge.innerHTML = `<span class="cyber-pulse-dot" style="background: var(--warning-amber);"></span> <span>BACKEND STANDBY / LOCAL</span>`;
        badge.style.borderColor = 'rgba(255, 187, 0, 0.4)';
        badge.style.color = 'var(--warning-amber)';
      }
    }

    if (navBadge) {
      navBadge.textContent = online ? 'ONLINE' : 'STANDBY';
      navBadge.style.color = online ? 'var(--matrix-green)' : 'var(--warning-amber)';
      navBadge.style.borderColor = online ? 'var(--matrix-green)' : 'var(--warning-amber)';
    }

    if (headerIndicator) {
      headerIndicator.title = online ? 'Real-World Network Monitor Active' : 'Connecting to local backend...';
    }
  }

  handleWebSocketMessage(msg) {
    switch (msg.type) {
      case 'INITIAL_HANDSHAKE':
        this.handleInitialHandshake(msg);
        break;

      case 'TELEMETRY_UPDATE':
        this.handleTelemetryUpdate(msg);
        break;

      case 'PORT_SCAN_PROGRESS':
        this.handleScanProgress(msg.data);
        break;

      case 'DEFENSE_ACTION':
        this.handleDefenseBroadcast(msg);
        break;

      default:
        break;
    }
  }

  handleInitialHandshake(msg) {
    console.log('[*] Initial Handshake received:', msg);
    if (msg.metrics) {
      this.latestMetrics = msg.metrics;
      this.updateHudMetrics(msg.metrics);
    }
    if (msg.quarantined_ips) {
      this.quarantinedIps = msg.quarantined_ips;
      this.renderQuarantinedList();
    }
  }

  handleTelemetryUpdate(msg) {
    this.latestMetrics = msg.metrics;
    this.activeConnections = msg.active_connections_sample || [];

    // 1. Update Top Dashboard Metrics
    this.updateHudMetrics(msg.metrics);

    // 2. Render live connection stream in Real Network View
    this.renderActiveConnectionsTable(this.activeConnections);
    this.renderThroughputGauges(msg.metrics);

    // 3. Process new real threats
    if (msg.new_threats && msg.new_threats.length > 0) {
      msg.new_threats.forEach((threat) => {
        // Add to main SOC threat log
        if (window.threatLogsService) {
          window.threatLogsService.addIncident(threat);
        }

        // Add to dashboard live stream ticker
        if (window.app) {
          window.app.addLiveStreamItem(
            {
              Source_IP: threat.sourceIp,
              Dest_IP: threat.destIp,
              Dest_Port: threat.destPort,
              Protocol: threat.protocol,
              Payload_Signature: threat.payloadSnippet
            },
            {
              prediction: threat.category,
              riskLevel: threat.riskLevel,
              confidence: threat.confidence,
              modelUsed: threat.model
            }
          );
        }

        // Add point to 3D Attack Map if valid coordinates
        if (threat.rawPacket && threat.rawPacket.geo && threat.rawPacket.geo.lat && window.app && window.app.attackMap) {
          window.app.attackMap.addCustomAttackPoint({
            sourceIp: threat.sourceIp,
            destIp: threat.destIp,
            lat: threat.rawPacket.geo.lat,
            lon: threat.rawPacket.geo.lon,
            country: threat.rawPacket.geo.country,
            category: threat.category,
            riskLevel: threat.riskLevel
          });
        }

        // Show toast alert
        if (window.alertsService) {
          const toastType = threat.riskLevel === 'CRITICAL' ? 'danger' : 'warning';
          window.alertsService.showToast(
            `ALERT: ${threat.category}`,
            `${threat.reason} [${threat.sourceIp} -> ${threat.destIp}:${threat.destPort}]`,
            toastType
          );

          if (threat.riskLevel === 'CRITICAL') {
            window.alertsService.playAlertSound('critical');
          }
        }
      });
    }
  }

  updateHudMetrics(metrics) {
    if (!metrics) return;

    // HUD total packets
    const totalPktEl = document.getElementById('hud-total-packets');
    if (totalPktEl && metrics.total_packets !== undefined) {
      totalPktEl.textContent = metrics.total_packets.toLocaleString();
    }

    // Bandwidth Rate Elements in Real Network View
    const uploadEl = document.getElementById('real-net-upload-rate');
    const downloadEl = document.getElementById('real-net-download-rate');
    const activeConnsEl = document.getElementById('real-net-active-conns');
    const listeningPortsEl = document.getElementById('real-net-listening-ports');

    if (uploadEl) uploadEl.textContent = `${metrics.kb_sent_per_sec || 0} KB/s`;
    if (downloadEl) downloadEl.textContent = `${metrics.kb_recv_per_sec || 0} KB/s`;
    if (activeConnsEl) activeConnsEl.textContent = (metrics.active_connections_count || 0).toLocaleString();
    if (listeningPortsEl) listeningPortsEl.textContent = (metrics.listening_ports_count || 0).toLocaleString();
  }

  renderThroughputGauges(metrics) {
    const upProgress = document.getElementById('gauge-upload-bar');
    const downProgress = document.getElementById('gauge-download-bar');

    if (upProgress) {
      const pct = Math.min(((metrics.kb_sent_per_sec || 0) / 500) * 100, 100);
      upProgress.style.width = `${pct}%`;
    }
    if (downProgress) {
      const pct = Math.min(((metrics.kb_recv_per_sec || 0) / 2000) * 100, 100);
      downProgress.style.width = `${pct}%`;
    }
  }

  async fetchInterfaces() {
    try {
      const res = await fetch(`${this.backendBaseUrl}/api/network/interfaces`);
      if (res.ok) {
        const data = await res.json();
        this.networkInterfaces = data.interfaces || [];
        this.selectedInterface = data.selected;
        this.renderInterfacesSelector();
      }
    } catch (e) {
      console.warn('[!] Failed to fetch interfaces:', e);
    }
  }

  renderInterfacesSelector() {
    const container = document.getElementById('interfaces-grid-container');
    if (!container) return;

    container.innerHTML = '';
    this.networkInterfaces.forEach((iface) => {
      const card = document.createElement('div');
      card.className = `interface-card ${iface.is_active ? 'active-adapter' : ''}`;
      card.innerHTML = `
        <div class="interface-card-header">
          <div class="iface-title">
            <i class="fas ${iface.name.toLowerCase().includes('wi-fi') ? 'fa-wifi' : 'fa-ethernet'}"></i>
            <span class="iface-name font-mono">${iface.name}</span>
          </div>
          <span class="cyber-badge ${iface.is_up ? 'badge-primary' : 'badge-danger'}">
            ${iface.is_up ? 'UP' : 'DOWN'}
          </span>
        </div>
        <div class="iface-details font-mono">
          <div><span>IP:</span> <strong>${iface.ipv4}</strong></div>
          <div><span>MAC:</span> <strong>${iface.mac}</strong></div>
          <div><span>Sent/Recv:</span> <strong>${Math.round(iface.bytes_sent / 1024 / 1024)}MB / ${Math.round(iface.bytes_recv / 1024 / 1024)}MB</strong></div>
        </div>
        <button class="cyber-btn cyber-btn-sm ${iface.is_active ? 'cyber-btn-primary' : ''}" 
                onclick="window.realTimeNetwork.selectInterface('${iface.name}')" style="width: 100%; margin-top: 10px;">
          <i class="fas fa-check-circle"></i> ${iface.is_active ? 'Active Sniffing Adapter' : 'Select Interface'}
        </button>
      `;
      container.appendChild(card);
    });
  }

  async selectInterface(ifaceName) {
    try {
      const res = await fetch(`${this.backendBaseUrl}/api/network/interfaces/select`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface_name: ifaceName })
      });
      if (res.ok) {
        if (window.alertsService) {
          window.alertsService.showToast('ADAPTER SELECTED', `Monitoring switched to ${ifaceName}`, 'success');
        }
        await this.fetchInterfaces();
      }
    } catch (e) {
      console.error(e);
    }
  }

  renderActiveConnectionsTable(connections) {
    const tbody = document.getElementById('real-conns-table-body');
    if (!tbody) return;

    if (!connections || connections.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 20px;">Awaiting active connection telemetry...</td></tr>`;
      return;
    }

    tbody.innerHTML = '';
    connections.slice(0, 40).forEach((c) => {
      const tr = document.createElement('tr');
      const isExt = c.geo && c.geo.is_external;
      const geoText = isExt ? `${c.geo.city || ''}, ${c.geo.country || 'External'}` : 'Local Intranet';
      const statusClass = c.status === 'ESTABLISHED' ? 'status-connected' : c.status === 'LISTEN' ? 'status-listen' : 'status-waiting';

      tr.innerHTML = `
        <td class="font-mono">
          <div style="font-weight: 600; color: #fff;">${c.process_name}</div>
          <div style="font-size: 0.72rem; color: var(--text-secondary);">PID: ${c.pid}</div>
        </td>
        <td class="font-mono">${c.protocol}</td>
        <td class="font-mono">${c.local_ip}:${c.local_port}</td>
        <td class="font-mono">
          <span style="color: ${isExt ? 'var(--neon-cyan)' : 'var(--text-primary)'};">${c.remote_ip || '0.0.0.0'}:${c.remote_port}</span>
        </td>
        <td>
          <span class="cyber-badge" style="background: rgba(0, 229, 255, 0.1); color: var(--neon-cyan); font-size: 0.72rem;">
            ${geoText}
          </span>
        </td>
        <td>
          <span class="connection-status-pill ${statusClass}">${c.status}</span>
        </td>
        <td>
          <div style="display: flex; gap: 6px;">
            ${
              isExt && c.remote_ip
                ? `<button class="cyber-btn cyber-btn-xs cyber-btn-danger" title="Quarantine IP via Firewall" onclick="window.realTimeNetwork.blockIp('${c.remote_ip}', 'SOC Connection Block')">
                     <i class="fas fa-ban"></i> Block IP
                   </button>`
                : ''
            }
            ${
              c.pid > 0
                ? `<button class="cyber-btn cyber-btn-xs" style="color: var(--warning-amber); border-color: var(--warning-amber);" title="Isolate / Kill Process" onclick="window.realTimeNetwork.killProcess(${c.pid})">
                     <i class="fas fa-power-off"></i> Kill
                   </button>`
                : ''
            }
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  async blockIp(ip, reason = 'SOC Manual Containment') {
    if (!confirm(`Engage Active Defense: Block remote IP ${ip} via Windows Firewall & Quarantine?`)) return;

    try {
      const res = await fetch(`${this.backendBaseUrl}/api/defense/block-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason })
      });
      const data = await res.json();
      if (window.alertsService) {
        window.alertsService.showToast(
          'FIREWALL RULE ENGAGED',
          `Quarantined IP ${ip}. ${data.firewall_msg || ''}`,
          'danger'
        );
      }
      await this.fetchDefenseStatus();
    } catch (e) {
      console.error(e);
    }
  }

  async unblockIp(ip) {
    try {
      const res = await fetch(`${this.backendBaseUrl}/api/defense/unblock-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      if (res.ok) {
        if (window.alertsService) {
          window.alertsService.showToast('QUARANTINE LIFTED', `IP ${ip} restored to traffic pool.`, 'info');
        }
        await this.fetchDefenseStatus();
      }
    } catch (e) {
      console.error(e);
    }
  }

  async killProcess(pid) {
    if (!confirm(`Terminate rogue process PID ${pid}?`)) return;

    try {
      const res = await fetch(`${this.backendBaseUrl}/api/defense/isolate-process`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid, reason: 'Rogue Socket Containment' })
      });
      const data = await res.json();
      if (data.status === 'SUCCESS') {
        if (window.alertsService) {
          window.alertsService.showToast('PROCESS TERMINATED', `Process PID ${pid} safely neutralized.`, 'success');
        }
      } else {
        alert(data.message || 'Error isolating process');
      }
    } catch (e) {
      console.error(e);
    }
  }

  async fetchDefenseStatus() {
    try {
      const res = await fetch(`${this.backendBaseUrl}/api/defense/status`);
      if (res.ok) {
        const data = await res.json();
        this.quarantinedIps = data.active_quarantined_ips || [];
        this.renderQuarantinedList();
      }
    } catch (e) {
      console.warn('[!] Failed to fetch defense status:', e);
    }
  }

  renderQuarantinedList() {
    const container = document.getElementById('quarantined-ips-list');
    if (!container) return;

    if (this.quarantinedIps.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-secondary); padding: 15px;">No active IP quarantines. System perimeter clear.</div>`;
      return;
    }

    container.innerHTML = '';
    this.quarantinedIps.forEach((q) => {
      const item = document.createElement('div');
      item.className = 'quarantine-item';
      item.innerHTML = `
        <div class="quarantine-meta font-mono">
          <div style="font-weight: 700; color: var(--alert-red);"><i class="fas fa-ban"></i> ${q.ip}</div>
          <div style="font-size: 0.75rem; color: var(--text-secondary);">${q.reason} • ${q.timestamp}</div>
          <div style="font-size: 0.72rem; color: var(--neon-cyan);">${q.firewall_msg || ''}</div>
        </div>
        <button class="cyber-btn cyber-btn-xs" onclick="window.realTimeNetwork.unblockIp('${q.ip}')">
          <i class="fas fa-trash-can"></i> Unblock
        </button>
      `;
      container.appendChild(item);
    });
  }

  /**
   * Active Network Port Scanner Trigger
   */
  async startPortScan(targetHost) {
    const target = targetHost || document.getElementById('port-scan-target-input')?.value || '127.0.0.1';
    const scanStatus = document.getElementById('port-scan-status-text');
    const scanProgress = document.getElementById('port-scan-progress-bar');
    const scanResultsTable = document.getElementById('port-scan-results-body');

    if (scanStatus) scanStatus.textContent = `Probing target ${target} across enterprise ports...`;
    if (scanProgress) scanProgress.style.width = '5%';
    if (scanResultsTable) scanResultsTable.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:15px;">Scanning sockets...</td></tr>`;

    try {
      const res = await fetch(`${this.backendBaseUrl}/api/scanner/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
      });
      const data = await res.json();
      if (scanStatus) {
        scanStatus.textContent = `Scan Complete for ${target}. Found ${data.open_ports_count} open service ports in ${data.elapsed_seconds}s.`;
      }
      if (scanProgress) scanProgress.style.width = '100%';
      this.renderScanResults(data.open_ports);

      if (window.alertsService) {
        window.alertsService.showToast(
          'RECONNAISSANCE SCAN FINISHED',
          `Target: ${target} - Open Ports: ${data.open_ports_count}`,
          'info'
        );
      }
    } catch (e) {
      if (scanStatus) scanStatus.textContent = `Scan Error: ${e.message}`;
    }
  }

  handleScanProgress(data) {
    const scanProgress = document.getElementById('port-scan-progress-bar');
    const scanStatus = document.getElementById('port-scan-status-text');

    if (scanProgress) scanProgress.style.width = `${data.progress_percent}%`;
    if (scanStatus) scanStatus.textContent = `Probing ${data.target_ip} (${data.ports_scanned}/${data.total_ports} ports - ${data.progress_percent}%)`;
  }

  renderScanResults(openPorts) {
    const tbody = document.getElementById('port-scan-results-body');
    if (!tbody) return;

    if (!openPorts || openPorts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--matrix-green); padding: 20px;">No open ports identified. Target host appears hardened or filtered.</td></tr>`;
      return;
    }

    tbody.innerHTML = '';
    openPorts.forEach((p) => {
      const tr = document.createElement('tr');
      const badgeClass = p.risk_level === 'CRITICAL' ? 'badge-danger' : p.risk_level === 'HIGH' ? 'badge-warning' : 'badge-primary';
      tr.innerHTML = `
        <td class="font-mono" style="font-weight: 700; color: #fff;">${p.port} / ${p.protocol}</td>
        <td class="font-mono">${p.service}</td>
        <td class="font-mono" style="font-size: 0.78rem; color: var(--neon-cyan); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${p.banner || 'None'}
        </td>
        <td>
          <span class="cyber-badge ${badgeClass}">${p.risk_level}</span>
        </td>
        <td style="font-size: 0.8rem; color: var(--text-secondary);">${p.recommendation}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  /**
   * Run real attack simulation test against backend
   */
  async triggerAttackSimulation(attackType) {
    if (window.alertsService) {
      window.alertsService.showToast('FIRING NETWORK PROBE', `Executing real ${attackType} test...`, 'warning');
    }

    try {
      const res = await fetch(`${this.backendBaseUrl}/api/simulation/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: attackType, target_ip: '127.0.0.1' })
      });
      const data = await res.json();
      console.log('[*] Attack Simulation executed:', data);

      const outputEl = document.getElementById('simulation-output-box');
      if (outputEl) {
        outputEl.textContent = JSON.stringify(data, null, 2);
      }
    } catch (e) {
      console.error(e);
    }
  }

  bindEvents() {
    // Port Scanner button
    const scanBtn = document.getElementById('start-port-scan-btn');
    if (scanBtn) {
      scanBtn.addEventListener('click', () => this.startPortScan());
    }

    // Simulation buttons
    const simPortScanBtn = document.getElementById('sim-port-scan-btn');
    if (simPortScanBtn) {
      simPortScanBtn.addEventListener('click', () => this.triggerAttackSimulation('PORT_SCAN'));
    }

    const simC2Btn = document.getElementById('sim-c2-beacon-btn');
    if (simC2Btn) {
      simC2Btn.addEventListener('click', () => this.triggerAttackSimulation('C2_BEACON'));
    }

    const simSynBtn = document.getElementById('sim-syn-flood-btn');
    if (simSynBtn) {
      simSynBtn.addEventListener('click', () => this.triggerAttackSimulation('SYN_FLOOD'));
    }

    // Export logs button
    const exportBtn = document.getElementById('export-audit-logs-btn');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        window.open(`${this.backendBaseUrl}/api/export/logs`, '_blank');
      });
    }
  }
}

// Global singleton instance
window.realTimeNetwork = new RealTimeNetworkService();
