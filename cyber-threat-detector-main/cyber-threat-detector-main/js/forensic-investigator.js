/**
 * Forensic Investigator & Threat Deep Dive Service
 * Renders raw packet hexdumps, MITRE ATT&CK technique mapping, AI executive briefing, and containment actions.
 */

const DEFAULT_MITRE_DB = [
  {
    id: "T1498",
    name: "Network Denial of Service (DDoS)",
    tactic: "Impact",
    category: "DDoS Attack",
    severity: "CRITICAL",
    cvssBaseScore: 8.6,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
    description: "Adversaries perform network denial of service (DoS) attacks to degrade or block the availability of targeted services to legitimate users via volumetric traffic spikes.",
    mitigations: [
      "Deploy automated BGP flowspec rate-limiting on border routers",
      "Enable SYN proxy / TCP cookie validation at edge reverse proxies",
      "Engage cloud anti-DDoS scrubbing centers"
    ]
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application (SQLi)",
    tactic: "Initial Access",
    category: "SQL Injection",
    severity: "CRITICAL",
    cvssBaseScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "Adversaries exploit SQL syntax vulnerabilities in public web applications to extract, alter, or drop entire database structures and breach sensitive customer/admin records.",
    mitigations: [
      "Mandate parameterized SQL queries and prepared statements (ORM)",
      "Enforce strict input validation, sanitization, and Web Application Firewall (WAF) rule sets",
      "Apply principle of least privilege on database connection credentials"
    ]
  },
  {
    id: "T1059.007",
    name: "Command and Scripting Interpreter: JavaScript (XSS)",
    tactic: "Execution",
    category: "Cross-Site Scripting (XSS)",
    severity: "HIGH",
    cvssBaseScore: 7.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    description: "Adversaries inject malicious client-side JavaScript payloads to hijack active authentication sessions, steal cookies, and execute unauthorized actions in the victim's browser context.",
    mitigations: [
      "Implement strict Content Security Policy (CSP) headers with cryptographic nonces",
      "Context-aware HTML and JavaScript entity encoding on all reflected user input",
      "Set HttpOnly and SameSite=Strict flags on all session cookies"
    ]
  },
  {
    id: "T1071.001",
    name: "Application Layer Protocol: Web Protocols (C2 / Ransomware)",
    tactic: "Command and Control",
    category: "Ransomware / C2",
    severity: "CRITICAL",
    cvssBaseScore: 9.6,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    description: "Adversaries communicate using standard web application protocols (HTTP/HTTPS) or SMB lateral movement to bypass network monitoring and orchestrate ransomware payload deployment.",
    mitigations: [
      "Network micro-segmentation and strict outbound firewall filtering",
      "Endpoint Detection & Response (EDR) behavioral monitoring on process injection",
      "Block known malicious C2 IP and JA3/JA4 TLS fingerprint hashes"
    ]
  },
  {
    id: "T1110.001",
    name: "Brute Force: Password Guessing",
    tactic: "Credential Access",
    category: "Brute Force",
    severity: "HIGH",
    cvssBaseScore: 7.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    description: "Adversaries systematically guess passwords to obtain valid credentials for administrative access across SSH, RDP, or web authentication portals.",
    mitigations: [
      "Enforce mandatory Multi-Factor Authentication (MFA / FIDO2)",
      "Implement account lockout policies and IP-based exponential backoff rate limiting",
      "Deploy Fail2Ban or PAM rate-limit modules"
    ]
  },
  {
    id: "T1046",
    name: "Network Service Discovery (Port Scanning)",
    tactic: "Discovery",
    category: "Port Scanning",
    severity: "MEDIUM",
    cvssBaseScore: 5.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    description: "Adversaries enumerate open network ports and running services across target IP ranges to identify exploitable entry points and software versions.",
    mitigations: [
      "Disable unused services and ports on all public subnets",
      "Deploy Port Knocking or Honeypot decoy listeners",
      "Enforce strict ingress firewall rules (Stateful Packet Inspection)"
    ]
  }
];

class ForensicInvestigator {
  constructor() {
    this.mitreDb = DEFAULT_MITRE_DB;
    this.activeIncident = null;
    this.initMitreDb();
  }

  async initMitreDb() {
    try {
      const resp = await fetch('data/mitre-attack.json');
      if (resp.ok) {
        const data = await resp.json();
        if (data.techniques && data.techniques.length > 0) {
          this.mitreDb = data.techniques;
        }
      }
    } catch (e) {
      // Use pre-bundled constant DB
    }
  }

  generateHexdump(text) {
    if (!text) text = 'RAW_ETHERNET_FRAME_DUMP_NULL';
    const bytes = [];
    for (let i = 0; i < text.length; i++) {
      bytes.push(text.charCodeAt(i));
    }
    while (bytes.length < 64) {
      bytes.push(Math.floor(Math.random() * 256));
    }

    let output = 'OFFSET    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII\n';
    output += '----------------------------------------------------------------------\n';

    for (let offset = 0; offset < bytes.length; offset += 16) {
      const chunk = bytes.slice(offset, offset + 16);
      const hexOffset = offset.toString(16).padStart(4, '0').toUpperCase();
      
      const hexPart1 = chunk.slice(0, 8).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ').padEnd(23, ' ');
      const hexPart2 = chunk.slice(8, 16).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ').padEnd(23, ' ');
      const asciiPart = chunk.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');

      output += `0x${hexOffset}  ${hexPart1}  ${hexPart2}  |${asciiPart}|\n`;
    }

    return output;
  }

  openInvestigation(incidentId) {
    const incident = window.threatLogsService.logs.find(l => l.id === incidentId);
    if (!incident) return;

    this.activeIncident = incident;
    const modal = document.getElementById('investigation-modal');
    if (!modal) return;

    const mitre = this.mitreDb.find(m => m.category.toLowerCase().includes(incident.category.toLowerCase()) || incident.category.toLowerCase().includes(m.category.toLowerCase())) || this.mitreDb[0];

    document.getElementById('inv-incident-id').textContent = incident.id;
    document.getElementById('inv-timestamp').textContent = incident.timestamp;
    document.getElementById('inv-category').textContent = incident.category;
    document.getElementById('inv-attacker-ip').textContent = incident.sourceIp;
    document.getElementById('inv-target').textContent = `${incident.destIp}:${incident.destPort} (${incident.protocol})`;
    document.getElementById('inv-confidence').textContent = `${incident.confidence}%`;

    const statusEl = document.getElementById('inv-status');
    if (statusEl) {
      statusEl.textContent = incident.status;
      statusEl.className = `status-badge ${incident.status === 'New' ? 'status-new' : incident.status === 'Investigating' ? 'status-investigating' : 'status-contained'}`;
    }

    const sevEl = document.getElementById('inv-severity');
    if (sevEl) {
      sevEl.textContent = incident.riskLevel;
      sevEl.className = `severity-badge ${incident.riskLevel === 'CRITICAL' ? 'severity-critical' : incident.riskLevel === 'HIGH' ? 'severity-high' : 'severity-medium'}`;
    }

    const hexdumpEl = document.getElementById('inv-hexdump');
    if (hexdumpEl) {
      hexdumpEl.textContent = this.generateHexdump(incident.payloadSnippet || incident.category);
    }

    if (mitre) {
      document.getElementById('inv-mitre-id').textContent = mitre.id;
      document.getElementById('inv-mitre-name').textContent = mitre.name;
      document.getElementById('inv-mitre-tactic').textContent = mitre.tactic;
      document.getElementById('inv-mitre-desc').textContent = mitre.description;
      document.getElementById('inv-cvss-score').textContent = mitre.cvssBaseScore || '9.8';
      document.getElementById('inv-cvss-vector').textContent = mitre.cvssVector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

      const mitList = document.getElementById('inv-mitigations-list');
      if (mitList) {
        mitList.innerHTML = (mitre.mitigations || []).map(m => `<li><i class="fas fa-shield" style="color: var(--neon-cyan); margin-right: 6px;"></i>${m}</li>`).join('');
      }
    }

    const aiSummaryEl = document.getElementById('inv-ai-summary');
    if (aiSummaryEl) {
      aiSummaryEl.innerHTML = `
        <p style="margin-bottom: 8px; color: var(--text-primary); line-height: 1.5;">
          <strong>AI Executive Brief:</strong> Autonomous sensor detected an adversary targeting port <code>${incident.destPort}</code> from source IP <code>${incident.sourceIp}</code>. The observed signature strongly matches <em>${incident.category}</em> with an estimated AI model confidence of <strong>${incident.confidence}%</strong>.
        </p>
        <p style="color: var(--text-secondary); font-size: 0.82rem; margin-bottom: 8px;">
          <strong>Threat Intent:</strong> Unauthorized exploitation attempt aimed at bypassing network boundary controls to achieve persistence, exfiltration, or denial of service.
        </p>
        <div style="background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 4px; font-family: var(--font-mono); font-size: 0.72rem; color: var(--neon-cyan);">
          IOC Flagged: IP=${incident.sourceIp} | Tactic=${mitre ? mitre.tactic : 'Execution'} | Signature="${incident.payloadSnippet}"
        </div>
      `;
    }

    const isolateBtn = document.getElementById('inv-isolate-btn');
    if (isolateBtn) {
      isolateBtn.onclick = () => {
        window.alertsService.executeContainment('isolate_host', incident.sourceIp, incident.id);
        this.openInvestigation(incident.id);
      };
    }

    const blockBtn = document.getElementById('inv-block-btn');
    if (blockBtn) {
      blockBtn.onclick = () => {
        window.alertsService.executeContainment('block_ip', incident.sourceIp, incident.id);
        this.openInvestigation(incident.id);
      };
    }

    const copyScriptBtn = document.getElementById('inv-copy-script-btn');
    if (copyScriptBtn) {
      copyScriptBtn.onclick = () => {
        const script = window.alertsService.generateRemediationScript(incident.category, incident.sourceIp, incident.destPort);
        navigator.clipboard.writeText(script).then(() => {
          window.alertsService.showToast('Playbook Copied', 'Remediation Bash script copied to clipboard.', 'success');
        });
      };
    }

    modal.classList.add('active');
  }

  closeInvestigation() {
    const modal = document.getElementById('investigation-modal');
    if (modal) modal.classList.remove('active');
  }

  addAnalystNote(noteText) {
    if (!noteText || !this.activeIncident) return;
    const notesContainer = document.getElementById('inv-notes-history');
    if (notesContainer) {
      const user = window.authService.getCurrentUser();
      const div = document.createElement('div');
      div.style.cssText = 'background: rgba(255,255,255,0.03); border-left: 2px solid var(--neon-cyan); padding: 8px 12px; margin-bottom: 8px; border-radius: 4px; font-size: 0.8rem;';
      div.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-family: var(--font-mono); font-size: 0.68rem; color: var(--neon-cyan); margin-bottom: 4px;">
          <span>${user.name} (${user.title})</span>
          <span>${new Date().toLocaleTimeString()}</span>
        </div>
        <div style="color: var(--text-primary);">${noteText}</div>
      `;
      notesContainer.prepend(div);
    }
  }
}

window.forensicInvestigator = new ForensicInvestigator();
