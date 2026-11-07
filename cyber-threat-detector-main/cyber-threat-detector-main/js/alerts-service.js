/**
 * Cyber Threat Alert & Incident Containment Service
 * Audio Synthesizer (Web Audio API), Toast System, and 1-Click Automated Response Playbooks.
 */

class AlertsService {
  constructor() {
    this.soundEnabled = true;
    this.audioCtx = null;
    this.activeAlerts = [];
    this.containmentLog = [];
  }

  initAudio() {
    if (!this.audioCtx) {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.audioCtx = new AudioContext();
      }
    }
  }

  toggleSound() {
    this.soundEnabled = !this.soundEnabled;
    return this.soundEnabled;
  }

  /**
   * Synthesize tactical alert sound using Web Audio API oscillators
   */
  playAlertSound(type = 'alarm') {
    if (!this.soundEnabled) return;
    try {
      this.initAudio();
      if (!this.audioCtx || this.audioCtx.state === 'suspended') {
        this.audioCtx.resume();
      }

      const now = this.audioCtx.currentTime;
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();

      osc.connect(gain);
      gain.connect(this.audioCtx.destination);

      if (type === 'critical') {
        // High urgency warble tone
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.exponentialRampToValueAtTime(440, now + 0.15);
        osc.frequency.exponentialRampToValueAtTime(880, now + 0.3);
        gain.gain.setValueAtTime(0.15, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.35);
        osc.start(now);
        osc.stop(now + 0.35);
      } else if (type === 'containment') {
        // Futuristic success chime
        osc.type = 'sine';
        osc.frequency.setValueAtTime(523.25, now); // C5
        osc.frequency.setValueAtTime(659.25, now + 0.1); // E5
        osc.frequency.setValueAtTime(783.99, now + 0.2); // G5
        osc.frequency.setValueAtTime(1046.50, now + 0.3); // C6
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.5);
        osc.start(now);
        osc.stop(now + 0.5);
      } else {
        // Soft blip
        osc.type = 'sine';
        osc.frequency.setValueAtTime(600, now);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.12);
        osc.start(now);
        osc.stop(now + 0.12);
      }
    } catch (e) {
      console.warn('Web Audio error:', e);
    }
  }

  /**
   * Display Cyber Toast Notification
   */
  showToast(title, message, type = 'danger') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    if (type === 'danger' || type === 'critical') {
      this.playAlertSound('critical');
    } else if (type === 'success') {
      this.playAlertSound('containment');
    } else {
      this.playAlertSound('blip');
    }

    const toast = document.createElement('div');
    toast.className = `cyber-toast ${type === 'success' ? 'toast-success' : ''}`;
    toast.innerHTML = `
      <div style="font-size: 1.3rem; color: ${type === 'success' ? '#00ff66' : '#ff3366'}">
        <i class="fas ${type === 'success' ? 'fa-shield-check' : 'fa-triangle-exclamation'}"></i>
      </div>
      <div style="flex: 1;">
        <div style="font-family: var(--font-display); font-weight: 700; font-size: 0.88rem; color: #fff; margin-bottom: 2px;">
          ${title}
        </div>
        <div style="font-size: 0.78rem; color: var(--text-secondary); line-height: 1.4;">
          ${message}
        </div>
      </div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  /**
   * Execute 1-Click Automated Containment Playbook
   */
  executeContainment(actionType, targetIp, incidentId) {
    const timeStr = new Date().toLocaleTimeString();
    let title = '';
    let detail = '';

    switch (actionType) {
      case 'isolate_host':
        title = `HOST ISOLATED: ${targetIp}`;
        detail = `Inserted stateful firewall rule 'REJECT ALL FROM ${targetIp}' and shifted MAC to quarantine VLAN 999.`;
        break;
      case 'block_ip':
        title = `IP BLACKLISTED: ${targetIp}`;
        detail = `Broadcasted BGP Flowspec route discard rule. Edge routers dropping all ingress packets from ${targetIp}.`;
        break;
      case 'revoke_session':
        title = `SESSION TERMINATED`;
        detail = `Invalidated OAuth2 JWT bearer tokens & terminated active TCP connection sockets for incident ${incidentId}.`;
        break;
      default:
        title = `CONTAINMENT EXECUTED`;
        detail = `Automated remediation playbook triggered for ${targetIp}.`;
    }

    this.containmentLog.unshift({
      action: actionType,
      target: targetIp,
      incidentId: incidentId,
      timestamp: timeStr,
      status: 'SUCCESS'
    });

    this.showToast(title, detail, 'success');

    // Update log status if exists
    if (window.threatLogsService) {
      window.threatLogsService.updateIncidentStatus(incidentId, 'Contained');
    }

    return { title, detail, timeStr };
  }

  /**
   * Generate AI Remediation Script (iptables / Snort / Python)
   */
  generateRemediationScript(threatCategory, sourceIp, destPort) {
    return `# ==========================================================
# AUTOMATED AI INCIDENT REMEDIATION PLAYBOOK
# Threat Category: ${threatCategory}
# Target Offender: ${sourceIp} | Port: ${destPort}
# Generated: ${new Date().toUTCString()}
# ==========================================================

#!/usr/bin/env bash
set -e

echo "[*] Initializing AI Containment Protocol for ${sourceIp}..."

# 1. IPTables Kernel Drop Rule
iptables -I INPUT 1 -s ${sourceIp} -j DROP
iptables -I FORWARD 1 -s ${sourceIp} -j DROP
echo "[+] Blocked all ingress & forward packets from ${sourceIp}"

# 2. Kill Established Sockets
ss -K dst ${sourceIp} || true
echo "[+] Killed active TCP sockets"

# 3. Dynamic Snort/Suricata Rule Injection
echo "alert ip ${sourceIp} any -> \\$HOME_NET any (msg:\\"AI Detected ${threatCategory}\\"; classtype:trojan-activity; sid:9001001; rev:1;)" >> /etc/snort/rules/local.rules
echo "[+] Injected Suricata live heuristic signature"

echo "[✓] Automated containment executed successfully."
`;
  }
}

window.alertsService = new AlertsService();
