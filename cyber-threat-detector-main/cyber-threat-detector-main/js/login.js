/**
 * AEGIS SOC Login Portal - Logic & Interactive Canvas Controller
 * Manages holographic particle canvas, credential validation, role selection, 
 * 2FA/Biometric simulation, and audio synthesis.
 */

class LoginController {
  constructor() {
    this.selectedRole = 'analyst';
    this.activeUser = null;
    this.audioCtx = null;
    this.audioEnabled = true;
    this.canvas = null;
    this.ctx = null;
    this.particles = [];
    this.mouse = { x: null, y: null, radius: 140 };
  }

  init() {
    console.log('[*] Initializing AEGIS Cyber Defense Command Login Terminal...');

    this.initCanvas();
    this.bindEvents();
    this.loadSavedIdentity();
    this.initAudio();
  }

  /* ==========================================================================
     Web Audio API Cyber FX Generator (Zero external dependencies)
     ========================================================================== */
  initAudio() {
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.audioCtx = new AudioContext();
      }
    } catch (e) {
      console.warn('Web Audio not supported');
    }
  }

  playSound(type) {
    if (!this.audioEnabled || !this.audioCtx) return;
    if (this.audioCtx.state === 'suspended') {
      this.audioCtx.resume();
    }

    const now = this.audioCtx.currentTime;
    const osc = this.audioCtx.createOscillator();
    const gain = this.audioCtx.createGain();
    osc.connect(gain);
    gain.connect(this.audioCtx.destination);

    if (type === 'click') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(800, now);
      osc.frequency.exponentialRampToValueAtTime(400, now + 0.05);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.05);
      osc.start(now);
      osc.stop(now + 0.05);
    } else if (type === 'error') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(220, now);
      osc.frequency.setValueAtTime(180, now + 0.08);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.2);
      osc.start(now);
      osc.stop(now + 0.2);
    } else if (type === 'success') {
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.exponentialRampToValueAtTime(880, now + 0.12);
      osc.frequency.exponentialRampToValueAtTime(1320, now + 0.25);
      gain.gain.setValueAtTime(0.15, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.4);
      osc.start(now);
      osc.stop(now + 0.4);
    } else if (type === 'scan') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(600, now);
      osc.frequency.linearRampToValueAtTime(1200, now + 0.15);
      gain.gain.setValueAtTime(0.06, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.15);
      osc.start(now);
      osc.stop(now + 0.15);
    }
  }

  /* ==========================================================================
     Interactive Holographic Cyber Canvas
     ========================================================================== */
  initCanvas() {
    this.canvas = document.getElementById('cyber-canvas');
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');

    const resize = () => {
      this.canvas.width = window.innerWidth;
      this.canvas.height = window.innerHeight;
      this.createParticles();
    };

    window.addEventListener('resize', resize);
    window.addEventListener('mousemove', (e) => {
      this.mouse.x = e.x;
      this.mouse.y = e.y;
    });
    window.addEventListener('mouseout', () => {
      this.mouse.x = null;
      this.mouse.y = null;
    });

    resize();
    this.animateCanvas();
  }

  createParticles() {
    this.particles = [];
    const count = Math.min(Math.floor((this.canvas.width * this.canvas.height) / 14000), 100);

    for (let i = 0; i < count; i++) {
      this.particles.push({
        x: Math.random() * this.canvas.width,
        y: Math.random() * this.canvas.height,
        vx: (Math.random() - 0.5) * 0.8,
        vy: (Math.random() - 0.5) * 0.8,
        size: Math.random() * 2 + 1,
        color: Math.random() > 0.3 ? 'rgba(0, 255, 204, ' : 'rgba(0, 168, 255, '
      });
    }
  }

  animateCanvas() {
    requestAnimationFrame(() => this.animateCanvas());
    if (!this.ctx) return;

    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    for (let i = 0; i < this.particles.length; i++) {
      const p = this.particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > this.canvas.width) p.vx = -p.vx;
      if (p.y < 0 || p.y > this.canvas.height) p.vy = -p.vy;

      // Mouse interaction
      if (this.mouse.x !== null) {
        const dx = this.mouse.x - p.x;
        const dy = this.mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < this.mouse.radius) {
          const force = (this.mouse.radius - dist) / this.mouse.radius;
          p.x -= (dx / dist) * force * 2;
          p.y -= (dy / dist) * force * 2;
        }
      }

      // Draw particle
      this.ctx.beginPath();
      this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      this.ctx.fillStyle = p.color + '0.7)';
      this.ctx.shadowBlur = 8;
      this.ctx.shadowColor = 'rgba(0, 255, 204, 0.5)';
      this.ctx.fill();

      // Connect nearby particles
      for (let j = i + 1; j < this.particles.length; j++) {
        const p2 = this.particles[j];
        const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
        if (dist < 110) {
          this.ctx.beginPath();
          this.ctx.moveTo(p.x, p.y);
          this.ctx.lineTo(p2.x, p2.y);
          this.ctx.strokeStyle = `rgba(0, 255, 204, ${0.18 * (1 - dist / 110)})`;
          this.ctx.lineWidth = 0.8;
          this.ctx.shadowBlur = 0;
          this.ctx.stroke();
        }
      }
    }
  }

  /* ==========================================================================
     Event Handlers & Form Validation
     ========================================================================== */
  bindEvents() {
    // Tabs switching
    const tabCredentials = document.getElementById('tab-btn-credentials');
    const tabQuickRoles = document.getElementById('tab-btn-quick-roles');
    const tabFingerprint = document.getElementById('tab-btn-fingerprint');
    const viewCredentials = document.getElementById('view-credentials');
    const viewQuickRoles = document.getElementById('view-quick-roles');
    const viewFingerprint = document.getElementById('view-fingerprint');

    const switchTab = (activeTab, activeView) => {
      this.playSound('click');
      [tabCredentials, tabQuickRoles, tabFingerprint].forEach(t => t && t.classList.remove('active'));
      [viewCredentials, viewQuickRoles, viewFingerprint].forEach(v => v && (v.style.display = 'none'));
      if (activeTab) activeTab.classList.add('active');
      if (activeView) activeView.style.display = 'block';
      this.hideAlert();
    };

    if (tabCredentials) tabCredentials.onclick = () => switchTab(tabCredentials, viewCredentials);
    if (tabQuickRoles) tabQuickRoles.onclick = () => switchTab(tabQuickRoles, viewQuickRoles);
    if (tabFingerprint) tabFingerprint.onclick = () => switchTab(tabFingerprint, viewFingerprint);

    // Quick Fingerprint CTA on Credentials Tab
    const ctaFingerprint = document.getElementById('cta-quick-fingerprint');
    if (ctaFingerprint) {
      ctaFingerprint.onclick = () => {
        switchTab(tabFingerprint, viewFingerprint);
        // Automatically trigger scan for convenience
        setTimeout(() => this.startBiometricAuth(false), 300);
      };
    }

    // Biometric Scanner Pad & Buttons
    const sensorPad = document.getElementById('fingerprint-sensor-pad');
    const scanNowBtn = document.getElementById('bio-scan-now-btn');
    const hardwareWebAuthnBtn = document.getElementById('bio-hardware-webauthn-btn');

    if (sensorPad) {
      sensorPad.onclick = () => this.startBiometricAuth(false);
    }
    if (scanNowBtn) {
      scanNowBtn.onclick = () => this.startBiometricAuth(false);
    }
    if (hardwareWebAuthnBtn) {
      hardwareWebAuthnBtn.onclick = () => this.startBiometricAuth(true);
    }

    // Step 2 2FA screen Biometric Touch Target
    const step2BioTarget = document.getElementById('step2-biometric-touch-target');
    if (step2BioTarget) {
      step2BioTarget.onclick = () => {
        this.playSound('click');
        const user = this.activeUser || window.authService.roles.analyst;
        if (window.biometricAuthService) {
          window.biometricAuthService.playBiometricSound('start');
          step2BioTarget.style.borderColor = 'var(--neon-cyan)';
          step2BioTarget.style.boxShadow = '0 0 30px rgba(0, 255, 204, 0.4)';
          setTimeout(() => {
            window.biometricAuthService.playBiometricSound('granted');
            step2BioTarget.style.borderColor = 'var(--matrix-green)';
            step2BioTarget.style.boxShadow = '0 0 30px rgba(0, 255, 102, 0.6)';
            setTimeout(() => {
              this.handleMfaSubmit(true);
            }, 400);
          }, 600);
        } else {
          this.handleMfaSubmit(true);
        }
      };
    }

    // Biometric Enrollment toggle & save
    const toggleEnrollLink = document.getElementById('toggle-enroll-link');
    const enrollPanel = document.getElementById('enroll-biometric-panel');
    if (toggleEnrollLink && enrollPanel) {
      toggleEnrollLink.onclick = (e) => {
        e.preventDefault();
        const isHidden = enrollPanel.style.display === 'none';
        enrollPanel.style.display = isHidden ? 'block' : 'none';
        this.playSound('click');
      };
    }

    const saveEnrollBtn = document.getElementById('save-enrollment-btn');
    if (saveEnrollBtn) {
      saveEnrollBtn.onclick = () => this.handleSaveBiometricEnrollment();
    }

    // Check for saved enrolled biometric profile on load
    this.checkEnrolledBiometric();

    // Password toggle
    const togglePassBtn = document.getElementById('toggle-password-btn');
    const passInput = document.getElementById('login-password');
    if (togglePassBtn && passInput) {
      togglePassBtn.onclick = () => {
        const isPass = passInput.type === 'password';
        passInput.type = isPass ? 'text' : 'password';
        togglePassBtn.innerHTML = `<i class="fas ${isPass ? 'fa-eye-slash' : 'fa-eye'}"></i>`;
        this.playSound('click');
      };
    }

    // Password strength meter
    if (passInput) {
      passInput.addEventListener('input', () => {
        this.updateStrengthMeter(passInput.value);
      });
    }

    // Clearance level select sync
    const clearanceSelect = document.getElementById('login-clearance-role');
    if (clearanceSelect) {
      clearanceSelect.onchange = (e) => {
        this.selectedRole = e.target.value;
        this.playSound('click');
      };
    }

    // Credential form submission
    const loginForm = document.getElementById('operator-login-form');
    if (loginForm) {
      loginForm.onsubmit = (e) => {
        e.preventDefault();
        this.handleCredentialSubmit();
      };
    }

    // Quick role cards click
    document.querySelectorAll('.quick-role-card').forEach(card => {
      card.onclick = () => {
        const role = card.getAttribute('data-role');
        this.playSound('click');
        this.handleQuickRoleSelect(role);
      };
    });

    // 2FA Verification Form
    const mfaForm = document.getElementById('mfa-verify-form');
    if (mfaForm) {
      mfaForm.onsubmit = (e) => {
        e.preventDefault();
        this.handleMfaSubmit();
      };
    }

    // Regenerate Token link
    const regenBtn = document.getElementById('mfa-regen-btn');
    if (regenBtn) {
      regenBtn.onclick = (e) => {
        e.preventDefault();
        this.generateNewOtp();
      };
    }

    // Back from 2FA to credentials
    const backBtn = document.getElementById('mfa-back-btn');
    if (backBtn) {
      backBtn.onclick = () => {
        this.playSound('click');
        document.getElementById('step-2fa-verification').style.display = 'none';
        document.getElementById('step-initial-auth').style.display = 'block';
        this.hideAlert();
      };
    }
  }

  /* ==========================================================================
     Biometric Fingerprint Authentication Handlers
     ========================================================================== */
  async startBiometricAuth(useHardware = false) {
    if (!window.biometricAuthService) {
      this.showAlert('Biometric authentication service offline.');
      return;
    }

    const sensorPad = document.getElementById('fingerprint-sensor-pad');
    const titleEl = document.getElementById('bio-status-title');
    const subEl = document.getElementById('bio-status-sub');
    const minutiaeEl = document.getElementById('bio-minutiae-val');
    const livenessEl = document.getElementById('bio-liveness-val');
    const fidelityEl = document.getElementById('bio-fidelity-val');
    const operatorSelect = document.getElementById('bio-target-operator');

    let targetRole = operatorSelect ? operatorSelect.value : 'analyst';
    let targetUser = window.authService.roles[targetRole] || window.authService.roles.analyst;

    // Check if enrolled user was selected
    const enrolled = window.biometricAuthService.getEnrolledProfile();
    if (targetRole === 'enrolled' && enrolled) {
      targetUser = enrolled;
    }

    this.activeUser = targetUser;
    if (sensorPad) {
      sensorPad.classList.remove('verified');
      sensorPad.classList.add('scanning');
    }

    try {
      const result = await window.biometricAuthService.scanFingerprint(
        targetUser,
        (progress) => {
          if (titleEl) titleEl.textContent = progress.label;
          if (subEl) subEl.innerHTML = progress.subtext;
          if (progress.stage === 'SCANNING') {
            if (minutiaeEl) minutiaeEl.textContent = '42 RIDGES';
            if (livenessEl) livenessEl.textContent = 'CHECKING';
            if (fidelityEl) fidelityEl.textContent = `${progress.pct}%`;
          } else if (progress.stage === 'ANALYSIS') {
            if (minutiaeEl) minutiaeEl.textContent = '164 PTS';
            if (livenessEl) livenessEl.textContent = 'PASS 99.8%';
            if (fidelityEl) fidelityEl.textContent = `${progress.pct}%`;
          } else if (progress.stage === 'SUCCESS') {
            if (fidelityEl) fidelityEl.textContent = '99.8%';
          }
        },
        useHardware
      );

      if (result.success) {
        if (sensorPad) {
          sensorPad.classList.remove('scanning');
          sensorPad.classList.add('verified');
        }

        // Biometric satisfies 2FA directly -> transition straight to Access Granted HUD
        setTimeout(() => {
          document.getElementById('step-initial-auth').style.display = 'none';
          const successHud = document.getElementById('auth-success-hud');
          if (successHud) successHud.classList.add('active');

          setTimeout(() => {
            window.location.href = 'index.html';
          }, 1100);
        }, 500);
      }
    } catch (err) {
      console.error('[!] Biometric scan error:', err);
      if (sensorPad) sensorPad.classList.remove('scanning');
      this.showAlert('Biometric validation interrupted. Please try again.');
    }
  }

  handleSaveBiometricEnrollment() {
    const nameInput = document.getElementById('enroll-name-input');
    const userInput = document.getElementById('enroll-username-input');
    const roleSelect = document.getElementById('enroll-role-select');

    const name = (nameInput ? nameInput.value : '').trim();
    const username = (userInput ? userInput.value : '').trim();
    const roleId = roleSelect ? roleSelect.value : 'analyst';

    if (!name || !username) {
      this.showAlert('Please provide both Full Name and Username for biometric enrollment.');
      return;
    }

    const baseRole = window.authService.roles[roleId] || window.authService.roles.analyst;
    const profile = {
      ...baseRole,
      id: 'enrolled',
      username: username,
      name: name,
      avatarText: name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase() || 'OP',
      biometricEnrolledAt: new Date().toISOString()
    };

    if (window.biometricAuthService.saveEnrolledProfile(profile)) {
      this.playSound('success');
      this.checkEnrolledBiometric();
      document.getElementById('enroll-biometric-panel').style.display = 'none';
      const titleEl = document.getElementById('bio-status-title');
      if (titleEl) titleEl.textContent = `ENROLLED: ${name.toUpperCase()}`;
    }
  }

  checkEnrolledBiometric() {
    if (!window.biometricAuthService) return;
    const enrolled = window.biometricAuthService.getEnrolledProfile();
    const select = document.getElementById('bio-target-operator');
    if (enrolled && select) {
      let option = select.querySelector('option[value="enrolled"]');
      if (!option) {
        option = document.createElement('option');
        option.value = 'enrolled';
        select.prepend(option);
      }
      option.textContent = `★ ${enrolled.name} &bull; Enrolled Biometric (${enrolled.title})`;
      option.selected = true;
    }
  }

  updateStrengthMeter(val) {
    const s1 = document.getElementById('strength-1');
    const s2 = document.getElementById('strength-2');
    const s3 = document.getElementById('strength-3');
    if (!s1 || !s2 || !s3) return;

    s1.className = 'strength-step';
    s2.className = 'strength-step';
    s3.className = 'strength-step';

    if (val.length >= 4) s1.className = 'strength-step active-1';
    if (val.length >= 7 && (/\d/.test(val) || /[!@#$%^&*]/.test(val))) s2.className = 'strength-step active-2';
    if (val.length >= 10 && (/[A-Z]/.test(val) && /\d/.test(val) && /[!@#$%^&*]/.test(val))) s3.className = 'strength-step active-3';
  }

  showAlert(msg) {
    const alertBox = document.getElementById('auth-alert-banner');
    const alertMsg = document.getElementById('auth-alert-text');
    if (alertBox && alertMsg) {
      alertMsg.textContent = msg;
      alertBox.classList.add('active');
      this.playSound('error');
    }
  }

  hideAlert() {
    const alertBox = document.getElementById('auth-alert-banner');
    if (alertBox) alertBox.classList.remove('active');
  }

  loadSavedIdentity() {
    const savedUser = localStorage.getItem('cyber_saved_username');
    if (savedUser) {
      const usernameInput = document.getElementById('login-username');
      const rememberCheckbox = document.getElementById('remember-identity');
      if (usernameInput) usernameInput.value = savedUser;
      if (rememberCheckbox) rememberCheckbox.checked = true;
    }
  }

  handleCredentialSubmit() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const remember = document.getElementById('remember-identity').checked;
    const roleSelect = document.getElementById('login-clearance-role');
    const selectedRole = roleSelect ? roleSelect.value : 'analyst';

    if (!window.authService) {
      this.showAlert('Authentication service offline.');
      return;
    }

    const verification = window.authService.verifyCredentials(username, password, selectedRole);
    if (!verification.success) {
      this.showAlert(verification.message);
      return;
    }

    // Save or clear username based on remember checkbox
    if (remember) {
      localStorage.setItem('cyber_saved_username', username.trim());
    } else {
      localStorage.removeItem('cyber_saved_username');
    }

    this.activeUser = verification.user;
    this.transitionTo2FA();
  }

  handleQuickRoleSelect(roleKey) {
    if (!window.authService) return;
    const user = window.authService.roles[roleKey] || window.authService.roles.analyst;
    this.activeUser = user;
    this.transitionTo2FA();
  }

  generateNewOtp() {
    const otpInput = document.getElementById('login-otp-input');
    if (otpInput) {
      const code = Math.floor(100000 + Math.random() * 900000);
      otpInput.value = code;
      this.playSound('scan');
    }
  }

  transitionTo2FA() {
    this.playSound('scan');
    this.hideAlert();

    // Hide step 1, show step 2
    document.getElementById('step-initial-auth').style.display = 'none';
    const step2 = document.getElementById('step-2fa-verification');
    step2.style.display = 'block';

    // Populate user banner in 2FA view
    const targetUser = this.activeUser || window.authService.roles.analyst;
    const targetName = document.getElementById('mfa-target-name');
    const targetRole = document.getElementById('mfa-target-role');
    if (targetName) targetName.textContent = targetUser.name;
    if (targetRole) targetRole.textContent = `${targetUser.title} // ${targetUser.clearance}`;

    this.generateNewOtp();
  }

  handleMfaSubmit(bypassOtp = false) {
    const otpInput = document.getElementById('login-otp-input');
    const otpVal = (otpInput ? otpInput.value : '').trim();

    if (!bypassOtp && (!otpVal || otpVal.length < 6)) {
      this.showAlert('Please provide a 6-digit TOTP token.');
      return;
    }

    this.playSound('success');

    // Hide 2FA container, show success HUD
    document.getElementById('step-2fa-verification').style.display = 'none';
    const successHud = document.getElementById('auth-success-hud');
    if (successHud) {
      successHud.classList.add('active');
    }

    // Store authenticated state
    const user = this.activeUser || window.authService.roles.analyst;
    window.authService.completeLogin(user);

    // Redirect to SOC Command Center (index.html)
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 1100);
  }
}

// Boot on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  window.loginController = new LoginController();
  window.loginController.init();
});
