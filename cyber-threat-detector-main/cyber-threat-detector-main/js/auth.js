/**
 * Multi-Role Authentication & 2FA Simulator System
 * Manages user sessions, roles (SOC Analyst, Threat Hunter, Security Admin), and simulated MFA.
 */

class AuthService {
  constructor() {
    this.roles = {
      analyst: {
        id: 'analyst',
        username: 'alex.vance',
        name: 'Alex Vance',
        title: 'SOC Analyst (Tier-1)',
        clearance: 'Secret / Level-2',
        avatarText: 'AV',
        permissions: ['view_dashboard', 'view_logs', 'run_ml_inference', 'view_investigation']
      },
      hunter: {
        id: 'hunter',
        username: 'elena.rostova',
        name: 'Elena Rostova',
        title: 'Senior Threat Hunter',
        clearance: 'Top Secret / Level-4',
        avatarText: 'ER',
        permissions: ['view_dashboard', 'view_logs', 'run_ml_inference', 'upload_datasets', 'view_investigation', 'trigger_containment']
      },
      admin: {
        id: 'admin',
        username: 'marcus.vance',
        name: 'Commander Marcus Vance',
        title: 'CISO / SOC Director',
        clearance: 'DEFCON-1 Full Executive',
        avatarText: 'MV',
        permissions: ['*']
      }
    };

    // Default pre-authorized credentials for instant demo access
    this.defaultCredentials = {
      'alex.vance': { password: 'analyst123', role: 'analyst' },
      'elena.rostova': { password: 'hunter123', role: 'hunter' },
      'marcus.vance': { password: 'admin123', role: 'admin' },
      'admin': { password: 'admin', role: 'admin' },
      'analyst': { password: 'analyst', role: 'analyst' },
      'hunter': { password: 'hunter', role: 'hunter' }
    };

    // Load active session from localStorage or default to analyst
    this.currentUser = JSON.parse(localStorage.getItem('cyber_soc_user')) || this.roles.analyst;
    this.isAuthenticated = localStorage.getItem('cyber_soc_auth') === 'true';
    this.pendingUser = null;
  }

  isLoggedIn() {
    return this.isAuthenticated;
  }

  getCurrentUser() {
    return this.currentUser;
  }

  hasPermission(perm) {
    if (!this.currentUser) return false;
    if (this.currentUser.permissions.includes('*')) return true;
    return this.currentUser.permissions.includes(perm);
  }

  /**
   * Verify username and password
   */
  verifyCredentials(username, password, selectedRole = null) {
    const cleanUser = (username || '').trim().toLowerCase();
    const cleanPass = (password || '').trim();

    if (!cleanUser) {
      return { success: false, message: 'Operator ID or Username is required.' };
    }
    if (!cleanPass) {
      return { success: false, message: 'Security Passcode is required.' };
    }

    // Check predefined accounts
    if (this.defaultCredentials[cleanUser]) {
      const cred = this.defaultCredentials[cleanUser];
      if (cleanPass === cred.password || cleanPass === 'password' || cleanPass.length >= 4) {
        const roleKey = selectedRole || cred.role;
        return { success: true, user: this.roles[roleKey] || this.roles.analyst };
      }
    }

    // Allow flexible test credentials if at least 4 chars long
    if (cleanPass.length >= 4) {
      const roleKey = selectedRole || 'analyst';
      const baseRole = this.roles[roleKey] || this.roles.analyst;
      const customUser = {
        ...baseRole,
        username: cleanUser,
        name: cleanUser.charAt(0).toUpperCase() + cleanUser.slice(1).replace('.', ' '),
        avatarText: cleanUser.slice(0, 2).toUpperCase()
      };
      return { success: true, user: customUser };
    }

    return { success: false, message: 'Invalid credentials. Minimum 4 characters required.' };
  }

  /**
   * Initiate Login sequence (triggers 2FA modal)
   */
  startLogin(roleKey, credentials = null) {
    const user = this.roles[roleKey] || this.roles.analyst;
    this.pendingUser = user;
    return new Promise((resolve) => {
      // Trigger 2FA modal
      this.show2FAModal(resolve);
    });
  }

  show2FAModal(callback) {
    const modal = document.getElementById('mfa-modal');
    if (!modal) {
      this.completeLogin(this.pendingUser);
      callback(true);
      return;
    }

    modal.classList.add('active');
    const otpInput = document.getElementById('mfa-otp-input');
    if (otpInput) {
      otpInput.value = Math.floor(100000 + Math.random() * 900000);
      otpInput.focus();
    }

    // Set one-time listener for verify button
    const verifyBtn = document.getElementById('mfa-verify-btn');
    const onVerify = () => {
      modal.classList.remove('active');
      verifyBtn.removeEventListener('click', onVerify);
      this.completeLogin(this.pendingUser);
      if (window.alertsService) {
        window.alertsService.showToast('Authentication Successful', `Welcome back, ${this.pendingUser.name} (${this.pendingUser.title})`, 'success');
      }
      callback(true);
    };

    verifyBtn.onclick = onVerify;
  }

  completeLogin(user) {
    this.currentUser = user;
    this.isAuthenticated = true;
    localStorage.setItem('cyber_soc_user', JSON.stringify(user));
    localStorage.setItem('cyber_soc_auth', 'true');
    this.updateUI();
  }

  logout(redirectToLogin = false) {
    this.isAuthenticated = false;
    localStorage.removeItem('cyber_soc_auth');
    if (redirectToLogin) {
      window.location.href = 'login.html';
      return;
    }
    const loginModal = document.getElementById('login-modal');
    if (loginModal) {
      loginModal.classList.add('active');
    }
  }

  updateUI() {
    const userRoleEl = document.getElementById('header-user-role');
    const userNameEl = document.getElementById('header-user-name');
    const userAvatarEl = document.getElementById('header-user-avatar');

    if (userRoleEl && this.currentUser) userRoleEl.textContent = this.currentUser.title;
    if (userNameEl && this.currentUser) userNameEl.textContent = this.currentUser.name;
    if (userAvatarEl && this.currentUser) userAvatarEl.textContent = this.currentUser.avatarText;
  }
}

window.authService = new AuthService();
