/**
 * Canvas-Based Cyber Attack Vector & Threat Map Visualizer
 * Renders global SOC nodes, animated ballistic curved attack vectors, and laser pulses.
 */

class AttackMap {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas ? this.canvas.getContext('2d') : null;
    this.isRunning = true;
    this.attacks = [];
    this.impacts = [];
    
    // Global SOC Node Coordinates (normalized 0 to 1)
    this.nodes = [
      { id: 'US-EAST', name: 'New York SOC (DC-1)', x: 0.28, y: 0.35, isHq: true },
      { id: 'US-WEST', name: 'San Francisco Gateway', x: 0.18, y: 0.38, isHq: false },
      { id: 'EU-CENTRAL', name: 'Frankfurt Hub', x: 0.52, y: 0.28, isHq: false },
      { id: 'UK-LONDON', name: 'London Node', x: 0.47, y: 0.25, isHq: false },
      { id: 'AP-TOKYO', name: 'Tokyo Subnet', x: 0.85, y: 0.36, isHq: false },
      { id: 'AP-MUMBAI', name: 'Mumbai Node', x: 0.68, y: 0.44, isHq: false },
      { id: 'AP-SINGAPORE', name: 'Singapore Hub', x: 0.76, y: 0.56, isHq: false },
      { id: 'SA-SAOPAULO', name: 'Sao Paulo Relay', x: 0.36, y: 0.72, isHq: false },
      { id: 'AU-SYDNEY', name: 'Sydney Node', x: 0.88, y: 0.78, isHq: false }
    ];

    if (this.canvas) {
      this.resize();
      window.addEventListener('resize', () => this.resize());
      this.startLoop();
      this.spawnInterval = setInterval(() => this.spawnRandomAttack(), 1400);
    }
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.getBoundingClientRect();
    this.canvas.width = rect.width * window.devicePixelRatio || rect.width || 800;
    this.canvas.height = rect.height * window.devicePixelRatio || rect.height || 380;
    if (this.ctx) {
      this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    }
  }

  spawnAttack(sourceNodeId, targetNodeId, threatCategory = 'DDoS Attack', severity = 'CRITICAL') {
    const src = this.nodes.find(n => n.id === sourceNodeId) || this.nodes[Math.floor(Math.random() * this.nodes.length)];
    let dst = this.nodes.find(n => n.id === targetNodeId);
    if (!dst || dst === src) {
      dst = this.nodes.find(n => n.isHq) || this.nodes[0];
    }

    const color = severity === 'CRITICAL' ? '#ff3366' : severity === 'HIGH' ? '#ffaa00' : '#00ffcc';

    this.attacks.push({
      src: src,
      dst: dst,
      progress: 0,
      speed: 0.008 + Math.random() * 0.008,
      category: threatCategory,
      color: color,
      arcHeight: (Math.random() - 0.5) * 60
    });
  }

  spawnRandomAttack() {
    if (!this.isRunning) return;
    const src = this.nodes[Math.floor(Math.random() * this.nodes.length)];
    const dst = this.nodes.find(n => n.isHq) || this.nodes[0];
    const threats = ['SYN Flood DDoS', 'SQL Injection Probe', 'Cobalt Strike C2', 'SSH Brute Force', 'XSS Injection'];
    const cat = threats[Math.floor(Math.random() * threats.length)];
    const sev = cat.includes('DDoS') || cat.includes('C2') ? 'CRITICAL' : 'HIGH';
    this.spawnAttack(src.id, dst.id, cat, cat.includes('DDoS') ? 'CRITICAL' : 'HIGH');
  }

  startLoop() {
    const animate = () => {
      if (this.isRunning) {
        this.render();
      }
      requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);
  }

  render() {
    if (!this.ctx || !this.canvas) return;
    const width = this.canvas.getBoundingClientRect().width;
    const height = this.canvas.getBoundingClientRect().height;

    this.ctx.clearRect(0, 0, width, height);

    // Draw Cyber Background Grid
    this.ctx.strokeStyle = 'rgba(0, 255, 204, 0.05)';
    this.ctx.lineWidth = 1;
    for (let x = 0; x < width; x += 40) {
      this.ctx.beginPath();
      this.ctx.moveTo(x, 0);
      this.ctx.lineTo(x, height);
      this.ctx.stroke();
    }
    for (let y = 0; y < height; y += 40) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(width, y);
      this.ctx.stroke();
    }

    // Draw Nodes
    this.nodes.forEach(node => {
      const nx = node.x * width;
      const ny = node.y * height;

      // Glow Halo
      const gradient = this.ctx.createRadialGradient(nx, ny, 2, nx, ny, node.isHq ? 16 : 10);
      gradient.addColorStop(0, node.isHq ? 'rgba(0, 255, 204, 0.6)' : 'rgba(0, 168, 255, 0.4)');
      gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
      this.ctx.fillStyle = gradient;
      this.ctx.beginPath();
      this.ctx.arc(nx, ny, node.isHq ? 16 : 10, 0, Math.PI * 2);
      this.ctx.fill();

      // Node Point
      this.ctx.fillStyle = node.isHq ? '#00ffcc' : '#00a8ff';
      this.ctx.beginPath();
      this.ctx.arc(nx, ny, node.isHq ? 4.5 : 3, 0, Math.PI * 2);
      this.ctx.fill();

      // Node Label
      this.ctx.font = '10px "JetBrains Mono", monospace';
      this.ctx.fillStyle = 'rgba(240, 246, 252, 0.7)';
      this.ctx.fillText(node.id, nx + 8, ny + 3);
    });

    // Draw & Update Attack Arcs
    for (let i = this.attacks.length - 1; i >= 0; i--) {
      const atk = this.attacks[i];
      atk.progress += atk.speed;

      const sx = atk.src.x * width;
      const sy = atk.src.y * height;
      const dx = atk.dst.x * width;
      const dy = atk.dst.y * height;

      // Calculate Quadratic Bezier Control Point
      const cx = (sx + dx) / 2;
      const cy = (sy + dy) / 2 - 50 + atk.arcHeight;

      // Draw faint trajectory arc
      this.ctx.strokeStyle = atk.color + '33';
      this.ctx.lineWidth = 1.2;
      this.ctx.beginPath();
      this.ctx.moveTo(sx, sy);
      this.ctx.quadraticCurveTo(cx, cy, dx, dy);
      this.ctx.stroke();

      // Calculate Current Position of Laser Pulse along Bezier
      const t = atk.progress;
      const px = Math.pow(1 - t, 2) * sx + 2 * (1 - t) * t * cx + Math.pow(t, 2) * dx;
      const py = Math.pow(1 - t, 2) * sy + 2 * (1 - t) * t * cy + Math.pow(t, 2) * dy;

      // Draw Glowing Laser Pulse
      this.ctx.fillStyle = atk.color;
      this.ctx.shadowColor = atk.color;
      this.ctx.shadowBlur = 8;
      this.ctx.beginPath();
      this.ctx.arc(px, py, 3.5, 0, Math.PI * 2);
      this.ctx.fill();
      this.ctx.shadowBlur = 0; // reset

      // On Arrival: trigger impact burst
      if (atk.progress >= 1.0) {
        this.impacts.push({
          x: dx,
          y: dy,
          radius: 2,
          maxRadius: 24,
          color: atk.color,
          alpha: 1.0
        });
        this.attacks.splice(i, 1);
      }
    }

    // Draw & Update Impact Rings
    for (let j = this.impacts.length - 1; j >= 0; j--) {
      const imp = this.impacts[j];
      imp.radius += 1.2;
      imp.alpha -= 0.04;

      if (imp.alpha <= 0) {
        this.impacts.splice(j, 1);
        continue;
      }

      this.ctx.strokeStyle = imp.color;
      this.ctx.globalAlpha = imp.alpha;
      this.ctx.lineWidth = 1.5;
      this.ctx.beginPath();
      this.ctx.arc(imp.x, imp.y, imp.radius, 0, Math.PI * 2);
      this.ctx.stroke();
      this.ctx.globalAlpha = 1.0;
    }
  }

  addCustomAttackPoint(data) {
    if (!this.canvas) return;
    const lat = data.lat || 38.0;
    const lon = data.lon || -77.0;
    // Map lon [-180, 180] to [0, 1]
    const normX = Math.max(0.05, Math.min(0.95, (lon + 180) / 360));
    // Map lat [90, -90] to [0, 1]
    const normY = Math.max(0.1, Math.min(0.9, (90 - lat) / 180));

    const customNode = {
      id: `EXT-${data.sourceIp}`,
      name: `${data.country || 'External'} (${data.sourceIp})`,
      x: normX,
      y: normY,
      isHq: false
    };

    const targetHq = this.nodes.find(n => n.isHq) || this.nodes[0];
    const color = data.riskLevel === 'CRITICAL' ? '#ff2244' : data.riskLevel === 'HIGH' ? '#ffaa00' : '#00e5ff';

    this.attacks.push({
      src: customNode,
      dst: targetHq,
      progress: 0,
      speed: 0.012,
      category: data.category || 'Live Network Threat',
      color: color,
      arcHeight: (Math.random() - 0.5) * 80
    });
  }

  toggle() {
    this.isRunning = !this.isRunning;
    return this.isRunning;
  }
}

window.AttackMap = AttackMap;
