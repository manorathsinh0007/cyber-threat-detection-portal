/**
 * Telemetry, Visual Analytics & ML Evaluation Hub
 * Manages Chart.js real-time charts, ROC/AUC curves, and Confusion Matrix rendering.
 */

class AnalyticsService {
  constructor() {
    this.attackTrendChart = null;
    this.categoryChart = null;
    this.protocolChart = null;
  }

  init() {
    this.initAttackTrendChart();
    this.initCategoryDistributionChart();
    this.initProtocolChart();
    this.drawRocCurve();
    this.renderConfusionMatrix();
  }

  initAttackTrendChart() {
    const ctx = document.getElementById('attackTrendCanvas');
    if (!ctx || typeof Chart === 'undefined') return;

    const labels = ['12:00', '12:10', '12:20', '12:30', '12:40', '12:50', '13:00'];
    const ddosData = [45, 60, 120, 420, 890, 650, 480];
    const sqliData = [12, 18, 15, 32, 45, 28, 35];
    const c2Data = [5, 8, 12, 14, 22, 18, 19];

    this.attackTrendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'DDoS Traffic (Packets/s)',
            data: ddosData,
            borderColor: '#ff3366',
            backgroundColor: 'rgba(255, 51, 102, 0.15)',
            fill: true,
            tension: 0.4,
            borderWidth: 2
          },
          {
            label: 'Web Exploits (SQLi/XSS)',
            data: sqliData,
            borderColor: '#00ffcc',
            backgroundColor: 'rgba(0, 255, 204, 0.1)',
            fill: true,
            tension: 0.4,
            borderWidth: 2
          },
          {
            label: 'Ransomware / C2 Beacons',
            data: c2Data,
            borderColor: '#ffaa00',
            backgroundColor: 'rgba(255, 170, 0, 0.1)',
            fill: true,
            tension: 0.4,
            borderWidth: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: '#8b9bb4', font: { family: 'JetBrains Mono', size: 11 } }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#8b9bb4', font: { family: 'JetBrains Mono' } }
          },
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#8b9bb4', font: { family: 'JetBrains Mono' } }
          }
        }
      }
    });
  }

  initCategoryDistributionChart() {
    const ctx = document.getElementById('categoryDoughnutCanvas');
    if (!ctx || typeof Chart === 'undefined') return;

    this.categoryChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['DDoS Attack', 'SQL Injection', 'Ransomware/C2', 'Brute Force', 'XSS', 'Zero-Day'],
        datasets: [
          {
            data: [42, 22, 16, 10, 6, 4],
            backgroundColor: [
              '#ff3366',
              '#00ffcc',
              '#ffaa00',
              '#9d4edd',
              '#00a8ff',
              '#ff0055'
            ],
            borderColor: '#0a0e17',
            borderWidth: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#8b9bb4', font: { family: 'JetBrains Mono', size: 11 } }
          }
        }
      }
    });
  }

  initProtocolChart() {
    const ctx = document.getElementById('protocolBarCanvas');
    if (!ctx || typeof Chart === 'undefined') return;

    this.protocolChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['TCP / 80', 'HTTPS / 443', 'SSH / 22', 'SMB / 445', 'UDP / 53', 'RDP / 3389'],
        datasets: [
          {
            label: 'Threat Volume',
            data: [1420, 890, 420, 310, 180, 95],
            backgroundColor: 'rgba(0, 255, 204, 0.4)',
            borderColor: '#00ffcc',
            borderWidth: 1,
            borderRadius: 4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: '#8b9bb4', font: { family: 'JetBrains Mono' } }
          },
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#8b9bb4', font: { family: 'JetBrains Mono' } }
          }
        }
      }
    });
  }

  /**
   * Draw ROC (Receiver Operating Characteristic) Curve on Canvas
   */
  drawRocCurve() {
    const canvas = document.getElementById('rocCurveCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth || 300;
    const h = canvas.height = 200;

    ctx.clearRect(0, 0, w, h);

    // Coordinate grid
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = 1;
    ctx.strokeRect(35, 10, w - 50, h - 35);

    // Random Guess Baseline
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(35, h - 25);
    ctx.lineTo(w - 15, 10);
    ctx.stroke();
    ctx.setLineDash([]); // reset

    // AI Model ROC Curve (AUC = 0.994)
    ctx.strokeStyle = '#00ffcc';
    ctx.lineWidth = 2.5;
    ctx.shadowColor = '#00ffcc';
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.moveTo(35, h - 25);
    ctx.bezierCurveTo(38, 14, 45, 12, w - 15, 10);
    ctx.stroke();
    ctx.shadowBlur = 0; // reset

    // Area Fill
    ctx.fillStyle = 'rgba(0, 255, 204, 0.08)';
    ctx.beginPath();
    ctx.moveTo(35, h - 25);
    ctx.bezierCurveTo(38, 14, 45, 12, w - 15, 10);
    ctx.lineTo(w - 15, h - 25);
    ctx.closePath();
    ctx.fill();

    // Labels
    ctx.font = '10px "JetBrains Mono"';
    ctx.fillStyle = '#8b9bb4';
    ctx.fillText('FPR (0.0 → 1.0)', w / 2 - 30, h - 8);
    ctx.save();
    ctx.translate(12, h / 2 + 30);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('TPR (0.0 → 1.0)', 0, 0);
    ctx.restore();

    // AUC Score Pill
    ctx.fillStyle = '#00ffcc';
    ctx.font = 'bold 11px "JetBrains Mono"';
    ctx.fillText('AUC = 0.994', w - 95, 30);
  }

  /**
   * Render Multi-Class Confusion Matrix Heatmap
   */
  renderConfusionMatrix() {
    const container = document.getElementById('confusion-matrix-container');
    if (!container) return;

    const classes = ['DDoS', 'SQLi', 'C2/Ransom', 'BruteForce', 'Benign'];
    const matrix = [
      [99, 0, 0, 1, 0],
      [0, 98, 1, 0, 1],
      [0, 1, 97, 0, 2],
      [1, 0, 0, 96, 3],
      [0, 1, 1, 1, 97]
    ];

    let html = `
      <table style="width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 0.72rem; text-align: center;">
        <thead>
          <tr>
            <th style="color: var(--text-muted); padding: 6px; font-weight: normal;">Act \\ Pred</th>
            ${classes.map(c => `<th style="color: var(--neon-cyan); padding: 6px;">${c}</th>`).join('')}
          </tr>
        </thead>
        <tbody>
    `;

    matrix.forEach((row, rIdx) => {
      html += `<tr><td style="color: var(--neon-cyan); font-weight: 600; text-align: right; padding-right: 8px;">${classes[rIdx]}</td>`;
      row.forEach((val, cIdx) => {
        const isDiagonal = rIdx === cIdx;
        const bg = isDiagonal ? `rgba(0, 255, 204, ${val / 110})` : val > 0 ? `rgba(255, 51, 102, 0.25)` : 'rgba(255, 255, 255, 0.02)';
        const textCol = isDiagonal ? '#ffffff' : val > 0 ? '#ff3366' : '#53627a';
        html += `<td style="background: ${bg}; color: ${textCol}; padding: 8px; border: 1px solid rgba(255,255,255,0.04); font-weight: ${isDiagonal ? 'bold' : 'normal'}">${val}%</td>`;
      });
      html += `</tr>`;
    });

    html += `</tbody></table>`;
    container.innerHTML = html;
  }
}

window.analyticsService = new AnalyticsService();
