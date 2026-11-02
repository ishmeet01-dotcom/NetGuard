/**
 * NetGuard Enterprise SOC Dashboard - Chart.js Visualization Engine
 * Manages Chart.js instances with dark enterprise themes, lifecycle cleanup,
 * and robust responsive rendering for security analytics.
 */

export class ChartEngine {
  constructor() {
    this.instances = new Map();
    this.theme = {
      textColor: '#93A1B2',
      gridColor: '#1D2633',
      tooltipBg: '#151C25',
      tooltipBorder: '#273241',
      accentBlue: '#3B82F6',
      accentCyan: '#38BDF8',
      accentGreen: '#22C55E',
      accentOrange: '#F97316',
      accentYellow: '#F59E0B',
      accentRed: '#EF4444',
      accentPurple: '#A855F7',
    };
  }

  /**
   * Safely destroy a managed Chart.js instance by canvas ID.
   */
  destroy(canvasId) {
    if (this.instances.has(canvasId)) {
      try {
        this.instances.get(canvasId).destroy();
      } catch (err) {
        console.warn(`Error destroying chart ${canvasId}:`, err);
      }
      this.instances.delete(canvasId);
    }
  }

  /**
   * Destroy all active chart instances (e.g., when unmounting views).
   */
  destroyAll() {
    for (const canvasId of this.instances.keys()) {
      this.destroy(canvasId);
    }
  }

  /**
   * Check if Chart.js is available on window.
   */
  isReady() {
    return typeof window.Chart !== 'undefined';
  }

  /**
   * 1. Traffic Timeline Chart (Packets/sec & Bytes/sec over time)
   */
  renderTrafficTimeline(canvasId, historyData = []) {
    if (!this.isReady()) return null;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    this.destroy(canvasId);

    // Format labels and datasets from history snapshots (ordered chronologically)
    const sorted = [...historyData].reverse();
    const labels = sorted.map((item) => {
      if (!item.timestamp) return '';
      const d = new Date(item.timestamp * 1000);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    });
    const ppsData = sorted.map((item) => Math.round(item.packets_per_second || 0));
    const bpsData = sorted.map((item) => Math.round(item.bytes_per_second || 0));

    // Fallback if no history points yet
    if (labels.length === 0) {
      labels.push('Now');
      ppsData.push(0);
      bpsData.push(0);
    }

    const ctx = canvas.getContext('2d');
    const chart = new window.Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Packets/sec (PPS)',
            data: ppsData,
            borderColor: this.theme.accentBlue,
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            fill: true,
            tension: 0.3,
            yAxisID: 'yPPS',
            borderWidth: 2,
            pointRadius: 2,
            pointHoverRadius: 5,
          },
          {
            label: 'Bytes/sec (BPS)',
            data: bpsData,
            borderColor: this.theme.accentCyan,
            backgroundColor: 'transparent',
            fill: false,
            tension: 0.3,
            yAxisID: 'yBPS',
            borderWidth: 2,
            borderDash: [4, 4],
            pointRadius: 2,
            pointHoverRadius: 5,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false,
        },
        plugins: {
          legend: {
            position: 'top',
            labels: {
              color: this.theme.textColor,
              font: { family: 'Inter', size: 11 },
              boxWidth: 12,
            },
          },
          tooltip: {
            backgroundColor: this.theme.tooltipBg,
            borderColor: this.theme.tooltipBorder,
            borderWidth: 1,
            titleColor: '#E6EDF5',
            bodyColor: this.theme.textColor,
            padding: 10,
          },
        },
        scales: {
          x: {
            grid: { color: this.theme.gridColor },
            ticks: { color: this.theme.textColor, font: { size: 10 } },
          },
          yPPS: {
            type: 'linear',
            position: 'left',
            grid: { color: this.theme.gridColor },
            ticks: { color: this.theme.textColor, font: { size: 10 } },
            beginAtZero: true,
          },
          yBPS: {
            type: 'linear',
            position: 'right',
            grid: { drawOnChartArea: false },
            ticks: {
              color: this.theme.textColor,
              font: { size: 10 },
              callback: (val) => `${val >= 1000 ? (val / 1000).toFixed(1) + 'k' : val} B/s`,
            },
            beginAtZero: true,
          },
        },
      },
    });

    this.instances.set(canvasId, chart);
    return chart;
  }

  /**
   * 2. Protocol Distribution Doughnut Chart
   */
  renderProtocolDistribution(canvasId, protocols = {}) {
    if (!this.isReady()) return null;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    this.destroy(canvasId);

    const labels = Object.keys(protocols);
    const data = Object.values(protocols);

    const defaultLabels = ['TCP', 'UDP', 'ICMP', 'ARP'];
    const finalLabels = labels.length ? labels : defaultLabels;
    const finalData = labels.length ? data : [0, 0, 0, 0];

    const ctx = canvas.getContext('2d');
    const chart = new window.Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: finalLabels,
        datasets: [
          {
            data: finalData,
            backgroundColor: [
              '#3B82F6', // TCP Blue
              '#8B5CF6', // UDP Purple
              '#EC4899', // ICMP Pink
              '#10B981', // ARP Green
              '#6B7280', // Other Grey
            ],
            borderColor: '#151C25',
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: this.theme.textColor,
              font: { family: 'Inter', size: 11 },
              boxWidth: 12,
            },
          },
          tooltip: {
            backgroundColor: this.theme.tooltipBg,
            borderColor: this.theme.tooltipBorder,
            borderWidth: 1,
            titleColor: '#E6EDF5',
            bodyColor: this.theme.textColor,
          },
        },
        cutout: '70%',
      },
    });

    this.instances.set(canvasId, chart);
    return chart;
  }

  /**
   * 3. Alert Severity Distribution Chart
   */
  renderSeverityDistribution(canvasId, severityCounts = {}) {
    if (!this.isReady()) return null;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    this.destroy(canvasId);

    const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const data = [
      severityCounts.CRITICAL || 0,
      severityCounts.HIGH || 0,
      severityCounts.MEDIUM || 0,
      severityCounts.LOW || 0,
    ];

    const ctx = canvas.getContext('2d');
    const chart = new window.Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Alerts',
            data,
            backgroundColor: [
              '#EF4444', // Critical Red
              '#F97316', // High Orange
              '#F59E0B', // Medium Yellow
              '#38BDF8', // Low Blue
            ],
            borderRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: this.theme.tooltipBg,
            borderColor: this.theme.tooltipBorder,
            borderWidth: 1,
            titleColor: '#E6EDF5',
            bodyColor: this.theme.textColor,
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: this.theme.textColor, font: { size: 10, weight: 'bold' } },
          },
          y: {
            grid: { color: this.theme.gridColor },
            ticks: { color: this.theme.textColor, font: { size: 10 }, stepSize: 1 },
            beginAtZero: true,
          },
        },
      },
    });

    this.instances.set(canvasId, chart);
    return chart;
  }

  /**
   * 4. Most Observed Hosts Horizontal Bar Chart (Observation Occurrences)
   */
  renderMostObservedHosts(canvasId, hosts = []) {
    if (!this.isReady()) return null;
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    this.destroy(canvasId);

    const topHosts = hosts.slice(0, 5);
    const labels = topHosts.map((h) => h.ip_address || 'Unknown');
    const data = topHosts.map((h) => h.observation_count || 0);

    if (labels.length === 0) {
      labels.push('No Active Hosts');
      data.push(0);
    }

    const ctx = canvas.getContext('2d');
    const chart = new window.Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Observed Packet Occurrences',
            data,
            backgroundColor: 'rgba(59, 130, 246, 0.75)',
            borderColor: '#3B82F6',
            borderWidth: 1,
            borderRadius: 4,
          },
        ],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: this.theme.tooltipBg,
            borderColor: this.theme.tooltipBorder,
            borderWidth: 1,
            titleColor: '#E6EDF5',
            bodyColor: this.theme.textColor,
          },
        },
        scales: {
          x: {
            grid: { color: this.theme.gridColor },
            ticks: { color: this.theme.textColor, font: { size: 10 } },
            beginAtZero: true,
          },
          y: {
            grid: { display: false },
            ticks: {
              color: this.theme.textColor,
              font: { family: 'ui-monospace, monospace', size: 11 },
            },
          },
        },
      },
    });

    this.instances.set(canvasId, chart);
    return chart;
  }

  renderTopTalkers(canvasId, hosts = []) {
    return this.renderMostObservedHosts(canvasId, hosts);
  }
}

export const charts = new ChartEngine();
