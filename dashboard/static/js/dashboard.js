/**
 * NetGuard Enterprise SOC Dashboard - Overview Controller
 * Coordinates KPI metric cards, high-level Chart.js graphs, and recent security alerts.
 */

import { api } from './api.js';
import { charts } from './charts.js';
import { Utils } from './utils.js';

export class DashboardController {
  constructor(app) {
    this.app = app;
    this.pollTimer = null;
    this.isPolling = false;
  }

  async init() {
    await this.refresh();
  }

  /**
   * Fetch all necessary dashboard data from API and update UI.
   */
  async refresh() {
    if (this.isPolling) return;
    this.isPolling = true;

    try {
      // Parallel requests for optimal dashboard load latency
      const [statusRes, statsRes, historyRes, alertsRes, hostsRes] = await Promise.allSettled([
        api.getStatus(),
        api.getStatistics(),
        api.getStatisticsHistory(25),
        api.getAlerts({ limit: 10 }),
        api.getHosts({ limit: 5 }),
      ]);

      if (statusRes.status === 'fulfilled' && statusRes.value.success) {
        this.updateKPICards(statusRes.value, statsRes.status === 'fulfilled' ? statsRes.value : null);
      }

      // Update Charts
      if (historyRes.status === 'fulfilled' && historyRes.value.success) {
        charts.renderTrafficTimeline('chart-traffic-timeline', historyRes.value.history);
      }

      if (statsRes.status === 'fulfilled' && statsRes.value.success) {
        charts.renderProtocolDistribution('chart-protocol-dist', statsRes.value.protocol_counts || {});
      }

      if (alertsRes.status === 'fulfilled' && alertsRes.value.success) {
        this.updateRecentAlertsTable(alertsRes.value.alerts || []);
        this.updateSeverityChart(alertsRes.value.alerts || []);
      }

      if (hostsRes.status === 'fulfilled' && hostsRes.value.success) {
        charts.renderTopTalkers('chart-top-talkers', hostsRes.value.hosts || []);
      }

      // Update footer timestamp
      const updateEl = document.getElementById('last-updated-text');
      if (updateEl) {
        const now = new Date();
        updateEl.textContent = `Updated ${now.toLocaleTimeString()}`;
      }
    } catch (err) {
      console.error('Error refreshing overview dashboard:', err);
    } finally {
      this.isPolling = false;
    }
  }

  /**
   * Update KPI Cards with real backend values.
   */
  updateKPICards(statusData, statsData) {
    const counts = statusData.counts || {};
    const monitor = statusData.monitoring || {};

    // 1. Total Packets
    const totalPkts = monitor.is_monitoring
      ? monitor.total_packets
      : counts.total_traffic_packets || 0;
    const elPkts = document.getElementById('kpi-total-packets');
    if (elPkts) elPkts.textContent = Utils.formatNumber(totalPkts);

    // 2. Total Bytes
    const totalBytes = monitor.is_monitoring
      ? monitor.total_bytes
      : (statsData && statsData.total_bytes) || 0;
    const elBytes = document.getElementById('kpi-total-bytes');
    if (elBytes) elBytes.textContent = Utils.formatBytes(totalBytes);

    // 3. PPS
    const pps = monitor.current_pps || (statsData && statsData.packets_per_second) || 0;
    const elPps = document.getElementById('kpi-pps');
    if (elPps) elPps.textContent = Utils.formatNumber(Math.round(pps));

    // 4. Active Hosts
    const hostsCount = monitor.is_monitoring
      ? monitor.active_sources_count || counts.active_hosts || 0
      : counts.active_hosts || 0;
    const elHosts = document.getElementById('kpi-active-hosts');
    if (elHosts) elHosts.textContent = Utils.formatNumber(hostsCount);

    // 5. Total Security Alerts
    const elAlerts = document.getElementById('kpi-total-alerts');
    if (elAlerts) elAlerts.textContent = Utils.formatNumber(counts.total_alerts || 0);

    // 6. Critical Alerts
    const elCritical = document.getElementById('kpi-critical-alerts');
    if (elCritical) elCritical.textContent = Utils.formatNumber(counts.critical_threats || 0);
  }

  /**
   * Calculate and render Alert Severity Distribution chart.
   */
  updateSeverityChart(alerts) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const a of alerts) {
      const sev = String(a.severity || 'LOW').toUpperCase();
      if (counts[sev] !== undefined) counts[sev]++;
    }
    charts.renderSeverityDistribution('chart-severity-dist', counts);
  }

  /**
   * Render Recent Alerts Table with quick inspect links.
   */
  updateRecentAlertsTable(alerts) {
    const tbody = document.getElementById('recent-alerts-tbody');
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-state">
            <div class="empty-state-title">No Security Alerts Detected</div>
            <div class="empty-state-desc">Traffic activity has not triggered any detection thresholds.</div>
          </td>
        </tr>`;
      return;
    }

    const rows = alerts.map((a) => {
      return `
        <tr data-alert-id="${Utils.escapeHTML(a.alert_id)}" style="cursor:pointer;">
          <td class="cell-mono cell-strong">${Utils.escapeHTML(a.alert_id)}</td>
          <td>${Utils.formatDate(a.timestamp)}</td>
          <td><span class="cell-strong">${Utils.escapeHTML(a.threat_type)}</span></td>
          <td class="cell-mono">${Utils.escapeHTML(a.source_ip)}</td>
          <td class="cell-mono">${Utils.escapeHTML(a.destination_ip)}</td>
          <td>${Utils.renderSeverityBadge(a.severity)}</td>
          <td>${Utils.renderStatusBadge(a.status)}</td>
        </tr>`;
    });

    tbody.innerHTML = rows.join('');

    // Attach click listeners to row to open alert details
    tbody.querySelectorAll('tr[data-alert-id]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const id = tr.getAttribute('data-alert-id');
        if (id && this.app && this.app.alertsController) {
          this.app.alertsController.openDetailDrawer(id);
        }
      });
    });
  }

  startPolling(intervalMs = 3000) {
    this.stopPolling();
    this.pollTimer = setInterval(() => {
      this.refresh();
    }, intervalMs);
  }

  stopPolling() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }
}
