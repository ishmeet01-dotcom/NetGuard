/**
 * NetGuard Enterprise SOC Dashboard - System Health & Diagnostics Controller
 * Monitors backend process health, SQLite storage metrics, thread lifecycles, and queue boundaries.
 */

import { api } from './api.js';
import { Utils } from './utils.js';

export class HealthController {
  constructor(app) {
    this.app = app;
    this.pollTimer = null;
    this.isLoading = false;
  }

  async init() {
    this.bindEvents();
    await this.refresh();
  }

  bindEvents() {
    const btnRefresh = document.getElementById('btn-refresh-health');
    if (btnRefresh) {
      btnRefresh.addEventListener('click', () => this.refresh());
    }
  }

  async refresh() {
    if (this.isLoading) return;
    this.isLoading = true;

    try {
      const [statusRes, monRes] = await Promise.allSettled([
        api.getStatus(),
        api.getMonitorStatus(),
      ]);

      const isApiOk = statusRes.status === 'fulfilled' && statusRes.value.success;
      const isMonOk = monRes.status === 'fulfilled' && monRes.value.success;

      const statusData = isApiOk ? statusRes.value : {};
      const monData = isMonOk ? monRes.value.data : {};

      this.updateUI(isApiOk, statusData, monData);
    } catch (err) {
      console.error('Failed to refresh system health:', err);
    } finally {
      this.isLoading = false;
    }
  }

  updateUI(isApiOk, statusData, m) {
    const counts = statusData.counts || {};

    // 1. API Status Card
    const apiBadge = document.getElementById('health-api-badge');
    const apiState = document.getElementById('health-api-state');
    if (apiBadge && apiState) {
      if (isApiOk) {
        apiBadge.className = 'status-dot online';
        apiState.textContent = 'Operational (HTTP 200 OK)';
        apiState.style.color = 'var(--color-success)';
      } else {
        apiBadge.className = 'status-dot offline';
        apiState.textContent = 'Degraded / Unreachable';
        apiState.style.color = 'var(--color-critical)';
      }
    }

    // 2. Database Status Card
    const dbBadge = document.getElementById('health-db-badge');
    const dbState = document.getElementById('health-db-state');
    const dbRecords = document.getElementById('health-db-records');
    if (dbBadge && dbState && dbRecords) {
      if (isApiOk) {
        dbBadge.className = 'status-dot online';
        dbState.textContent = 'Connected (SQLite3)';
        dbState.style.color = 'var(--color-success)';
        dbRecords.textContent = `${Utils.formatNumber(counts.total_traffic_packets || 0)} traffic records, ${Utils.formatNumber(counts.total_alerts || 0)} alerts stored`;
      } else {
        dbBadge.className = 'status-dot offline';
        dbState.textContent = 'Database Unreachable';
        dbState.style.color = 'var(--color-critical)';
      }
    }

    // 3. Monitoring Worker Status Card
    const workerBadge = document.getElementById('health-worker-badge');
    const workerState = document.getElementById('health-worker-state');
    const workerMeta = document.getElementById('health-worker-meta');
    if (workerBadge && workerState && workerMeta) {
      if (m.is_monitoring) {
        workerBadge.className = 'status-dot capturing';
        workerState.textContent = 'Active Sniffer Worker Running';
        workerState.style.color = 'var(--color-info)';
        workerMeta.textContent = `Adapter: ${m.interface || 'Default'} | Filter: ${m.bpf_filter || 'None'}`;
      } else {
        workerBadge.className = 'status-dot standby';
        workerState.textContent = 'Worker Idle (Standby)';
        workerState.style.color = 'var(--color-warning)';
        workerMeta.textContent = 'Opt-in live capture is currently stopped.';
      }
    }

    // 4. Queue Utilization Card
    const queueVal = document.getElementById('health-queue-val');
    const queueBar = document.getElementById('health-queue-bar');
    const droppedVal = document.getElementById('health-dropped-val');
    if (queueVal && queueBar && droppedVal) {
      const qSize = m.queue_size || 0;
      const qCap = m.queue_capacity || 10000;
      const pct = Math.min(100, Math.round((qSize / qCap) * 100));
      queueVal.textContent = `${qSize} / ${qCap} (${pct}%)`;
      queueBar.style.width = `${pct}%`;
      droppedVal.textContent = Utils.formatNumber(m.dropped_packets || 0);
    }

    // 5. System Diagnostics Metrics
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setVal('health-uptime', Utils.formatDuration(m.uptime_seconds || 0));
    setVal('health-total-packets', Utils.formatNumber(m.total_packets || counts.total_traffic_packets || 0));
    setVal('health-total-bytes', Utils.formatBytes(m.total_bytes || 0));
    setVal('health-dropped-packets', Utils.formatNumber(m.dropped_packets || 0));

    // Error log
    const errBox = document.getElementById('health-last-error');
    if (errBox) {
      if (m.last_error) {
        // Sanitize to prevent revealing internal filesystem paths or stack traces
        let sanitized = String(m.last_error).replace(/([A-Za-z]:\\[^:\n\r]+|\/[a-zA-Z0-9_\-\.\/]+)/g, '[internal_path]');
        sanitized = sanitized.split('\n')[0]; // Top-level summary line only
        errBox.textContent = `[!] Diagnostic Notice: ${sanitized}`;
        errBox.style.color = 'var(--color-critical)';
      } else {
        errBox.textContent = 'No internal errors logged. System operating normally.';
        errBox.style.color = 'var(--color-success)';
      }
    }
  }

  startPolling(intervalMs = 5000) {
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
