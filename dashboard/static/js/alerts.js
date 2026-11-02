/**
 * NetGuard Enterprise SOC Dashboard - Alert Management Controller
 * Coordinates security alert inspection, multi-criteria filtering,
 * pagination, slideout detail drawer, and status PATCH transitions.
 */

import { api } from './api.js';
import { Utils } from './utils.js';

export class AlertsController {
  constructor(app) {
    this.app = app;
    this.limit = 50;
    this.offset = 0;
    this.totalLoaded = 0;
    this.currentDetailAlertId = null;
    this.isLoading = false;
  }

  init() {
    this.bindEvents();
    this.loadAlerts();
  }

  bindEvents() {
    // Filter controls
    const btnApply = document.getElementById('btn-apply-alert-filters');
    if (btnApply) {
      btnApply.addEventListener('click', () => {
        this.offset = 0;
        this.loadAlerts();
      });
    }

    const btnClear = document.getElementById('btn-clear-alert-filters');
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        const sev = document.getElementById('filter-alert-sev');
        const threat = document.getElementById('filter-alert-threat');
        const status = document.getElementById('filter-alert-status');
        const src = document.getElementById('filter-alert-src');
        const dst = document.getElementById('filter-alert-dst');
        if (sev) sev.value = '';
        if (threat) threat.value = '';
        if (status) status.value = '';
        if (src) src.value = '';
        if (dst) dst.value = '';
        this.offset = 0;
        this.loadAlerts();
      });
    }

    // Pagination
    const btnPrev = document.getElementById('btn-alerts-prev');
    if (btnPrev) {
      btnPrev.addEventListener('click', () => {
        if (this.offset >= this.limit) {
          this.offset -= this.limit;
          this.loadAlerts();
        }
      });
    }

    const btnNext = document.getElementById('btn-alerts-next');
    if (btnNext) {
      btnNext.addEventListener('click', () => {
        this.offset += this.limit;
        this.loadAlerts();
      });
    }

    // Drawer close buttons
    const btnCloseDrawer = document.getElementById('btn-close-alert-drawer');
    const drawerOverlay = document.getElementById('alert-drawer-overlay');
    if (btnCloseDrawer) {
      btnCloseDrawer.addEventListener('click', () => this.closeDetailDrawer());
    }
    if (drawerOverlay) {
      drawerOverlay.addEventListener('click', () => this.closeDetailDrawer());
    }

    // Status Update Button in Drawer
    const btnUpdateStatus = document.getElementById('btn-drawer-update-status');
    if (btnUpdateStatus) {
      btnUpdateStatus.addEventListener('click', () => this.handleUpdateStatus());
    }
  }

  async loadAlerts() {
    if (this.isLoading) return;
    this.isLoading = true;

    const tbody = document.getElementById('alerts-tbody');
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="empty-state">
            <div class="empty-state-title">Loading Security Alerts...</div>
          </td>
        </tr>`;
    }

    const sev = document.getElementById('filter-alert-sev')?.value || '';
    const threat = document.getElementById('filter-alert-threat')?.value || '';
    const status = document.getElementById('filter-alert-status')?.value || '';
    const src = document.getElementById('filter-alert-src')?.value.trim() || '';
    const dst = document.getElementById('filter-alert-dst')?.value.trim() || '';

    const params = {
      limit: this.limit,
      offset: this.offset,
    };
    if (sev) params.severity = sev;
    if (threat) params.threat_type = threat;
    if (status) params.status = status;
    if (src) params.source_ip = src;
    if (dst) params.destination_ip = dst;

    try {
      const res = await api.getAlerts(params);
      if (res.success) {
        this.totalLoaded = res.alerts ? res.alerts.length : 0;
        this.renderTable(res.alerts || []);
        this.updatePaginationUI();
      }
    } catch (err) {
      if (err.isAborted) return;
      if (tbody) {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" class="empty-state">
              <div class="empty-state-title" style="color:var(--color-critical);">Failed to Load Alerts</div>
              <div class="empty-state-desc">${Utils.escapeHTML(err.message)}</div>
            </td>
          </tr>`;
      }
    } finally {
      this.isLoading = false;
    }
  }

  renderTable(alerts) {
    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;

    if (alerts.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="empty-state">
            <div class="empty-state-title">No Security Alerts Found</div>
            <div class="empty-state-desc">No alerts match the applied filters.</div>
          </td>
        </tr>`;
      return;
    }

    const rows = alerts.map((a) => {
      const riskScore = Math.round(a.risk_score || 0);
      return `
        <tr data-alert-id="${Utils.escapeHTML(a.alert_id)}" style="cursor:pointer;">
          <td class="cell-mono cell-strong">${Utils.escapeHTML(a.alert_id)}</td>
          <td>${Utils.formatDate(a.timestamp)}</td>
          <td><span class="cell-strong">${Utils.escapeHTML(a.threat_type)}</span></td>
          <td class="cell-mono">${Utils.escapeHTML(a.source_ip)}</td>
          <td class="cell-mono">${Utils.escapeHTML(a.destination_ip)}</td>
          <td>${Utils.renderSeverityBadge(a.severity)}</td>
          <td class="cell-mono">${riskScore}/100</td>
          <td>${Utils.renderStatusBadge(a.status)}</td>
        </tr>`;
    });

    tbody.innerHTML = rows.join('');

    // Attach row click handlers to open drawer
    tbody.querySelectorAll('tr[data-alert-id]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const id = tr.getAttribute('data-alert-id');
        if (id) this.openDetailDrawer(id);
      });
    });
  }

  updatePaginationUI() {
    const info = document.getElementById('alerts-pagination-info');
    const btnPrev = document.getElementById('btn-alerts-prev');
    const btnNext = document.getElementById('btn-alerts-next');

    if (info) {
      const start = this.offset + 1;
      const end = this.offset + this.totalLoaded;
      info.textContent = this.totalLoaded > 0 ? `Showing ${start} - ${end} alerts` : '0 alerts';
    }

    if (btnPrev) btnPrev.disabled = this.offset === 0;
    if (btnNext) btnNext.disabled = this.totalLoaded < this.limit;
  }

  /**
   * Open slideout drawer and populate detailed alert metadata from API.
   */
  async openDetailDrawer(alertId) {
    this.currentDetailAlertId = alertId;
    const drawer = document.getElementById('alert-detail-drawer');
    const overlay = document.getElementById('alert-drawer-overlay');

    if (overlay) overlay.classList.add('active');
    if (drawer) drawer.classList.add('open');

    // Reset drawer content to loading state
    const setDrawerText = (id, text) => {
      const el = document.getElementById(id);
      if (el) el.textContent = text;
    };
    setDrawerText('drawer-alert-id', alertId);
    setDrawerText('drawer-threat-type', 'Loading...');
    setDrawerText('drawer-timestamp', '...');
    setDrawerText('drawer-source', '...');
    setDrawerText('drawer-destination', '...');
    setDrawerText('drawer-severity', '...');
    setDrawerText('drawer-risk-score', '...');
    setDrawerText('drawer-description', 'Loading investigation details...');
    const evidenceEl = document.getElementById('drawer-evidence-json');
    if (evidenceEl) evidenceEl.textContent = 'Loading evidence...';

    try {
      const res = await api.getAlertDetail(alertId);
      if (res.success && res.alert) {
        const a = res.alert;
        setDrawerText('drawer-threat-type', a.threat_type);
        setDrawerText('drawer-timestamp', Utils.formatDate(a.timestamp));
        setDrawerText('drawer-source', a.source_ip);
        setDrawerText('drawer-destination', a.destination_ip);
        
        const sevEl = document.getElementById('drawer-severity-badge');
        if (sevEl) sevEl.innerHTML = Utils.renderSeverityBadge(a.severity);

        setDrawerText('drawer-risk-score', `${Math.round(a.risk_score || 0)}/100`);
        setDrawerText('drawer-description', a.description || 'No description provided.');

        // Format evidence object cleanly
        let evidenceFormatted = 'No evidence payload';
        if (a.evidence) {
          evidenceFormatted = JSON.stringify(a.evidence, null, 2);
        }
        if (evidenceEl) evidenceEl.textContent = evidenceFormatted;

        // Populate status dropdown selector
        const selectStatus = document.getElementById('drawer-status-select');
        if (selectStatus) {
          selectStatus.value = a.status || 'NEW';
        }
      }
    } catch (err) {
      Utils.showToast(err.message || 'Failed to fetch alert details', 'error');
    }
  }

  closeDetailDrawer() {
    this.currentDetailAlertId = null;
    const drawer = document.getElementById('alert-detail-drawer');
    const overlay = document.getElementById('alert-drawer-overlay');
    if (drawer) drawer.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
  }

  /**
   * Handle PATCH /api/alerts/<id>/status
   */
  async handleUpdateStatus() {
    if (!this.currentDetailAlertId) return;
    const select = document.getElementById('drawer-status-select');
    const btn = document.getElementById('btn-drawer-update-status');
    const newStatus = select ? select.value : null;

    if (!newStatus) return;
    if (btn) btn.disabled = true;

    try {
      const res = await api.updateAlertStatus(this.currentDetailAlertId, newStatus);
      if (res.success) {
        Utils.showToast(`Alert ${res.alert_id} updated to ${res.status}`, 'success');
        this.closeDetailDrawer();
        // Refresh alert list and overview counts
        await this.loadAlerts();
        if (this.app && this.app.dashboardController) {
          this.app.dashboardController.refresh();
        }
      }
    } catch (err) {
      Utils.showToast(err.message || 'Failed to update alert status', 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }
}
