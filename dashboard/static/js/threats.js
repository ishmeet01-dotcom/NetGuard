/**
 * NetGuard Enterprise SOC Dashboard - Threat Intelligence Controller
 * Analyzes detected threat categories (Port Scan, SYN/UDP/ICMP Floods, ARP & Statistical Anomalies),
 * evidence classifications, and risk score distributions.
 */

import { api } from './api.js';
import { Utils } from './utils.js';

export class ThreatsController {
  constructor(app) {
    this.app = app;
    this.threatCategories = [
      { id: 'PORT_SCAN', name: 'Port Scan', desc: 'Sliding window multi-port reconnaissance', icon: 'crosshair' },
      { id: 'SYN_FLOOD', name: 'SYN Flood', desc: 'High-volume half-open TCP connection burst', icon: 'zap' },
      { id: 'UDP_FLOOD', name: 'UDP Flood', desc: 'High-rate UDP packet bandwidth exhaustion', icon: 'activity' },
      { id: 'ICMP_FLOOD', name: 'ICMP Flood', desc: 'Excessive ping/echo flood attack pattern', icon: 'radio' },
      { id: 'ARP_ANOMALY', name: 'ARP Anomaly', desc: 'MAC-IP conflicting association or cache poison', icon: 'git-commit' },
      { id: 'STATISTICAL_ANOMALY', name: 'Statistical Anomaly', desc: 'Packet size Z-score & rate distribution deviations', icon: 'bar-chart-2' },
    ];
  }

  async init() {
    this.bindEvents();
    await this.loadThreats();
  }

  bindEvents() {
    const btnFilter = document.getElementById('btn-apply-threat-filters');
    if (btnFilter) {
      btnFilter.addEventListener('click', () => this.loadThreats());
    }

    const btnClear = document.getElementById('btn-clear-threat-filters');
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        const typeSelect = document.getElementById('filter-threat-type');
        const sevSelect = document.getElementById('filter-threat-sev');
        const srcInput = document.getElementById('filter-threat-src');
        if (typeSelect) typeSelect.value = '';
        if (sevSelect) sevSelect.value = '';
        if (srcInput) srcInput.value = '';
        this.loadThreats();
      });
    }
  }

  async loadThreats() {
    const type = document.getElementById('filter-threat-type')?.value || '';
    const sev = document.getElementById('filter-threat-sev')?.value || '';
    const src = document.getElementById('filter-threat-src')?.value.trim() || '';

    const params = { limit: 100 };
    if (type) params.threat_type = type;
    if (sev) params.severity = sev;
    if (src) params.source_ip = src;

    try {
      const res = await api.getAlerts(params);
      if (res.success) {
        const alerts = res.alerts || [];
        this.renderCategoryCards(alerts);
        this.renderThreatsTable(alerts);
      }
    } catch (err) {
      console.error('Failed to load threats:', err);
    }
  }

  renderCategoryCards(alerts) {
    const container = document.getElementById('threat-category-cards');
    if (!container) return;

    // Count detections per category
    const counts = {};
    for (const a of alerts) {
      counts[a.threat_type] = (counts[a.threat_type] || 0) + 1;
    }

    const cardsHtml = this.threatCategories.map((cat) => {
      const count = counts[cat.id] || 0;
      return `
        <div class="kpi-card" style="border-left: 3px solid var(--accent-primary);">
          <div class="kpi-top">
            <span class="kpi-title">${Utils.escapeHTML(cat.name)}</span>
            <i data-lucide="${cat.icon}" class="kpi-icon"></i>
          </div>
          <div class="kpi-value-row">
            <span class="kpi-value">${Utils.formatNumber(count)}</span>
            <span class="kpi-unit">detections</span>
          </div>
          <div class="kpi-subtext">${Utils.escapeHTML(cat.desc)}</div>
        </div>`;
    });

    container.innerHTML = cardsHtml.join('');
    if (window.lucide && window.lucide.createIcons) {
      window.lucide.createIcons({ root: container });
    }
  }

  renderThreatsTable(alerts) {
    const tbody = document.getElementById('threats-tbody');
    if (!tbody) return;

    if (alerts.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-state">
            <div class="empty-state-title">No Threats Detected</div>
            <div class="empty-state-desc">Traffic features are currently within baseline thresholds.</div>
          </td>
        </tr>`;
      return;
    }

    const rows = alerts.map((a) => {
      const riskScore = Math.round(a.risk_score || 0);
      let scoreColor = 'var(--color-info)';
      if (riskScore >= 90) scoreColor = 'var(--color-critical)';
      else if (riskScore >= 70) scoreColor = '#F97316';
      else if (riskScore >= 40) scoreColor = 'var(--color-warning)';

      return `
        <tr data-alert-id="${Utils.escapeHTML(a.alert_id)}" style="cursor:pointer;">
          <td class="cell-mono cell-strong">${Utils.escapeHTML(a.alert_id)}</td>
          <td>${Utils.formatDate(a.timestamp)}</td>
          <td><span class="cell-strong">${Utils.escapeHTML(a.threat_type)}</span></td>
          <td class="cell-mono">${Utils.escapeHTML(a.source_ip)}</td>
          <td class="cell-mono">${Utils.escapeHTML(a.destination_ip)}</td>
          <td>${Utils.renderSeverityBadge(a.severity)}</td>
          <td>
            <div style="display:flex;align-items:center;gap:6px;">
              <span class="cell-mono" style="font-weight:700;color:${scoreColor};">${riskScore}</span>
              <span style="font-size:10px;color:var(--text-muted);">/100</span>
            </div>
          </td>
        </tr>`;
    });

    tbody.innerHTML = rows.join('');

    tbody.querySelectorAll('tr[data-alert-id]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const id = tr.getAttribute('data-alert-id');
        if (id && this.app && this.app.alertsController) {
          this.app.alertsController.openDetailDrawer(id);
        }
      });
    });
  }
}
