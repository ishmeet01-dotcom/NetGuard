/**
 * NetGuard Enterprise SOC Dashboard - Host Monitoring Controller
 * Queries tracked active network hosts from SQLite with search filters and MAC/IP copy helpers.
 */

import { api } from './api.js';
import { Utils } from './utils.js';

export class HostsController {
  constructor(app) {
    this.app = app;
    this.isLoading = false;
  }

  init() {
    this.bindEvents();
    this.loadHosts();
  }

  bindEvents() {
    const btnSearch = document.getElementById('btn-search-hosts');
    const inputSearch = document.getElementById('input-search-hosts');

    if (btnSearch) {
      btnSearch.addEventListener('click', () => this.loadHosts());
    }

    if (inputSearch) {
      inputSearch.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') this.loadHosts();
      });
    }

    const btnClear = document.getElementById('btn-clear-hosts-search');
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        if (inputSearch) inputSearch.value = '';
        this.loadHosts();
      });
    }
  }

  async loadHosts() {
    if (this.isLoading) return;
    this.isLoading = true;

    const tbody = document.getElementById('hosts-tbody');
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">
            <div class="empty-state-title">Loading Tracked Network Hosts...</div>
          </td>
        </tr>`;
    }

    const search = document.getElementById('input-search-hosts')?.value.trim() || '';
    const params = { limit: 100 };
    if (search) params.search = search;

    try {
      const res = await api.getHosts(params);
      if (res.success) {
        this.renderTable(res.hosts || []);
      }
    } catch (err) {
      if (tbody) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="empty-state">
              <div class="empty-state-title" style="color:var(--color-critical);">Failed to Load Hosts</div>
              <div class="empty-state-desc">${Utils.escapeHTML(err.message)}</div>
            </td>
          </tr>`;
      }
    } finally {
      this.isLoading = false;
    }
  }

  renderTable(hosts) {
    const tbody = document.getElementById('hosts-tbody');
    if (!tbody) return;

    if (hosts.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">
            <div class="empty-state-title">No Network Hosts Tracked</div>
            <div class="empty-state-desc">No active hosts match the search query.</div>
          </td>
        </tr>`;
      return;
    }

    const rows = hosts.map((h) => {
      const macStr = h.mac_address || '<span style="color:var(--text-muted);">Unassociated</span>';
      return `
        <tr>
          <td class="cell-mono cell-strong">
            <div class="cell-actions">
              <span>${Utils.escapeHTML(h.ip_address)}</span>
              <button class="btn-copy-ip" data-copy="${Utils.escapeHTML(h.ip_address)}" title="Copy IP">
                <i data-lucide="copy" style="width:12px;height:12px;"></i>
              </button>
            </div>
          </td>
          <td class="cell-mono">${macStr}</td>
          <td class="cell-mono">${Utils.formatNumber(h.observation_count || 1)}</td>
          <td>${Utils.formatDate(h.first_seen)}</td>
          <td>${Utils.formatDate(h.last_seen)}</td>
          <td>
            <span class="badge badge-status-resolved">Active Host</span>
          </td>
        </tr>`;
    });

    tbody.innerHTML = rows.join('');

    tbody.querySelectorAll('.btn-copy-ip').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const text = btn.getAttribute('data-copy');
        if (text) Utils.copyToClipboard(text, 'IP Copied');
      });
    });

    if (window.lucide && window.lucide.createIcons) {
      window.lucide.createIcons({ root: tbody });
    }
  }
}
