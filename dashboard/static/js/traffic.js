/**
 * NetGuard Enterprise SOC Dashboard - Network Traffic Controller
 * Handles paginated packet records, protocol/IP filtering, copy actions, and safe table rendering.
 */

import { api } from './api.js';
import { Utils } from './utils.js';

export class TrafficController {
  constructor(app) {
    this.app = app;
    this.limit = 50;
    this.offset = 0;
    this.totalLoaded = 0;
    this.isLoading = false;
  }

  init() {
    this.bindEvents();
    this.loadTraffic();
  }

  bindEvents() {
    const btnApply = document.getElementById('btn-apply-traffic-filters');
    if (btnApply) {
      btnApply.addEventListener('click', () => {
        this.offset = 0;
        this.loadTraffic();
      });
    }

    const btnClear = document.getElementById('btn-clear-traffic-filters');
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        const protoSelect = document.getElementById('filter-traffic-protocol');
        const srcInput = document.getElementById('filter-traffic-src');
        const dstInput = document.getElementById('filter-traffic-dst');
        if (protoSelect) protoSelect.value = '';
        if (srcInput) srcInput.value = '';
        if (dstInput) dstInput.value = '';
        this.offset = 0;
        this.loadTraffic();
      });
    }

    const btnPrev = document.getElementById('btn-traffic-prev');
    if (btnPrev) {
      btnPrev.addEventListener('click', () => {
        if (this.offset >= this.limit) {
          this.offset -= this.limit;
          this.loadTraffic();
        }
      });
    }

    const btnNext = document.getElementById('btn-traffic-next');
    if (btnNext) {
      btnNext.addEventListener('click', () => {
        this.offset += this.limit;
        this.loadTraffic();
      });
    }

    const selectLimit = document.getElementById('select-traffic-limit');
    if (selectLimit) {
      selectLimit.addEventListener('change', (e) => {
        this.limit = parseInt(e.target.value, 10) || 50;
        this.offset = 0;
        this.loadTraffic();
      });
    }
  }

  /**
   * Fetch traffic records with active filters and render table.
   */
  async loadTraffic() {
    if (this.isLoading) return;
    this.isLoading = true;

    const tbody = document.getElementById('traffic-tbody');
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="empty-state">
            <div class="empty-state-title">Loading Traffic Records...</div>
          </td>
        </tr>`;
    }

    const proto = document.getElementById('filter-traffic-protocol')?.value || '';
    const src = document.getElementById('filter-traffic-src')?.value.trim() || '';
    const dst = document.getElementById('filter-traffic-dst')?.value.trim() || '';

    const params = {
      limit: this.limit,
      offset: this.offset,
    };
    if (proto) params.protocol = proto;
    if (src) params.source_ip = src;
    if (dst) params.destination_ip = dst;

    try {
      const res = await api.getTraffic(params);
      if (res.success) {
        this.totalLoaded = res.records ? res.records.length : 0;
        this.renderTable(res.records || []);
        this.updatePaginationUI();
      }
    } catch (err) {
      if (err.isAborted) return;
      if (tbody) {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" class="empty-state">
              <div class="empty-state-title" style="color:var(--color-critical);">Failed to Load Traffic</div>
              <div class="empty-state-desc">${Utils.escapeHTML(err.message)}</div>
            </td>
          </tr>`;
      }
    } finally {
      this.isLoading = false;
    }
  }

  renderTable(records) {
    const tbody = document.getElementById('traffic-tbody');
    if (!tbody) return;

    if (records.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="empty-state">
            <div class="empty-state-title">No Network Traffic Found</div>
            <div class="empty-state-desc">No records match the active criteria. Start live monitoring or upload a PCAP capture.</div>
          </td>
        </tr>`;
      return;
    }

    const rows = records.map((r) => {
      const srcPortStr = r.source_port !== null && r.source_port !== undefined ? `:${r.source_port}` : '';
      const dstPortStr = r.destination_port !== null && r.destination_port !== undefined ? `:${r.destination_port}` : '';
      const flagsStr = r.tcp_flags ? Utils.escapeHTML(r.tcp_flags) : '<span style="color:var(--text-muted);">-</span>';

      return `
        <tr>
          <td class="cell-mono">${Utils.formatDate(r.timestamp)}</td>
          <td class="cell-mono">
            <div class="cell-actions">
              <span>${Utils.escapeHTML(r.source_ip || '-')}</span>
              ${r.source_ip ? `<button class="btn-copy-ip" data-copy="${Utils.escapeHTML(r.source_ip)}" title="Copy IP"><i data-lucide="copy" style="width:12px;height:12px;"></i></button>` : ''}
            </div>
          </td>
          <td class="cell-mono">${Utils.escapeHTML(srcPortStr || '-')}</td>
          <td class="cell-mono">
            <div class="cell-actions">
              <span>${Utils.escapeHTML(r.destination_ip || '-')}</span>
              ${r.destination_ip ? `<button class="btn-copy-ip" data-copy="${Utils.escapeHTML(r.destination_ip)}" title="Copy IP"><i data-lucide="copy" style="width:12px;height:12px;"></i></button>` : ''}
            </div>
          </td>
          <td class="cell-mono">${Utils.escapeHTML(dstPortStr || '-')}</td>
          <td>${Utils.renderProtocolBadge(r.protocol)}</td>
          <td class="cell-mono">${Utils.formatBytes(r.packet_size)}</td>
          <td class="cell-mono">${flagsStr}</td>
        </tr>`;
    });

    tbody.innerHTML = rows.join('');

    // Attach copy actions
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

  updatePaginationUI() {
    const info = document.getElementById('traffic-pagination-info');
    const btnPrev = document.getElementById('btn-traffic-prev');
    const btnNext = document.getElementById('btn-traffic-next');

    if (info) {
      const start = this.offset + 1;
      const end = this.offset + this.totalLoaded;
      info.textContent = this.totalLoaded > 0 ? `Showing ${start} - ${end} records` : '0 records';
    }

    if (btnPrev) btnPrev.disabled = this.offset === 0;
    if (btnNext) btnNext.disabled = this.totalLoaded < this.limit;
  }
}
