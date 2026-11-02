/**
 * NetGuard Enterprise SOC Dashboard - Offline PCAP Analyzer Controller
 * Coordinates drag-and-drop capture uploads, size & extension validations,
 * upload progress telemetry, and rich analysis report generation.
 */

import { api } from './api.js';
import { Utils } from './utils.js';

export class PcapController {
  constructor(app) {
    this.app = app;
    this.selectedFile = null;
    this.isUploading = false;
  }

  init() {
    this.bindEvents();
  }

  bindEvents() {
    const dropzone = document.getElementById('pcap-dropzone');
    const fileInput = document.getElementById('input-pcap-file');
    const btnUpload = document.getElementById('btn-start-pcap-upload');
    const btnSelect = document.getElementById('btn-browse-pcap');

    if (btnSelect && fileInput) {
      btnSelect.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
      });
    }

    if (dropzone && fileInput) {
      dropzone.addEventListener('click', () => fileInput.click());

      dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      });

      dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
      });

      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          this.handleFileSelected(e.dataTransfer.files[0]);
        }
      });

      fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          this.handleFileSelected(e.target.files[0]);
        }
      });
    }

    if (btnUpload) {
      btnUpload.addEventListener('click', () => this.handleUpload());
    }
  }

  handleFileSelected(file) {
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    const validExts = ['.pcap', '.pcapng', '.cap'];

    if (!validExts.includes(ext)) {
      Utils.showToast(`Invalid file extension '${ext}'. Allowed: .pcap, .pcapng, .cap`, 'error');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      Utils.showToast(`File size (${Utils.formatBytes(file.size)}) exceeds maximum limit of 10MB.`, 'error');
      return;
    }

    this.selectedFile = file;

    const fileMeta = document.getElementById('pcap-selected-file-meta');
    const fileNameEl = document.getElementById('pcap-selected-filename');
    const fileSizeEl = document.getElementById('pcap-selected-filesize');
    const btnUpload = document.getElementById('btn-start-pcap-upload');

    if (fileMeta) fileMeta.style.display = 'flex';
    if (fileNameEl) fileNameEl.textContent = file.name;
    if (fileSizeEl) fileSizeEl.textContent = Utils.formatBytes(file.size);
    if (btnUpload) btnUpload.disabled = false;
  }

  async handleUpload() {
    if (!this.selectedFile || this.isUploading) return;
    this.isUploading = true;

    const btnUpload = document.getElementById('btn-start-pcap-upload');
    const progressContainer = document.getElementById('pcap-upload-progress');
    const progressFill = document.getElementById('pcap-progress-fill');
    const resultsPanel = document.getElementById('pcap-results-panel');

    if (btnUpload) btnUpload.disabled = true;
    if (progressContainer) progressContainer.style.display = 'block';
    if (progressFill) progressFill.style.width = '0%';
    if (resultsPanel) resultsPanel.style.display = 'none';

    try {
      const res = await api.uploadPCAP(this.selectedFile, (percent) => {
        if (progressFill) progressFill.style.width = `${percent}%`;
      });

      if (res.success) {
        Utils.showToast(`PCAP analysis completed: ${res.total_packets} packets processed`, 'success');
        this.renderResults(res);
        // Refresh overview counts in background
        if (this.app && this.app.dashboardController) {
          this.app.dashboardController.refresh();
        }
      }
    } catch (err) {
      Utils.showToast(err.message || 'PCAP analysis failed', 'error');
    } finally {
      this.isUploading = false;
      if (btnUpload) btnUpload.disabled = false;
      if (progressContainer) progressContainer.style.display = 'none';
    }
  }

  renderResults(data) {
    const resultsPanel = document.getElementById('pcap-results-panel');
    if (!resultsPanel) return;
    resultsPanel.style.display = 'block';

    const summary = data.summary || {};
    const protos = data.protocols || {};

    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setVal('pcap-res-filename', data.filename || 'capture.pcap');
    setVal('pcap-res-packets', Utils.formatNumber(data.total_packets || 0));
    setVal('pcap-res-duration', `${(data.traffic_duration_seconds || 0).toFixed(3)}s`);
    setVal('pcap-res-bytes', Utils.formatBytes(summary.total_bytes || 0));
    setVal('pcap-res-pps', Utils.formatNumber(Math.round(summary.packets_per_second || 0)));
    setVal('pcap-res-threats', Utils.formatNumber(data.detected_threats_count || 0));

    // Protocol Breakdown Pills
    const protoContainer = document.getElementById('pcap-res-protocols');
    if (protoContainer) {
      const pills = Object.entries(protos).map(([k, v]) => {
        return `<span class="badge badge-proto" style="padding:4px 8px;font-size:11px;">${Utils.escapeHTML(k)}: <strong>${v}</strong></span>`;
      });
      protoContainer.innerHTML = pills.join(' ') || '<span style="color:var(--text-muted);">None</span>';
    }

    // Render Generated Alerts Table
    const tbody = document.getElementById('pcap-alerts-tbody');
    if (tbody) {
      const alerts = data.alerts || [];
      if (alerts.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="empty-state">
              <div class="empty-state-title" style="color:var(--color-success);">Clean Capture</div>
              <div class="empty-state-desc">No security threats were identified in this PCAP file.</div>
            </td>
          </tr>`;
      } else {
        const rows = alerts.map((a) => `
          <tr>
            <td class="cell-mono cell-strong">${Utils.escapeHTML(a.alert_id)}</td>
            <td><span class="cell-strong">${Utils.escapeHTML(a.threat_type)}</span></td>
            <td class="cell-mono">${Utils.escapeHTML(a.source_ip)}</td>
            <td class="cell-mono">${Utils.escapeHTML(a.destination_ip)}</td>
            <td>${Utils.renderSeverityBadge(a.severity)}</td>
            <td class="cell-mono">${Math.round(a.risk_score || 0)}/100</td>
          </tr>`);
        tbody.innerHTML = rows.join('');
      }
    }

    // Scroll smoothly to results
    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}
