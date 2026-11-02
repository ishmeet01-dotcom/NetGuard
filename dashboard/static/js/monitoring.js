/**
 * NetGuard Enterprise SOC Dashboard - Live Monitoring Controller
 * Manages interface enumeration, BPF capture filters, start/stop flows with confirmation,
 * and high-frequency real-time metrics telemetry.
 */

import { api } from './api.js';
import { Utils } from './utils.js';

export class MonitoringController {
  constructor(app) {
    this.app = app;
    this.pollTimer = null;
    this.isMonitoring = false;
    this.interfacesLoaded = false;
    this.selectedInterface = null;
  }

  async init() {
    this.bindEvents();
    await this.loadInterfaces();
    await this.refreshStatus();
  }

  bindEvents() {
    // Start Monitoring Button
    const btnStart = document.getElementById('btn-start-monitor');
    if (btnStart) {
      btnStart.addEventListener('click', () => this.handleStartMonitoring());
    }

    // Stop Monitoring Button (opens confirmation modal)
    const btnStop = document.getElementById('btn-stop-monitor');
    if (btnStop) {
      btnStop.addEventListener('click', () => this.openStopConfirmModal());
    }

    // Modal Confirm Stop Button
    const btnConfirmStop = document.getElementById('btn-modal-confirm-stop');
    if (btnConfirmStop) {
      btnConfirmStop.addEventListener('click', () => this.handleStopMonitoring());
    }

    // Modal Cancel Buttons
    const modal = document.getElementById('modal-stop-monitor');
    if (modal) {
      modal.querySelectorAll('.modal-close-trigger').forEach((el) => {
        el.addEventListener('click', () => {
          modal.classList.remove('active');
        });
      });
    }

    // BPF Example Pills
    document.querySelectorAll('.bpf-example-pill').forEach((pill) => {
      pill.addEventListener('click', (e) => {
        const filterVal = e.target.getAttribute('data-filter') || '';
        const input = document.getElementById('input-bpf-filter');
        if (input) input.value = filterVal;
      });
    });
  }

  /**
   * Fetch available network interfaces and populate selector.
   */
  async loadInterfaces() {
    if (this.interfacesLoaded) return;
    const select = document.getElementById('select-interface');
    if (!select) return;

    try {
      const res = await api.getInterfaces();
      if (res.success && res.interfaces) {
        select.innerHTML = '<option value="">-- Default Interface (Auto-Detect) --</option>';
        res.interfaces.forEach((iface) => {
          const opt = document.createElement('option');
          opt.value = iface.id;
          const ipDesc = iface.ip ? ` [${iface.ip}]` : '';
          opt.textContent = `${iface.name}${ipDesc} (${iface.description || iface.id})`;
          select.appendChild(opt);
        });
        this.interfacesLoaded = true;
      }
    } catch (err) {
      console.error('Failed to load network interfaces:', err);
      select.innerHTML = '<option value="">Error loading interfaces</option>';
    }
  }

  /**
   * Start capture session on selected interface.
   */
  async handleStartMonitoring() {
    const btnStart = document.getElementById('btn-start-monitor');
    const select = document.getElementById('select-interface');
    const bpfInput = document.getElementById('input-bpf-filter');

    const ifaceVal = select ? select.value : null;
    const bpfVal = bpfInput ? bpfInput.value.trim() : '';

    if (btnStart) btnStart.disabled = true;

    try {
      const res = await api.startMonitoring(ifaceVal || null, bpfVal);
      if (res.success) {
        Utils.showToast(`Monitoring started on ${res.interface || 'default adapter'}`, 'success');
        this.isMonitoring = true;
        await this.refreshStatus();
        this.startPolling(1500);
      }
    } catch (err) {
      Utils.showToast(err.message || 'Failed to start monitoring', 'error');
    } finally {
      if (btnStart) btnStart.disabled = false;
    }
  }

  /**
   * Open confirmation dialog before terminating live session.
   */
  openStopConfirmModal() {
    const modal = document.getElementById('modal-stop-monitor');
    if (modal) {
      modal.classList.add('active');
    }
  }

  /**
   * Stop capture session.
   */
  async handleStopMonitoring() {
    const modal = document.getElementById('modal-stop-monitor');
    if (modal) modal.classList.remove('active');

    const btnStop = document.getElementById('btn-stop-monitor');
    if (btnStop) btnStop.disabled = true;

    try {
      const res = await api.stopMonitoring();
      if (res.success) {
        Utils.showToast('Monitoring stopped cleanly.', 'info');
        this.isMonitoring = false;
        await this.refreshStatus();
        this.stopPolling();
      }
    } catch (err) {
      Utils.showToast(err.message || 'Failed to stop monitoring', 'error');
    } finally {
      if (btnStop) btnStop.disabled = false;
    }
  }

  /**
   * Query /api/monitor/status and update real-time telemetry elements.
   */
  async refreshStatus() {
    try {
      const res = await api.getMonitorStatus();
      if (res.success && res.data) {
        const m = res.data;
        this.isMonitoring = m.is_monitoring;
        this.updateUI(m);
        this.app.updateGlobalMonitorState(m);
      }
    } catch (err) {
      console.warn('Could not retrieve monitor status:', err);
    }
  }

  /**
   * Update all DOM elements on the live monitoring page.
   */
  updateUI(m) {
    const btnStart = document.getElementById('btn-start-monitor');
    const btnStop = document.getElementById('btn-stop-monitor');
    const select = document.getElementById('select-interface');
    const bpfInput = document.getElementById('input-bpf-filter');

    // Controls state
    if (btnStart) btnStart.disabled = m.is_monitoring;
    if (btnStop) btnStop.disabled = !m.is_monitoring;
    if (select) select.disabled = m.is_monitoring;
    if (bpfInput) bpfInput.disabled = m.is_monitoring;

    // Hero title & badge
    const stateTitle = document.getElementById('monitor-hero-state');
    const stateMeta = document.getElementById('monitor-hero-meta');
    const heroDot = document.getElementById('monitor-hero-dot');

    if (stateTitle) {
      stateTitle.textContent = m.is_monitoring ? 'Capturing Live Network Traffic' : 'Monitoring Stopped (Standby)';
    }
    if (heroDot) {
      heroDot.className = `status-dot ${m.is_monitoring ? 'capturing' : 'standby'}`;
    }
    if (stateMeta) {
      const ifaceLabel = m.interface ? `Interface: ${m.interface}` : 'Interface: Auto-Detect';
      const filterLabel = m.bpf_filter ? ` | Filter: "${m.bpf_filter}"` : '';
      stateMeta.textContent = `${ifaceLabel}${filterLabel}`;
    }

    // Telemetry metric boxes
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setVal('mon-metric-uptime', Utils.formatDuration(m.uptime_seconds || 0));
    setVal('mon-metric-pkts', Utils.formatNumber(m.total_packets || 0));
    setVal('mon-metric-bytes', Utils.formatBytes(m.total_bytes || 0));
    setVal('mon-metric-pps', Utils.formatNumber(Math.round(m.current_pps || 0)));
    setVal('mon-metric-bps', `${Utils.formatBytes(Math.round(m.current_bps || 0))}/s`);

    const protos = m.protocol_counts || {};
    setVal('mon-metric-tcp', Utils.formatNumber(protos.TCP || 0));
    setVal('mon-metric-udp', Utils.formatNumber(protos.UDP || 0));
    setVal('mon-metric-icmp', Utils.formatNumber(protos.ICMP || 0));
    setVal('mon-metric-arp', Utils.formatNumber(protos.ARP || 0));

    setVal('mon-metric-srcs', Utils.formatNumber(m.active_sources_count || 0));
    setVal('mon-metric-dsts', Utils.formatNumber(m.active_destinations_count || 0));
    setVal('mon-metric-threats', Utils.formatNumber(m.detected_threats || 0));
    setVal('mon-metric-alerts', Utils.formatNumber(m.generated_alerts || 0));
    setVal('mon-metric-dropped', Utils.formatNumber(m.dropped_packets || 0));
    setVal('mon-metric-queue', `${m.queue_size || 0} / ${m.queue_capacity || 10000}`);
  }

  startPolling(intervalMs = 1500) {
    this.stopPolling();
    this.pollTimer = setInterval(() => {
      this.refreshStatus();
    }, intervalMs);
  }

  stopPolling() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }
}
