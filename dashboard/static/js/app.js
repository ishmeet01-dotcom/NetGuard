/**
 * NetGuard Enterprise SOC Dashboard - Main Application Controller
 * Single-Page Application (SPA) navigation router, global clock, polling lifecycle,
 * mobile drawer management, and component coordination.
 */

import { DashboardController } from './dashboard.js';
import { MonitoringController } from './monitoring.js';
import { TrafficController } from './traffic.js';
import { ThreatsController } from './threats.js';
import { AlertsController } from './alerts.js';
import { HostsController } from './hosts.js';
import { PcapController } from './pcap.js';
import { HealthController } from './health.js';
import { Utils } from './utils.js';

class NetGuardApp {
  constructor() {
    this.currentView = 'view-overview';
    this.clockTimer = null;

    // Sub-controllers
    this.dashboardController = new DashboardController(this);
    this.monitoringController = new MonitoringController(this);
    this.trafficController = new TrafficController(this);
    this.threatsController = new ThreatsController(this);
    this.alertsController = new AlertsController(this);
    this.hostsController = new HostsController(this);
    this.pcapController = new PcapController(this);
    this.healthController = new HealthController(this);
  }

  async init() {
    this.initNavigation();
    this.initClock();
    this.initVisibilityHandling();
    this.initGlobalActions();

    // Initialize default view
    this.navigateTo('view-overview');

    // Initialize sub-controllers
    await this.dashboardController.init();
    await this.monitoringController.init();
    this.trafficController.init();
    await this.threatsController.init();
    this.alertsController.init();
    this.hostsController.init();
    this.pcapController.init();
    await this.healthController.init();

    // Refresh icons
    if (window.lucide && window.lucide.createIcons) {
      window.lucide.createIcons();
    }
  }

  /**
   * Bind sidebar and mobile drawer navigation triggers.
   */
  initNavigation() {
    const navItems = document.querySelectorAll('.sidebar .nav-item[data-view]');
    navItems.forEach((item) => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const viewId = item.getAttribute('data-view');
        if (viewId) {
          this.navigateTo(viewId);
          this.closeMobileSidebar();
        }
      });
    });

    // Mobile nav toggle & backdrop
    const toggleBtn = document.getElementById('btn-mobile-nav-toggle');
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');

    if (toggleBtn && sidebar && backdrop) {
      toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('mobile-open');
        backdrop.classList.toggle('active');
      });

      backdrop.addEventListener('click', () => {
        this.closeMobileSidebar();
      });
    }
  }

  closeMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (sidebar) sidebar.classList.remove('mobile-open');
    if (backdrop) backdrop.classList.remove('active');
  }

  /**
   * Switch between the 8 single-page views smoothly.
   */
  navigateTo(viewId) {
    this.currentView = viewId;

    // 1. Hide all views and show target view
    document.querySelectorAll('.content-view').forEach((v) => {
      v.classList.remove('active-view');
    });
    const targetView = document.getElementById(viewId);
    if (targetView) targetView.classList.add('active-view');

    // 2. Update active nav state in sidebar
    document.querySelectorAll('.sidebar .nav-item[data-view]').forEach((item) => {
      if (item.getAttribute('data-view') === viewId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // 3. Update breadcrumb and page title
    const viewTitles = {
      'view-overview': 'Overview Dashboard',
      'view-monitoring': 'Live Network Monitoring',
      'view-traffic': 'Network Traffic Records',
      'view-threats': 'Threat Intelligence',
      'view-alerts': 'Alert Management',
      'view-hosts': 'Host Monitoring',
      'view-pcap': 'PCAP Analyzer',
      'view-health': 'System Health & Diagnostics',
    };

    const breadcrumbEl = document.getElementById('breadcrumb-current');
    if (breadcrumbEl) {
      breadcrumbEl.textContent = viewTitles[viewId] || 'Overview';
    }

    // 4. Optimize polling intervals according to active view
    if (viewId === 'view-overview') {
      this.dashboardController.startPolling(3000);
      this.dashboardController.refresh();
    } else {
      this.dashboardController.stopPolling();
    }

    if (viewId === 'view-monitoring') {
      this.monitoringController.refreshStatus();
    } else if (viewId === 'view-traffic') {
      this.trafficController.loadTraffic();
    } else if (viewId === 'view-threats') {
      this.threatsController.loadThreats();
    } else if (viewId === 'view-alerts') {
      this.alertsController.loadAlerts();
    } else if (viewId === 'view-hosts') {
      this.hostsController.loadHosts();
    } else if (viewId === 'view-health') {
      this.healthController.startPolling(5000);
      this.healthController.refresh();
    } else {
      this.healthController.stopPolling();
    }

    // Refresh icons inside dynamically rendered panels
    if (window.lucide && window.lucide.createIcons) {
      window.lucide.createIcons();
    }
  }

  /**
   * Top bar real-time UTC/local clock.
   */
  initClock() {
    const clockEl = document.getElementById('system-clock');
    if (!clockEl) return;

    const updateClock = () => {
      const now = new Date();
      const timeStr = now.toISOString().replace('T', ' ').substring(0, 19);
      clockEl.textContent = `${timeStr} UTC`;
    };
    updateClock();
    this.clockTimer = setInterval(updateClock, 1000);
  }

  /**
   * Pause polling when tab is hidden to save CPU/network resources.
   */
  initVisibilityHandling() {
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.dashboardController.stopPolling();
        this.monitoringController.stopPolling();
        this.healthController.stopPolling();
      } else {
        if (this.currentView === 'view-overview') {
          this.dashboardController.startPolling(3000);
          this.dashboardController.refresh();
        } else if (this.currentView === 'view-health') {
          this.healthController.startPolling(5000);
          this.healthController.refresh();
        }
        if (this.monitoringController.isMonitoring) {
          this.monitoringController.startPolling(1500);
        }
      }
    });
  }

  /**
   * Topbar global manual refresh action.
   */
  initGlobalActions() {
    const btnRefresh = document.getElementById('btn-global-refresh');
    if (btnRefresh) {
      btnRefresh.addEventListener('click', async () => {
        btnRefresh.classList.add('rotating');
        if (this.currentView === 'view-overview') {
          await this.dashboardController.refresh();
        } else if (this.currentView === 'view-monitoring') {
          await this.monitoringController.refreshStatus();
        } else if (this.currentView === 'view-traffic') {
          await this.trafficController.loadTraffic();
        } else if (this.currentView === 'view-threats') {
          await this.threatsController.loadThreats();
        } else if (this.currentView === 'view-alerts') {
          await this.alertsController.loadAlerts();
        } else if (this.currentView === 'view-hosts') {
          await this.hostsController.loadHosts();
        } else if (this.currentView === 'view-health') {
          await this.healthController.refresh();
        }
        Utils.showToast('Data refreshed', 'info', 1500);
        setTimeout(() => btnRefresh.classList.remove('rotating'), 500);
      });
    }
  }

  /**
   * Update global badges when monitor state changes.
   */
  updateGlobalMonitorState(m) {
    const topPill = document.getElementById('topbar-monitor-pill');
    const sideDot = document.getElementById('sidebar-engine-dot');
    const sideText = document.getElementById('sidebar-engine-state');

    if (m.is_monitoring) {
      if (topPill) {
        topPill.className = 'indicator-pill capturing';
        topPill.innerHTML = '<span class="status-dot capturing"></span><span>CAPTURING LIVE</span>';
      }
      if (sideDot) sideDot.className = 'status-dot capturing';
      if (sideText) sideText.textContent = 'Sniffing Active';
    } else {
      if (topPill) {
        topPill.className = 'indicator-pill idle';
        topPill.innerHTML = '<span class="status-dot standby"></span><span>MONITOR IDLE</span>';
      }
      if (sideDot) sideDot.className = 'status-dot standby';
      if (sideText) sideText.textContent = 'Standby (Opt-in)';
    }
  }
}

// Bootstrap application on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  window.app = new NetGuardApp();
  window.app.init();
});
