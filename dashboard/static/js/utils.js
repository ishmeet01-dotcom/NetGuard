/**
 * NetGuard Enterprise SOC Dashboard - Utilities & Helper Functions
 * Provides safe text formatting, DOM manipulation, clipboard access, and toast notifications.
 */

export const Utils = {
  /**
   * Safely escape HTML to prevent XSS attacks when rendering dynamic strings.
   */
  escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  /**
   * Format byte count into human-readable unit (B, KB, MB, GB).
   */
  formatBytes(bytes, decimals = 2) {
    if (!bytes || isNaN(bytes) || bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  },

  /**
   * Format integer numbers with locale commas.
   */
  formatNumber(num) {
    if (num === null || num === undefined || isNaN(num)) return '0';
    return Number(num).toLocaleString();
  },

  /**
   * Format UNIX epoch timestamp into human-readable UTC or local datetime.
   */
  formatDate(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp * 1000);
    if (isNaN(date.getTime())) return 'Invalid date';
    return date.toISOString().replace('T', ' ').substring(0, 19);
  },

  /**
   * Format duration in seconds into HH:MM:SS or DD:HH:MM:SS.
   */
  formatDuration(seconds) {
    if (!seconds || isNaN(seconds) || seconds < 0) return '00:00:00';
    const sec = Math.floor(seconds);
    const hrs = Math.floor(sec / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    const secs = sec % 60;
    const pad = (n) => String(n).padStart(2, '0');
    if (hrs >= 24) {
      const days = Math.floor(hrs / 24);
      const remHrs = hrs % 24;
      return `${days}d ${pad(remHrs)}:${pad(mins)}:${pad(secs)}`;
    }
    return `${pad(hrs)}:${pad(mins)}:${pad(secs)}`;
  },

  /**
   * Copy plain text to user's system clipboard and notify.
   */
  async copyToClipboard(text, label = 'Copied') {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      this.showToast(`${label}: ${text}`, 'info', 2500);
      return true;
    } catch (err) {
      this.showToast('Failed to copy to clipboard', 'error');
      return false;
    }
  },

  /**
   * Display a non-intrusive toast notification.
   */
  showToast(message, type = 'info', duration = 3500) {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const iconSpan = document.createElement('span');
    iconSpan.style.display = 'inline-flex';
    iconSpan.style.alignItems = 'center';
    
    let iconName = 'info';
    if (type === 'success') iconName = 'check-circle';
    if (type === 'error') iconName = 'alert-triangle';
    if (type === 'warning') iconName = 'alert-circle';
    iconSpan.innerHTML = `<i data-lucide="${iconName}" style="width:16px;height:16px;"></i>`;

    const textSpan = document.createElement('span');
    textSpan.style.flex = '1';
    textSpan.textContent = message;

    toast.appendChild(iconSpan);
    toast.appendChild(textSpan);
    container.appendChild(toast);

    if (window.lucide && window.lucide.createIcons) {
      window.lucide.createIcons({ root: toast });
    }

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => {
        if (toast.parentElement) toast.parentElement.removeChild(toast);
      }, 250);
    }, duration);
  },

  /**
   * Generate standardized HTML badge for alert severities.
   */
  renderSeverityBadge(severity) {
    const sev = String(severity || 'LOW').toUpperCase();
    let badgeClass = 'badge-sev-low';
    if (sev === 'CRITICAL') badgeClass = 'badge-sev-critical';
    else if (sev === 'HIGH') badgeClass = 'badge-sev-high';
    else if (sev === 'MEDIUM') badgeClass = 'badge-sev-medium';
    return `<span class="badge ${badgeClass}">${this.escapeHTML(sev)}</span>`;
  },

  /**
   * Generate standardized HTML badge for alert investigation statuses.
   */
  renderStatusBadge(status) {
    const st = String(status || 'NEW').toUpperCase();
    let badgeClass = 'badge-status-new';
    if (st === 'INVESTIGATING') badgeClass = 'badge-status-investigating';
    else if (st === 'RESOLVED') badgeClass = 'badge-status-resolved';
    else if (st === 'FALSE_POSITIVE') badgeClass = 'badge-status-fp';
    return `<span class="badge ${badgeClass}">${this.escapeHTML(st)}</span>`;
  },

  /**
   * Generate standardized HTML badge for network protocols.
   */
  renderProtocolBadge(protocol) {
    const proto = String(protocol || 'OTHER').toUpperCase();
    let protoClass = 'badge-proto';
    if (proto === 'TCP') protoClass += ' badge-proto-tcp';
    else if (proto === 'UDP') protoClass += ' badge-proto-udp';
    else if (proto === 'ICMP') protoClass += ' badge-proto-icmp';
    else if (proto === 'ARP') protoClass += ' badge-proto-arp';
    return `<span class="${protoClass}">${this.escapeHTML(proto)}</span>`;
  }
};
