/**
 * NetGuard Enterprise SOC Dashboard - Centralized API Service
 * Encapsulates all backend HTTP interactions with error normalization,
 * abort handling, query string serialization, and timeout controls.
 */

export class ApiClient {
  constructor(baseUrl = '') {
    this.baseUrl = baseUrl;
    this.activeControllers = new Map();
  }

  /**
   * Internal fetch wrapper supporting timeouts and JSON/error handling.
   */
  async request(endpoint, options = {}, abortKey = null) {
    if (abortKey && this.activeControllers.has(abortKey)) {
      this.activeControllers.get(abortKey).abort();
    }

    const controller = new AbortController();
    if (abortKey) {
      this.activeControllers.set(abortKey, controller);
    }

    const timeout = options.timeout || 15000;
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const headers = options.headers || {};
    if (!(options.body instanceof FormData)) {
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      headers['Accept'] = 'application/json';
    }

    const config = {
      ...options,
      headers,
      signal: controller.signal,
    };

    try {
      const url = `${this.baseUrl}${endpoint}`;
      const response = await fetch(url, config);
      clearTimeout(timeoutId);

      let data;
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = { success: response.ok, raw: await response.text() };
      }

      if (!response.ok) {
        const errorMsg = data.error || data.message || `Request failed with status ${response.status}`;
        const error = new Error(errorMsg);
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        err.isAborted = true;
      }
      throw err;
    } finally {
      if (abortKey) {
        this.activeControllers.delete(abortKey);
      }
    }
  }

  /**
   * Helper to serialize URL query parameters.
   */
  buildQuery(params = {}) {
    const searchParams = new URLSearchParams();
    for (const [key, val] of Object.entries(params)) {
      if (val !== undefined && val !== null && val !== '') {
        searchParams.append(key, val);
      }
    }
    const qs = searchParams.toString();
    return qs ? `?${qs}` : '';
  }

  // --- Endpoints ---

  async getStatus() {
    return this.request('/api/status', { method: 'GET' }, 'status');
  }

  async getInterfaces() {
    return this.request('/api/interfaces', { method: 'GET' });
  }

  async startMonitoring(iface = null, bpfFilter = '') {
    return this.request('/api/monitor/start', {
      method: 'POST',
      body: JSON.stringify({ interface: iface, filter: bpfFilter }),
    });
  }

  async stopMonitoring() {
    return this.request('/api/monitor/stop', {
      method: 'POST',
    });
  }

  async getMonitorStatus() {
    return this.request('/api/monitor/status', { method: 'GET' }, 'monitor-status');
  }

  async getStatistics() {
    return this.request('/api/statistics', { method: 'GET' }, 'stats');
  }

  async getStatisticsHistory(limit = 50) {
    return this.request(`/api/statistics/history?limit=${encodeURIComponent(limit)}`, { method: 'GET' }, 'stats-history');
  }

  async getTraffic(params = {}) {
    const qs = this.buildQuery(params);
    return this.request(`/api/traffic${qs}`, { method: 'GET' }, 'traffic');
  }

  async getAlerts(params = {}) {
    const qs = this.buildQuery(params);
    return this.request(`/api/alerts${qs}`, { method: 'GET' }, 'alerts');
  }

  async getAlertDetail(alertId) {
    return this.request(`/api/alerts/${encodeURIComponent(alertId)}`, { method: 'GET' });
  }

  async updateAlertStatus(alertId, newStatus) {
    return this.request(`/api/alerts/${encodeURIComponent(alertId)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status: newStatus }),
    });
  }

  async getHosts(params = {}) {
    const qs = this.buildQuery(params);
    return this.request(`/api/hosts${qs}`, { method: 'GET' }, 'hosts');
  }

  async uploadPCAP(file, onProgress = null) {
    const formData = new FormData();
    formData.append('file', file);

    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${this.baseUrl}/api/analyze/pcap`);

      if (onProgress && xhr.upload) {
        xhr.upload.onprogress = (evt) => {
          if (evt.lengthComputable) {
            const percent = Math.round((evt.loaded / evt.total) * 100);
            onProgress(percent);
          }
        };
      }

      xhr.onload = () => {
        let jsonResponse;
        try {
          jsonResponse = JSON.parse(xhr.responseText);
        } catch (e) {
          jsonResponse = { success: false, error: 'Invalid response from server' };
        }

        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(jsonResponse);
        } else {
          const err = new Error(jsonResponse.error || `Upload failed with HTTP ${xhr.status}`);
          err.status = xhr.status;
          err.data = jsonResponse;
          reject(err);
        }
      };

      xhr.onerror = () => {
        reject(new Error('Network error during PCAP upload.'));
      };

      xhr.send(formData);
    });
  }
}

export const api = new ApiClient();
