"""
NetGuard Unit & Integration Tests - SOC Dashboard Frontend
Validates template serving, static asset delivery, content negotiation,
single-page view structures, and frontend API endpoints.
"""

import pytest
from pathlib import Path
from dashboard.app import create_app
from database.db import DatabaseManager
from capture.monitor_manager import MonitorManager


@pytest.fixture
def dashboard_client(tmp_path):
    """Fixture providing Flask test client configured with isolated database."""
    test_db = DatabaseManager(db_path=tmp_path / "frontend_test.db")
    monitor = MonitorManager(db_manager=test_db)
    app = create_app(db_manager=test_db, monitor_manager=monitor)
    app.config["TESTING"] = True
    return app.test_client()


class TestDashboardFrontend:
    """Verifies that the Flask web application serves the enterprise SOC frontend correctly."""

    def test_root_serves_html_dashboard_by_default(self, dashboard_client):
        """Confirm GET / returns HTML5 Enterprise SOC dashboard with HTTP 200."""
        res = dashboard_client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.content_type
        content = res.get_data(as_text=True)
        assert "<!DOCTYPE html>" in content
        assert "NetGuard — Enterprise Security Operations Center (SOC)" in content
        assert "NETGUARD" in content

    def test_all_eight_single_page_views_exist_in_template(self, dashboard_client):
        """Verify template defines all 8 single-page application views."""
        res = dashboard_client.get("/")
        content = res.get_data(as_text=True)

        expected_views = [
            'id="view-overview"',
            'id="view-monitoring"',
            'id="view-traffic"',
            'id="view-threats"',
            'id="view-alerts"',
            'id="view-hosts"',
            'id="view-pcap"',
            'id="view-health"',
        ]
        for v in expected_views:
            assert v in content, f"Missing view container in template: {v}"

    def test_alert_drawer_and_modal_present_in_template(self, dashboard_client):
        """Verify modal dialogs and slideout drawer elements are rendered."""
        res = dashboard_client.get("/")
        content = res.get_data(as_text=True)

        assert 'id="alert-detail-drawer"' in content
        assert 'id="modal-stop-monitor"' in content
        assert 'id="pcap-dropzone"' in content
        assert 'id="select-interface"' in content
        assert 'id="input-bpf-filter"' in content

    def test_root_content_negotiation_returns_json_when_requested(self, dashboard_client):
        """Verify GET / returns JSON metadata when Accept: application/json header is sent."""
        res = dashboard_client.get("/", headers={"Accept": "application/json"})
        assert res.status_code == 200
        assert "application/json" in res.content_type
        data = res.get_json()
        assert data["name"] == "NetGuard NIDS"
        assert data["status"] == "ready"

    def test_static_stylesheets_are_accessible(self, dashboard_client):
        """Verify static CSS stylesheets are served with HTTP 200."""
        css_files = [
            "/static/css/style.css",
            "/static/css/components.css",
            "/static/css/responsive.css",
        ]
        for url in css_files:
            res = dashboard_client.get(url)
            assert res.status_code == 200, f"Failed to retrieve CSS asset: {url}"
            assert len(res.data) > 100

    def test_static_javascript_modules_are_accessible(self, dashboard_client):
        """Verify static JavaScript modules and vendor bundles are served with HTTP 200."""
        js_files = [
            "/static/js/app.js",
            "/static/js/api.js",
            "/static/js/charts.js",
            "/static/js/dashboard.js",
            "/static/js/monitoring.js",
            "/static/js/traffic.js",
            "/static/js/threats.js",
            "/static/js/alerts.js",
            "/static/js/hosts.js",
            "/static/js/pcap.js",
            "/static/js/health.js",
            "/static/js/utils.js",
            "/static/vendor/chart.umd.js",
            "/static/vendor/lucide.js",
        ]
        for url in js_files:
            res = dashboard_client.get(url)
            assert res.status_code == 200, f"Failed to retrieve JS asset: {url}"
            assert len(res.data) > 50

    def test_hosts_search_query_parameter(self, dashboard_client):
        """Verify GET /api/hosts supports search query parameter."""
        res = dashboard_client.get("/api/hosts?search=192.168")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert isinstance(data["hosts"], list)

    def test_most_observed_hosts_terminology(self, dashboard_client):
        """Verify the host activity visualization uses accurate 'Most Observed Hosts' wording."""
        res = dashboard_client.get("/")
        content = res.get_data(as_text=True)
        assert "Most Observed Hosts" in content
        assert "Endpoints with highest packet observation frequency" in content

    def test_threat_attribution_evidence_based_terminology(self, dashboard_client):
        """Verify threat intelligence uses evidence-based 'Suspicious Source IP' rather than 'Attacker IP'."""
        res = dashboard_client.get("/")
        content = res.get_data(as_text=True)
        assert "Suspicious Source IP" in content
        assert "Attacker IP" not in content
