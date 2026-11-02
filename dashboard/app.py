"""
NetGuard Flask Application Factory
Builds the Flask application with registered API blueprints and dependency injection.
"""

from typing import Optional
from pathlib import Path
from flask import Flask, jsonify, render_template, request

from config import (
    SERVER_HOST,
    SERVER_PORT,
    DEBUG_MODE,
    MAX_PCAP_UPLOAD_BYTES,
    DB_PATH,
)
from database.db import DatabaseManager
from capture.monitor_manager import MonitorManager, get_monitor_manager
from dashboard.routes import api_bp


def create_app(
    db_manager: Optional[DatabaseManager] = None,
    monitor_manager: Optional[MonitorManager] = None,
) -> Flask:
    """
    Construct and configure the NetGuard Flask web application.
    Supports injecting DatabaseManager and MonitorManager for isolated testing.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # Server configuration
    app.config["HOST"] = SERVER_HOST
    app.config["PORT"] = SERVER_PORT
    app.config["DEBUG"] = DEBUG_MODE
    app.config["MAX_CONTENT_LENGTH"] = MAX_PCAP_UPLOAD_BYTES + (1024 * 1024)

    # Dependency injection
    db = db_manager or DatabaseManager(db_path=DB_PATH)
    monitor = monitor_manager or get_monitor_manager(db_manager=db)

    app.config["DB_MANAGER"] = db
    app.config["MONITOR_MANAGER"] = monitor

    # Register API blueprint
    app.register_blueprint(api_bp)

    # JSON Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"success": False, "error": "Bad request", "details": str(error)}), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"success": False, "error": "Resource not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({"success": False, "error": "Method not allowed"}), 405

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({"success": False, "error": "Uploaded file is too large"}), 413

    @app.errorhandler(500)
    def internal_server_error(error):
        return jsonify({"success": False, "error": "Internal server error"}), 500

    @app.route("/")
    def index():
        """Serve the Enterprise SOC Dashboard frontend or JSON info when requested."""
        if request.args.get("format") == "json" or request.headers.get("Accept") == "application/json":
            return jsonify({
                "name": "NetGuard NIDS",
                "version": "1.0.0",
                "status": "ready",
                "api_documentation": "/api/status",
            })
        try:
            return render_template("index.html")
        except Exception:
            return jsonify({
                "name": "NetGuard NIDS",
                "version": "1.0.0",
                "status": "ready",
                "api_documentation": "/api/status",
            })

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=DEBUG_MODE)
