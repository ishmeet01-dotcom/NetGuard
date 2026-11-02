"""
NetGuard Dashboard Package
Provides Flask web application factory and REST API blueprint.
"""

from dashboard.app import create_app

__all__ = ["create_app"]
