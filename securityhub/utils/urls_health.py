"""
Health Check URL Configuration

Routes for health check endpoints.
Created for Issue #23 (Phase 3)
"""

from django.urls import path
from utils.views_health import health_live, health_ready, health_detail, ping

urlpatterns = [
    # Modern health check endpoints
    path('live/', health_live, name='health-live'),      # Liveness probe
    path('ready/', health_ready, name='health-ready'),    # Readiness probe
    path('', health_detail, name='health-detail'),        # Detailed health check
    
    # Legacy endpoint (backward compatibility)
    path('ping/', ping, name='health-ping'),              # Deprecated
]


