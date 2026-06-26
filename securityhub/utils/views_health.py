"""
Health Check Views

API endpoints for application health monitoring.
Provides liveness, readiness, and detailed health checks.

Created for Issue #23 (Phase 3)
"""

import logging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from utils.health_check import HealthCheckService, get_health_status

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([AllowAny])
def health_live(request):
    """
    Liveness probe endpoint.
    
    Returns a simple 200 OK if the application is running.
    Used by Kubernetes/Docker to determine if the container should be restarted.
    
    **No authentication required** - this is a health check endpoint.
    
    **Example**:
        GET /api/health/live/
        
    **Response**:
        {
            "status": "alive",
            "service": "SecurityHub API",
            "timestamp": 1703520000.123
        }
    """
    health_data = HealthCheckService.liveness_check()
    return Response(health_data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def health_ready(request):
    """
    Readiness probe endpoint.
    
    Checks if the application is ready to serve traffic.
    Verifies database and cache connectivity.
    Used by load balancers to determine routing.
    
    **No authentication required** - this is a health check endpoint.
    
    **Example**:
        GET /api/health/ready/
        
    **Response** (Ready):
        {
            "status": "ready",
            "service": "SecurityHub API",
            "timestamp": 1703520000.123,
            "checks": {
                "database": {
                    "healthy": true,
                    "message": "Database connection successful",
                    "response_time_ms": 2.34
                },
                "cache": {
                    "healthy": true,
                    "message": "Cache connection successful",
                    "response_time_ms": 1.23
                }
            }
        }
        
    **Response** (Not Ready):
        HTTP 503 Service Unavailable
        {
            "status": "not_ready",
            ...
        }
    """
    health_data = HealthCheckService.readiness_check()
    
    # Return 503 if not ready
    if health_data['status'] == 'not_ready':
        return Response(health_data, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    
    return Response(health_data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def health_detail(request):
    """
    Detailed health check endpoint.
    
    Provides comprehensive status of all application components:
    - Database (PostgreSQL)
    - Cache

    Includes response times and detailed metrics.
    
    **No authentication required** - this is a health check endpoint.
    
    **Example**:
        GET /api/health/
        
    **Response** (Healthy):
        {
            "status": "healthy",
            "service": "SecurityHub API",
            "version": "1.0.0",
            "timestamp": 1703520000.123,
            "components": {
                "database": {
                    "healthy": true,
                    "message": "Database connection successful",
                    "response_time_ms": 2.34,
                    "type": "postgresql",
                    "critical": true
                },
                "cache": {
                    "healthy": true,
                    "message": "Cache connection successful",
                    "response_time_ms": 1.23,
                    "type": "locmem",
                    "critical": true
                },
                    "critical": false
                }
            },
            "summary": {
                "total_checks": 2,
                "passed": 3,
                "failed": 0,
                "critical_passed": 2,
                "critical_failed": 0
            }
        }
        
    **Status Codes**:
        - 200: Healthy or Degraded (critical components ok)
        - 503: Unhealthy (critical components failing)
    """
    health_data, status_code = get_health_status()
    
    logger.info(
        f"Health check performed: {health_data['status']}",
        extra={
            'status': health_data['status'],
            'passed': health_data['summary']['passed'],
            'failed': health_data['summary']['failed']
        }
    )
    
    return Response(health_data, status=status_code)


# Legacy endpoint for backward compatibility
@api_view(['GET'])
@permission_classes([AllowAny])
def ping(request):
    """
    Legacy ping endpoint (backward compatibility).
    
    Simple health check that returns 200 OK.
    
    **Deprecated**: Use /api/health/live/ instead.
    
    **No authentication required** - this is a health check endpoint.
    """
    logger.debug("Legacy ping endpoint called", extra={
        'request_id': getattr(request, 'request_id', None),
        'ip_address': request.META.get('REMOTE_ADDR'),
    })
    
    return Response({
        'status': 'ok',
        'message': 'Server is up and running!',
        'note': 'Deprecated: Use /api/health/live/ instead'
    }, status=status.HTTP_200_OK)


