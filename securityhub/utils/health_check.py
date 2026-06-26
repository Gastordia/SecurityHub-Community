"""
Health Check Utilities

Comprehensive health check system for monitoring application status.
Provides liveness, readiness, and detailed health checks.

Created for Issue #23 (Phase 3)
"""

import logging
from typing import Dict, Any, Tuple
from django.db import connections
from django.core.cache import cache
from django.conf import settings
import time

logger = logging.getLogger(__name__)


class HealthCheckService:
    """
    Service for performing health checks on various application components.
    
    Provides three types of checks:
    1. Liveness: Is the application running?
    2. Readiness: Is the application ready to serve traffic?
    3. Detailed: Comprehensive status of all components
    """
    
    @staticmethod
    def check_database() -> Tuple[bool, str, float]:
        """
        Check database connectivity and responsiveness.
        
        Returns:
            Tuple of (is_healthy, message, response_time_ms)
        """
        try:
            start_time = time.time()
            
            # Try to execute a simple query
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            return True, "Database connection successful", response_time
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}", exc_info=True)
            return False, f"Database connection failed: {str(e)}", 0.0
    
    @staticmethod
    def check_cache() -> Tuple[bool, str, float]:
        """
        Check cache connectivity and responsiveness.
        
        Returns:
            Tuple of (is_healthy, message, response_time_ms)
        """
        try:
            start_time = time.time()
            
            # Test cache write/read
            test_key = 'health_check_test'
            test_value = 'ok'
            
            cache.set(test_key, test_value, timeout=10)
            retrieved_value = cache.get(test_key)
            cache.delete(test_key)
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            if retrieved_value == test_value:
                return True, "Cache connection successful", response_time
            else:
                return False, "Cache read/write verification failed", response_time
            
        except Exception as e:
            logger.error(f"Cache health check failed: {e}", exc_info=True)
            return False, f"Cache connection failed: {str(e)}", 0.0
    

    @classmethod
    def liveness_check(cls) -> Dict[str, Any]:
        """
        Liveness probe: Is the application running?
        
        This is a lightweight check that only verifies the app is responsive.
        Used by Kubernetes/Docker for restart decisions.
        
        Returns:
            Dict with status and basic info
        """
        return {
            'status': 'alive',
            'service': 'SecurityHub API',
            'timestamp': time.time()
        }
    
    @classmethod
    def readiness_check(cls) -> Dict[str, Any]:
        """
        Readiness probe: Is the application ready to serve traffic?
        
        Checks critical dependencies (database, cache).
        Used by load balancers to determine if traffic should be routed here.
        
        Returns:
            Dict with status and dependency health
        """
        db_healthy, db_message, db_time = cls.check_database()
        cache_healthy, cache_message, cache_time = cls.check_cache()
        
        is_ready = db_healthy and cache_healthy
        
        return {
            'status': 'ready' if is_ready else 'not_ready',
            'service': 'SecurityHub API',
            'timestamp': time.time(),
            'checks': {
                'database': {
                    'healthy': db_healthy,
                    'message': db_message,
                    'response_time_ms': round(db_time, 2)
                },
                'cache': {
                    'healthy': cache_healthy,
                    'message': cache_message,
                    'response_time_ms': round(cache_time, 2)
                }
            }
        }
    
    @classmethod
    def detailed_health_check(cls) -> Dict[str, Any]:
        """
        Detailed health check: Comprehensive status of all components.
        
        Checks all dependencies: database, cache.
        Provides detailed metrics and response times.
        
        Returns:
            Dict with comprehensive health information
        """
        # Check all components
        db_healthy, db_message, db_time = cls.check_database()
        cache_healthy, cache_message, cache_time = cls.check_cache()
        
        # Determine overall health
        critical_healthy = db_healthy and cache_healthy
        all_healthy = critical_healthy
        
        # Determine status
        if all_healthy:
            status = 'healthy'
        else:
            status = 'unhealthy'
        
        return {
            'status': status,
            'service': 'SecurityHub API',
            'version': getattr(settings, 'VERSION', '1.0.0'),
            'timestamp': time.time(),
            'components': {
                'database': {
                    'healthy': db_healthy,
                    'message': db_message,
                    'response_time_ms': round(db_time, 2),
                    'type': 'postgresql',
                    'critical': True
                },
                'cache': {
                    'healthy': cache_healthy,
                    'message': cache_message,
                    'response_time_ms': round(cache_time, 2),
                    'type': 'locmem',
                    'critical': True
                }
            },
            'summary': {
                'total_checks': 2,
                'passed': sum([db_healthy, cache_healthy]),
                'failed': sum([not db_healthy, not cache_healthy]),
                'critical_passed': sum([db_healthy, cache_healthy]),
                'critical_failed': sum([not db_healthy, not cache_healthy])
            }
        }


def get_health_status() -> Tuple[Dict[str, Any], int]:
    """
    Get health status with appropriate HTTP status code.
    
    Returns:
        Tuple of (health_dict, http_status_code)
    """
    health = HealthCheckService.detailed_health_check()
    
    # Determine HTTP status code
    if health['status'] == 'healthy':
        status_code = 200
    elif health['status'] == 'degraded':
        status_code = 200  # Still serving traffic
    else:
        status_code = 503  # Service Unavailable
    
    return health, status_code


