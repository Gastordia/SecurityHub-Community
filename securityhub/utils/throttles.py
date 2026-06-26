"""
Rate limiting for SecurityHub API endpoints.

This module provides comprehensive rate limiting classes that:
- Different limits for different user types
- Per-endpoint rate limiting
- IP-based and user-based throttling
- Integration with DRF throttling system

Usage:
    from utils.throttles import TenantAwareThrottle, FileUploadThrottle
    
    class MyView(APIView):
        throttle_classes = [TenantAwareThrottle]
        throttle_scope = 'api'
"""
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle, SimpleRateThrottle
from django.core.cache import cache
import time


class TenantAwareThrottle(UserRateThrottle):
    """
    Rate limiting for authenticated API users.

    Default rate: 200 requests per minute for authenticated users
    """
    scope = 'user'

    def get_cache_key(self, request, view):
        """
        Generate cache key based on user ID.
        """
        if request.user.is_authenticated:
            ident = f"{request.user.id}"

            return self.cache_format % {
                'scope': self.scope,
                'ident': ident
            }

        # For anonymous users, use IP-based throttling
        return self.get_ident(request)


class FileUploadThrottle(SimpleRateThrottle):
    """
    Rate limiting specifically for file upload endpoints.

    More restrictive than general API throttling to prevent:
    - DoS attacks via large file uploads
    - Resource exhaustion
    - Bandwidth abuse

    Default rate: 10 requests per minute
    """
    scope = 'file_upload'

    def get_cache_key(self, request, view):
        """
        Generate cache key for file uploads.

        Uses user ID for authenticated users, IP address for anonymous users.
        """
        if request.user.is_authenticated:
            ident = f"{request.user.id}"

            return self.cache_format % {
                'scope': self.scope,
                'ident': ident
            }

        return self.get_ident(request)


class LoginThrottle(SimpleRateThrottle):
    """
    Rate limiting for authentication endpoints.
    
    Prevents brute force attacks on login endpoints.
    
    Default rate: 5 requests per minute per IP
    """
    scope = 'login'
    
    def get_cache_key(self, request, view):
        """
        Generate cache key for login attempts.
        
        Uses IP address to prevent bypassing by switching accounts.
        """
        # Always use IP for login throttling
        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }


class SearchThrottle(TenantAwareThrottle):
    """
    Rate limiting for search endpoints.
    
    Search operations can be expensive, so limit them separately.
    
    Default rate: 30 requests per minute
    """
    scope = 'search'


class AdminThrottle(UserRateThrottle):
    """
    Rate limiting for admin/superuser endpoints.
    
    Higher limits for admin users performing administrative tasks.
    
    Default rate: 500 requests per minute
    """
    scope = 'admin'
    
    def get_cache_key(self, request, view):
        """Only apply to authenticated admin users."""
        if request.user.is_authenticated and request.user.is_superuser:
            return self.cache_format % {
                'scope': self.scope,
                'ident': request.user.id
            }
        return None  # No throttling for non-admin


class BurstThrottle(SimpleRateThrottle):
    """
    Burst protection throttle.

    Allows short bursts of requests but limits sustained high-frequency requests.
    Uses a sliding window algorithm.

    Default rate: 100 requests per minute
    """
    scope = 'burst'

    def get_cache_key(self, request, view):
        """Generate cache key for burst protection."""
        if request.user.is_authenticated:
            ident = f"{request.user.id}"

            return self.cache_format % {
                'scope': self.scope,
                'ident': ident
            }

        return self.get_ident(request)


class CustomThrottle(SimpleRateThrottle):
    """
    Custom throttle that can be configured per-view.
    
    Usage:
        class MyView(APIView):
            throttle_classes = [CustomThrottle]
            throttle_scope = 'custom_scope'
    """
    
    def get_cache_key(self, request, view):
        """Generate cache key based on scope and user/IP."""
        scope = getattr(view, 'throttle_scope', 'default')
        self.scope = scope

        if request.user.is_authenticated:
            ident = f"{request.user.id}"

            return self.cache_format % {
                'scope': scope,
                'ident': ident
            }

        return self.cache_format % {
            'scope': scope,
            'ident': self.get_ident(request)
        }


def get_throttle_rate_headers(request, throttle_instance):
    """
    Get rate limit headers for response.
    
    Returns dictionary with:
    - X-RateLimit-Limit: Maximum requests allowed
    - X-RateLimit-Remaining: Remaining requests
    - X-RateLimit-Reset: Time when limit resets (Unix timestamp)
    """
    if not throttle_instance:
        return {}
    
    throttle_key = throttle_instance.key
    if not throttle_key:
        return {}
    
    # Get throttle history from cache
    history = cache.get(throttle_key, [])
    now = time.time()
    
    # Filter out old entries
    while history and history[-1] <= now - throttle_instance.duration:
        history.pop()
    
    # Calculate remaining requests
    num_requests = len(history)
    limit = throttle_instance.num_requests
    remaining = max(0, limit - num_requests)
    
    # Calculate reset time
    if history:
        reset_time = int(history[0] + throttle_instance.duration)
    else:
        reset_time = int(now + throttle_instance.duration)
    
    return {
        'X-RateLimit-Limit': limit,
        'X-RateLimit-Remaining': remaining,
        'X-RateLimit-Reset': reset_time,
    }











