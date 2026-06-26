"""
Security middleware for biometric authentication endpoints
"""
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
import time
from collections import defaultdict, deque

class BiometricSecurityMiddleware(MiddlewareMixin):
    """
    Security middleware to protect biometric authentication endpoints
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        # Rate limiting storage
        self.rate_limits = defaultdict(lambda: deque())
        self.max_attempts = 5  # Max attempts per minute
        self.time_window = 60  # 1 minute
    
    def process_request(self, request):
        # Apply rate limiting to biometric endpoints
        if request.path.startswith('/api/auth/biometric/'):
            client_ip = self.get_client_ip(request)
            current_time = time.time()
            
            # Clean old attempts
            while (self.rate_limits[client_ip] and 
                   self.rate_limits[client_ip][0] < current_time - self.time_window):
                self.rate_limits[client_ip].popleft()
            
            # Check rate limit
            if len(self.rate_limits[client_ip]) >= self.max_attempts:
                return JsonResponse({
                    'success': False,
                    'message': 'Too many requests. Please try again later.'
                }, status=429)
            
            # Record this attempt
            self.rate_limits[client_ip].append(current_time)
        
        return None
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


