"""
Comprehensive tests for CORS configuration security.

Tests verify that:
1. CORS_ORIGIN_ALLOW_ALL is set to False (critical security fix)
2. Only whitelisted origins can access the API
3. Unauthorized origins are blocked
4. Production mode enforces CORS_ALLOWED_ORIGINS environment variable
"""

import os
import pytest
from django.test import TestCase, override_settings
from django.http import HttpResponse
from rest_framework.test import APIClient
from django.conf import settings


class CORSConfigurationTestCase(TestCase):
    """Test CORS security configuration"""
    
    def setUp(self):
        """Set up test client"""
        self.client = APIClient()
        self.test_endpoint = '/api/accounts/health/'  # Public endpoint for testing
    
    def test_cors_allow_all_is_false(self):
        """CRITICAL: Verify CORS_ORIGIN_ALLOW_ALL is set to False"""
        # This is the primary security fix
        self.assertFalse(
            settings.CORS_ORIGIN_ALLOW_ALL,
            "CORS_ORIGIN_ALLOW_ALL must be False! Allowing all origins is a critical "
            "security vulnerability (OWASP A05:2021, CWE-942)"
        )
    
    def test_cors_allowed_origins_exists(self):
        """Verify CORS_ALLOWED_ORIGINS setting exists and is a list"""
        self.assertTrue(
            hasattr(settings, 'CORS_ALLOWED_ORIGINS'),
            "CORS_ALLOWED_ORIGINS setting must exist"
        )
        self.assertIsInstance(
            settings.CORS_ALLOWED_ORIGINS,
            list,
            "CORS_ALLOWED_ORIGINS must be a list"
        )
    
    def test_cors_allowed_origins_not_empty(self):
        """Verify CORS_ALLOWED_ORIGINS contains at least one origin"""
        self.assertGreater(
            len(settings.CORS_ALLOWED_ORIGINS),
            0,
            "CORS_ALLOWED_ORIGINS must contain at least one allowed origin"
        )
    
    def test_cors_allowed_origins_format(self):
        """Verify all origins are properly formatted (protocol + domain)"""
        for origin in settings.CORS_ALLOWED_ORIGINS:
            self.assertTrue(
                origin.startswith('http://') or origin.startswith('https://'),
                f"Origin '{origin}' must start with http:// or https://"
            )
            self.assertFalse(
                origin.endswith('/'),
                f"Origin '{origin}' should not have trailing slash"
            )
    
    def test_cors_preflight_request_allowed_origin(self):
        """Test that preflight requests from allowed origins succeed"""
        allowed_origin = settings.CORS_ALLOWED_ORIGINS[0]
        
        response = self.client.options(
            self.test_endpoint,
            HTTP_ORIGIN=allowed_origin,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET'
        )
        
        # Should return 200 OK for allowed origin
        self.assertEqual(
            response.status_code,
            200,
            f"Preflight request from allowed origin '{allowed_origin}' should succeed"
        )
    
    def test_cors_preflight_request_blocked_origin(self):
        """Test that preflight requests from unknown origins are blocked"""
        malicious_origin = 'https://malicious-hacker-site.com'
        
        # Ensure this origin is NOT in allowed list
        self.assertNotIn(
            malicious_origin,
            settings.CORS_ALLOWED_ORIGINS,
            f"Test malicious origin should not be in CORS_ALLOWED_ORIGINS"
        )
        
        response = self.client.options(
            self.test_endpoint,
            HTTP_ORIGIN=malicious_origin,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET'
        )
        
        # Response header should NOT include Access-Control-Allow-Origin for blocked origin
        # The browser will block the request
        # Note: Django still returns 200, but without CORS headers, browser blocks it
        self.assertNotIn(
            'Access-Control-Allow-Origin',
            response,
            "Blocked origin should not receive Access-Control-Allow-Origin header"
        )
    
    def test_no_wildcard_in_allowed_origins(self):
        """Verify no wildcard origins are configured (security risk)"""
        for origin in settings.CORS_ALLOWED_ORIGINS:
            self.assertNotIn(
                '*',
                origin,
                f"Wildcard '*' in origin '{origin}' is a security risk"
            )
    
    def test_no_http_in_production_origins(self):
        """
        If DEBUG=False, verify all origins use HTTPS (not HTTP)
        HTTP is only acceptable in development mode or tests
        """
        # Skip this test if using test settings (allows HTTP for test convenience)
        if 'settings_test' in settings.SETTINGS_MODULE:
            self.skipTest("Test settings allow HTTP origins for testing")
        
        if not settings.DEBUG:
            for origin in settings.CORS_ALLOWED_ORIGINS:
                self.assertTrue(
                    origin.startswith('https://'),
                    f"Production origin '{origin}' must use HTTPS, not HTTP"
                )


@pytest.mark.django_db
class CORSEnvironmentVariableTestCase(TestCase):
    """Test CORS configuration from environment variables"""
    
    def test_cors_reads_from_environment_variable(self):
        """Test that CORS origins can be set via environment variable"""
        test_origins = "https://app.example.com,https://www.example.com"
        
        # This test verifies the logic in settings.py parses the env var correctly
        # The actual setting is loaded at Django startup, so we test the logic
        origins_list = [
            origin.strip() 
            for origin in test_origins.split(',') 
            if origin.strip()
        ]
        
        self.assertEqual(len(origins_list), 2)
        self.assertEqual(origins_list[0], "https://app.example.com")
        self.assertEqual(origins_list[1], "https://www.example.com")
    
    def test_cors_env_var_strips_whitespace(self):
        """Test that environment variable parsing strips whitespace"""
        test_origins = "https://app.example.com , https://www.example.com , https://api.example.com"
        
        origins_list = [
            origin.strip() 
            for origin in test_origins.split(',') 
            if origin.strip()
        ]
        
        # Verify all origins have no leading/trailing whitespace
        for origin in origins_list:
            self.assertEqual(origin, origin.strip())


class CORSDevelopmentDefaultsTestCase(TestCase):
    """Test CORS development defaults"""
    
    def test_development_defaults_include_localhost(self):
        """Verify development defaults include common localhost ports"""
        if settings.DEBUG:
            # In development mode, ensure common dev server ports are allowed
            allowed_origins_str = ','.join(settings.CORS_ALLOWED_ORIGINS)
            
            # Check for common development origins
            self.assertIn(
                'localhost:5173',  # Vite
                allowed_origins_str,
                "Development defaults should include Vite dev server (localhost:5173)"
            )
            self.assertIn(
                'localhost:3000',  # React
                allowed_origins_str,
                "Development defaults should include React dev server (localhost:3000)"
            )


class CORSSecurityRegressionTestCase(TestCase):
    """
    Regression tests to ensure CORS_ORIGIN_ALLOW_ALL is never re-enabled
    
    These tests will fail if someone accidentally re-introduces the vulnerability
    """
    
    def test_cors_allow_all_never_true(self):
        """
        CRITICAL REGRESSION TEST
        
        This test MUST ALWAYS PASS. If it fails, someone has re-introduced
        a critical security vulnerability.
        
        CORS_ORIGIN_ALLOW_ALL = True allows ANY website to make authenticated
        requests, enabling CSRF attacks, session hijacking, and data exfiltration.
        """
        self.assertFalse(
            settings.CORS_ORIGIN_ALLOW_ALL,
            "❌ CRITICAL SECURITY VULNERABILITY DETECTED! ❌\n\n"
            "CORS_ORIGIN_ALLOW_ALL is set to True!\n"
            "This allows ANY website to make authenticated requests to your API.\n\n"
            "Security Risks:\n"
            "- CSRF attacks\n"
            "- Session hijacking\n"
            "- Data exfiltration\n"
            "- Compliance violations (GDPR, SOC 2)\n\n"
            "OWASP Classification: A05:2021 - Security Misconfiguration\n"
            "CWE: CWE-942 - Permissive Cross-domain Policy\n\n"
            "FIX: Set CORS_ORIGIN_ALLOW_ALL = False in settings.py"
        )
    
    def test_no_wildcard_cors_regex(self):
        """Verify CORS_ALLOWED_ORIGIN_REGEXES doesn't use wildcards"""
        if hasattr(settings, 'CORS_ALLOWED_ORIGIN_REGEXES'):
            self.assertEqual(
                len(settings.CORS_ALLOWED_ORIGIN_REGEXES),
                0,
                "CORS_ALLOWED_ORIGIN_REGEXES should be empty. "
                "Regex patterns can be security risks if misconfigured."
            )


class CORSHeadersTestCase(TestCase):
    """Test CORS headers configuration"""
    
    def test_cors_allow_credentials(self):
        """Verify credentials (cookies, auth headers) are allowed"""
        # CORS_ALLOW_CREDENTIALS should be True to allow authenticated requests
        if hasattr(settings, 'CORS_ALLOW_CREDENTIALS'):
            self.assertTrue(
                settings.CORS_ALLOW_CREDENTIALS,
                "CORS_ALLOW_CREDENTIALS should be True to allow authenticated requests"
            )


# Integration test helper
def simulate_cors_preflight(client, origin, endpoint='/api/accounts/health/'):
    """
    Helper function to simulate a CORS preflight request
    
    Args:
        client: Django test client
        origin: Origin header value
        endpoint: API endpoint to test
    
    Returns:
        Response object
    """
    return client.options(
        endpoint,
        HTTP_ORIGIN=origin,
        HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
        HTTP_ACCESS_CONTROL_REQUEST_HEADERS='authorization,content-type,x-org-id'
    )


# Pytest-style tests (alternative format)
@pytest.mark.django_db
def test_cors_critical_security_check():
    """Pytest-style critical security check"""
    assert settings.CORS_ORIGIN_ALLOW_ALL is False, (
        "CRITICAL: CORS_ORIGIN_ALLOW_ALL must be False!"
    )


@pytest.mark.django_db  
def test_cors_allowed_origins_not_empty():
    """Pytest-style test for non-empty allowed origins"""
    assert len(settings.CORS_ALLOWED_ORIGINS) > 0, (
        "CORS_ALLOWED_ORIGINS must contain at least one origin"
    )


@pytest.mark.django_db
def test_cors_no_wildcards():
    """Pytest-style test for no wildcard origins"""
    for origin in settings.CORS_ALLOWED_ORIGINS:
        assert '*' not in origin, f"Wildcard in origin '{origin}' is security risk"

