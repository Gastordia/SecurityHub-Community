"""
Test-specific Django settings for SecurityHub.

This file imports all settings from the main settings.py and overrides
test-specific configurations to ensure tests run cleanly without
permission errors or unnecessary I/O operations.

Usage:
    pytest automatically uses this via pytest.ini configuration:
    DJANGO_SETTINGS_MODULE = securityhub.settings_test
    
    Or manually:
    python manage.py test --settings=securityhub.settings_test
"""

# Import all settings from main settings file
from .settings import *

# ============================================================================
# Test Database Configuration
# ============================================================================
# Use in-memory SQLite for fast tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
        'ATOMIC_REQUESTS': True,
    }
}

# ============================================================================
# Logging Configuration (Test-Friendly)
# ============================================================================
# Override logging to use console only (no file handlers)
# This prevents permission errors and speeds up tests
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '[%(levelname)s] %(message)s',
        },
        'verbose': {
            'format': '[%(levelname)s] %(name)s: %(message)s',
        },
    },
    'handlers': {
        'console': {
            'level': 'WARNING',  # Reduce noise in test output
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        # Django loggers - minimize output
        'django': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['null'],  # Silence SQL queries
            'level': 'ERROR',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
        
        # Application loggers - only show warnings/errors
        'accounts': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'customers': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'vulnerability': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'project': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'utils': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'audit': {
            'handlers': ['null'],  # Silence audit logs in tests
            'level': 'ERROR',
            'propagate': False,
        },
        
        # Test-specific loggers
        'tests': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# ============================================================================
# Security Settings (Relaxed for Tests)
# ============================================================================
# Allow HTTP in tests (no HTTPS required)
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Simpler password hashing for faster tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# ============================================================================
# Email Configuration (Mock for Tests)
# ============================================================================
# Use console backend to prevent actual email sending
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# ============================================================================
# Cache Configuration (Dummy Cache for Tests)
# ============================================================================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}

# ============================================================================
# Static Files (Disable WhiteNoise in Tests)
# ============================================================================
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# ============================================================================
# Debug Settings
# ============================================================================
# Keep DEBUG = False to test production-like behavior
# Individual tests can override this if needed
DEBUG = False

# Show template errors clearly
TEMPLATES[0]['OPTIONS']['debug'] = True

# ============================================================================
# Media Files (Use Temp Directory)
# ============================================================================
import tempfile
MEDIA_ROOT = os.path.join(tempfile.gettempdir(), 'securityhub_test_media')

# ============================================================================
# Test-Specific Optimizations
# ============================================================================
# Disable migrations for faster test database setup
# Tests will use model schema directly
class DisableMigrations:
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# ============================================================================
# CORS Configuration (Test-Friendly)
# ============================================================================
# Allow test origins
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://testserver",  # Django test client
]

# Ensure CORS_ORIGIN_ALLOW_ALL is False (security test requirement)
CORS_ORIGIN_ALLOW_ALL = False

# ============================================================================
# Test Configuration Summary
# ============================================================================
print("=" * 80)
print("🧪 TEST SETTINGS ACTIVE")
print("=" * 80)
print(f"Database: {DATABASES['default']['ENGINE']} (in-memory)")
print(f"Debug Mode: {DEBUG}")
print(f"Email Backend: {EMAIL_BACKEND}")
print(f"Cache Backend: {CACHES['default']['BACKEND']}")
print(f"CORS Allow All: {CORS_ORIGIN_ALLOW_ALL}")
print(f"CORS Allowed Origins: {len(CORS_ALLOWED_ORIGINS)} origins")
print(f"Logging: Console only (no file handlers)")
print("=" * 80)


