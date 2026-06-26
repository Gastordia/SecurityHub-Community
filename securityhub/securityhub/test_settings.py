"""
Test-specific Django settings for SecurityHub
Overrides database and cache settings to use SQLite and in-memory storage for testing
"""

import os
from pathlib import Path
from .settings import *

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Override database settings for testing
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',  # Use in-memory SQLite for testing
    }
}

# Override cache settings for testing
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Disable optional Redis cache for testing
REDIS_URL = None

# Disable email for testing
EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'

# Disable debug toolbar for testing
DEBUG_TOOLBAR_CONFIG = {
    'SHOW_TOOLBAR_CALLBACK': lambda request: False,
    'IS_RUNNING_TESTS': True,  # Tell toolbar we're running tests
}

# Remove debug toolbar from installed apps and middleware for tests
if 'debug_toolbar' in INSTALLED_APPS:
    INSTALLED_APPS.remove('debug_toolbar')

if 'debug_toolbar.middleware.DebugToolbarMiddleware' in MIDDLEWARE:
    MIDDLEWARE.remove('debug_toolbar.middleware.DebugToolbarMiddleware')

# Set DEBUG to False for tests (Django default)
DEBUG = False

# Enable feature flags for testing
FEATURE_RBAC_USERS = False  # Use legacy endpoints for now

# Disable logging to files for testing
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}

# Disable migrations for faster test setup (uses model state instead)
class DisableMigrations:
    def __contains__(self, item):
        return True
    
    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# Test-specific settings
TEST_RUNNER = 'django.test.runner.DiscoverRunner'
TEST_DISCOVER_TOP_LEVEL = BASE_DIR
TEST_DISCOVER_PATTERN = 'test_*.py'
