"""
Pytest configuration for SecurityHub test suite.

This file configures pytest fixtures and settings that apply to all tests.
"""

import os
import sys
import pytest

# Ensure securityhub directory is in Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set Django settings module for pytest-django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securityhub.settings_test')

# Suppress test warnings for cleaner output
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=PendingDeprecationWarning)


# Enable pytest-django database setup
pytest_plugins = ['pytest_django']


@pytest.fixture
def api_client():
    """
    Provide DRF APIClient for tests.
    """
    from rest_framework.test import APIClient
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, test_user):
    """
    Provide authenticated API client.
    """
    api_client.force_authenticate(user=test_user)
    return api_client


@pytest.fixture
def test_user(db):
    """
    Create a test user.
    """
    from accounts.models import CustomUser

    user = CustomUser.objects.create_user(
        email="test@example.com",
        username="testuser",
        password="testpass123",
        is_active=True
    )

    return user
