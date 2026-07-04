"""Tests for SLA policy view — staff-only write access."""
from datetime import date

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import SLAPolicy


def _make_user(email, username, is_staff=False):
    return CustomUser.objects.create_user(
        email=email, password="Pass1!", username=username, is_staff=is_staff,
    )


class SLAPolicyTests(APITestCase):
    def setUp(self):
        self.staff = _make_user("staff@sla.com", "slastaff", is_staff=True)
        self.regular = _make_user("reg@sla.com", "slareg", is_staff=False)
        self.url = reverse('sla-policy')

    def test_get_returns_defaults_when_no_policy(self):
        self.client.force_authenticate(user=self.staff)
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn('critical_days', r.data)

    def test_staff_can_create_policy(self):
        self.client.force_authenticate(user=self.staff)
        r = self.client.put(self.url, {
            "critical_days": 5, "high_days": 20, "medium_days": 60,
            "low_days": 120, "informational_days": 300,
        }, format='json')
        self.assertIn(r.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED])
        self.assertEqual(SLAPolicy.objects.count(), 1)

    def test_staff_can_update_policy(self):
        SLAPolicy.objects.create(
            critical_days=7, high_days=30, medium_days=90,
            low_days=180, informational_days=365, created_by=self.staff,
        )
        self.client.force_authenticate(user=self.staff)
        r = self.client.put(self.url, {"critical_days": 3}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(SLAPolicy.objects.order_by('-created_at').first().critical_days, 3)

    def test_non_staff_cannot_write_policy(self):
        self.client.force_authenticate(user=self.regular)
        r = self.client.put(self.url, {"critical_days": 1}, format='json')
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_cannot_read(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
