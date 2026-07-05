"""Tests for configapi — project types and report standards sync/CRUD."""
from unittest.mock import patch, MagicMock

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from configapi.models import ProjectType, ReportStandard


def _make_staff(**kw):
    d = dict(email="staff@c.com", password="Pass1!", username="staff", is_staff=True, is_superuser=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_user(**kw):
    d = dict(email="user@c.com", password="Pass1!", username="user", is_staff=False)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


# ── Project types list ────────────────────────────────────────────────────────

class ProjectTypeListTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)
        self.url = reverse('project-type-list')

    def test_list_empty(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        data = r.data if isinstance(r.data, list) else r.data.get('results', r.data)
        self.assertEqual(len(data), 0)

    def test_list_with_entries(self):
        ProjectType.objects.create(name='Web App Pentest')
        ProjectType.objects.create(name='Mobile Pentest')
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        data = r.data if isinstance(r.data, list) else r.data.get('results', r.data)
        self.assertEqual(len(data), 2)

    def test_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)


# ── Project types sync ────────────────────────────────────────────────────────

class ProjectTypeSyncTests(APITestCase):
    def setUp(self):
        self.staff = _make_staff()
        self.user = _make_user()
        self.url = reverse('project-type-sync')

    def _mock_response(self, json_data, status_code=200):
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.json.return_value = json_data
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_sync_creates_entries(self):
        self.client.force_authenticate(user=self.staff)
        payload = [{"name": "Web App Pentest"}, {"name": "Mobile Pentest"}]
        with patch('configapi.views.config.http_requests.get') as mock_get:
            mock_get.return_value = self._mock_response(payload)
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data['created'], 2)
        self.assertEqual(ProjectType.objects.count(), 2)

    def test_sync_upserts_existing(self):
        ProjectType.objects.create(name='Web App Pentest')
        self.client.force_authenticate(user=self.staff)
        payload = [{"name": "Web App Pentest"}, {"name": "Network Pentest"}]
        with patch('configapi.views.config.http_requests.get') as mock_get:
            mock_get.return_value = self._mock_response(payload)
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(ProjectType.objects.count(), 2)

    def test_sync_skips_entries_without_name(self):
        self.client.force_authenticate(user=self.staff)
        payload = [{"name": "Good"}, {"other_key": "bad"}, {"name": ""}]
        with patch('configapi.views.config.http_requests.get') as mock_get:
            mock_get.return_value = self._mock_response(payload)
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data['skipped'], 2)
        self.assertEqual(ProjectType.objects.count(), 1)

    def test_sync_unauthenticated_rejected(self):
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_sync_non_staff_rejected(self):
        self.client.force_authenticate(user=self.user)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_sync_github_timeout_returns_504(self):
        import requests as req_lib
        self.client.force_authenticate(user=self.staff)
        with patch('configapi.views.config.http_requests.get') as mock_get:
            mock_get.side_effect = req_lib.exceptions.Timeout()
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_504_GATEWAY_TIMEOUT)

    def test_sync_non_list_response_returns_502(self):
        self.client.force_authenticate(user=self.staff)
        with patch('configapi.views.config.http_requests.get') as mock_get:
            mock_get.return_value = self._mock_response({"not": "a list"})
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_502_BAD_GATEWAY)


# ── Report standards list ─────────────────────────────────────────────────────

class ReportStandardListTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)
        self.url = reverse('report-standard-list')

    def test_list_empty(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)

    def test_list_with_entries(self):
        ReportStandard.objects.create(name='OWASP Top 10')
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        data = r.data if isinstance(r.data, list) else r.data.get('results', r.data)
        self.assertGreaterEqual(len(data), 1)

    def test_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)


# ── Report standards sync ─────────────────────────────────────────────────────

class ReportStandardSyncTests(APITestCase):
    def setUp(self):
        self.staff = _make_staff()
        self.url = reverse('report-standard-sync')

    def _mock_response(self, json_data):
        mock_resp = MagicMock()
        mock_resp.json.return_value = json_data
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_sync_creates_standards(self):
        self.client.force_authenticate(user=self.staff)
        payload = [{"name": "OWASP Top 10"}, {"name": "PTES"}]
        with patch('configapi.views.config.http_requests.get') as mock_get:
            mock_get.return_value = self._mock_response(payload)
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data['created'], 2)
        self.assertEqual(ReportStandard.objects.count(), 2)

    def test_sync_unauthenticated_rejected(self):
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_sync_github_timeout_returns_504(self):
        import requests as req_lib
        self.client.force_authenticate(user=self.staff)
        with patch('configapi.views.config.http_requests.get') as mock_get:
            mock_get.side_effect = req_lib.exceptions.Timeout()
            r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_504_GATEWAY_TIMEOUT)


# ── Ping health check ─────────────────────────────────────────────────────────

class PingTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)

    def test_ping_returns_200(self):
        r = self.client.get(reverse('ping'))
        self.assertEqual(r.status_code, status.HTTP_200_OK)
