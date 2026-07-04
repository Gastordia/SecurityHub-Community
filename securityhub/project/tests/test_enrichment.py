"""Tests for CVE enrichment endpoint — verifies routing and auth without hitting external APIs."""
from datetime import date
from unittest.mock import patch

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import Project, Vulnerability


def _make_staff(**kw):
    d = dict(email="staff@enr.com", password="Pass1!", username="enrstaff", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_project(name="Enrich Proj"):
    return Project.objects.create(
        name=name, description="d", projecttype="Web",
        startdate=date(2026, 1, 1), enddate=date(2026, 1, 31),
        testingtype="Gray Box", status="In Progress", standard=[],
    )


class CVEEnrichmentTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project()
        self.vuln = Vulnerability.objects.create(
            project=self.project,
            vulnerabilityname="Log4Shell",
            vulnerabilityseverity="Critical",
        )

    def _enrich_url(self, vuln_id):
        return reverse('enrich-vulnerability', args=[vuln_id])

    @patch('project.tasks.enrich_vulnerability_cve')
    def test_enrich_returns_200(self, mock_task):
        mock_task.return_value = None
        r = self.client.post(self._enrich_url(self.vuln.id))
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn('cve_enrichment_status', r.data)
        mock_task.assert_called_once_with(self.vuln.id)

    @patch('project.tasks.enrich_vulnerability_cve')
    def test_enrich_nonexistent_vuln_returns_404(self, mock_task):
        import uuid
        r = self.client.post(self._enrich_url(uuid.uuid4()))
        self.assertEqual(r.status_code, status.HTTP_404_NOT_FOUND)
        mock_task.assert_not_called()

    def test_unauthenticated_cannot_enrich(self):
        self.client.logout()
        r = self.client.post(self._enrich_url(self.vuln.id))
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
