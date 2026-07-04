"""Tests for bulk vulnerability operations."""
from datetime import date

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import Project, Vulnerability


def _make_staff(**kw):
    d = dict(email="staff@bulk.com", password="Pass1!", username="bstaff", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_project(name="Bulk Proj"):
    return Project.objects.create(
        name=name, description="d", projecttype="Web",
        startdate=date(2026, 1, 1), enddate=date(2026, 1, 31),
        testingtype="Gray Box", status="In Progress", standard=[],
    )


class BulkOperationTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project()
        self.v1 = Vulnerability.objects.create(
            project=self.project, vulnerabilityname="SQL Injection",
            vulnerabilityseverity="High", status="Open",
        )
        self.v2 = Vulnerability.objects.create(
            project=self.project, vulnerabilityname="XSS",
            vulnerabilityseverity="Medium", status="Open",
        )
        self.url = reverse('vulnerability-bulk-action', args=[self.project.id])

    def test_bulk_change_status(self):
        r = self.client.post(self.url, {
            "action": "change_status",
            "ids": [str(self.v1.id), str(self.v2.id)],
            "value": "Confirm Fixed",
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.v1.refresh_from_db()
        self.v2.refresh_from_db()
        self.assertEqual(self.v1.status, "Confirm Fixed")
        self.assertEqual(self.v2.status, "Confirm Fixed")

    def test_bulk_change_severity(self):
        r = self.client.post(self.url, {
            "action": "change_severity",
            "ids": [str(self.v1.id)],
            "value": "Critical",
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.v1.refresh_from_db()
        self.assertEqual(self.v1.vulnerabilityseverity, "Critical")

    def test_bulk_delete(self):
        r = self.client.post(self.url, {
            "action": "delete",
            "ids": [str(self.v1.id), str(self.v2.id)],
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(Vulnerability.objects.filter(project=self.project).count(), 0)

    def test_invalid_action_rejected(self):
        r = self.client.post(self.url, {
            "action": "not_real",
            "ids": [str(self.v1.id)],
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_value_for_change_status_rejected(self):
        r = self.client.post(self.url, {
            "action": "change_status",
            "ids": [str(self.v1.id)],
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)

    def test_empty_ids_rejected(self):
        r = self.client.post(self.url, {
            "action": "delete",
            "ids": [],
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)

    def test_unauthenticated_cannot_bulk(self):
        self.client.logout()
        r = self.client.post(self.url, {"action": "delete", "ids": [str(self.v1.id)]}, format='json')
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
