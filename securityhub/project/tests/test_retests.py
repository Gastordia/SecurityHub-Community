"""Tests for vulnerability retest CRUD."""
from datetime import date

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import Project, Vulnerability, Retest


def _make_staff(**kw):
    d = dict(email="staff@r.com", password="Pass1!", username="rstaff", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_project(name="Proj"):
    return Project.objects.create(
        name=name, description="d", projecttype="Web",
        startdate=date(2026, 1, 1), enddate=date(2026, 1, 31),
        testingtype="Gray Box", status="In Progress", standard=[],
    )


def _make_vuln(project, name="XSS"):
    return Vulnerability.objects.create(
        project=project, vulnerabilityname=name, vulnerabilityseverity="Medium",
    )


class RetestCRUDTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project()
        self.vuln = _make_vuln(self.project)
        self.list_url = reverse('vulnerability-retests', args=[self.vuln.id])

    def test_create_retest(self):
        r = self.client.post(self.list_url, {
            "date": "2026-06-01",
            "result": "fixed",
            "notes": "Verified on staging",
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Retest.objects.count(), 1)

    def test_list_retests(self):
        Retest.objects.create(vulnerability=self.vuln, tester=self.user, date=date(2026, 5, 1), result="still_vulnerable")
        Retest.objects.create(vulnerability=self.vuln, tester=self.user, date=date(2026, 6, 1), result="fixed")
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 2)

    def test_delete_retest(self):
        retest = Retest.objects.create(vulnerability=self.vuln, tester=self.user, date=date(2026, 5, 1), result="still_vulnerable")
        url = reverse('vulnerability-retest-detail', args=[self.vuln.id, retest.id])
        r = self.client.delete(url)
        self.assertEqual(r.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Retest.objects.filter(id=retest.id).exists())

    def test_invalid_result_rejected(self):
        r = self.client.post(self.list_url, {
            "date": "2026-06-01",
            "result": "NotAChoice",
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)

    def test_unauthenticated_cannot_list(self):
        self.client.logout()
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
