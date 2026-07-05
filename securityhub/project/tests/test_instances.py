"""Tests for vulnerability instance (affected asset) CRUD endpoints."""
from datetime import date

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import Project, Vulnerability, VulnerableInstance


def _make_user(**kw):
    d = dict(email="user@c.com", password="Pass1!", username="user", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_project():
    return Project.objects.create(
        name="Proj", description="d", projecttype="Web",
        startdate=date(2026, 1, 1), enddate=date(2026, 1, 31),
        testingtype="Gray Box", status="In Progress", standard=[],
    )


def _make_vuln(project):
    return Vulnerability.objects.create(
        project=project, vulnerabilityname="XSS", vulnerabilityseverity="High",
    )


def _make_instance(vuln, url="https://example.com/search"):
    return VulnerableInstance.objects.create(
        vulnerabilityid=vuln, project=vuln.project, URL=url, Parameter="q",
    )


class VulnerabilityInstanceTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project()
        self.vuln = _make_vuln(self.project)
        self.list_url = reverse('vulnerability-instance-list', args=[self.vuln.id])

    def test_add_instance(self):
        payload = [{'URL': 'https://example.com/login', 'Parameter': 'user'}]
        r = self.client.post(self.list_url, payload, format='json')
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(VulnerableInstance.objects.count(), 1)

    def test_list_instances(self):
        _make_instance(self.vuln, 'https://a.com')
        _make_instance(self.vuln, 'https://b.com')
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        data = r.data if isinstance(r.data, list) else r.data.get('results', [])
        self.assertEqual(len(data), 2)

    def test_update_instance(self):
        inst = _make_instance(self.vuln)
        url = reverse('vulnerability-instance-update', args=[self.vuln.id, inst.id])
        r = self.client.patch(url, {'Parameter': 'id'}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        inst.refresh_from_db()
        self.assertEqual(inst.Parameter, 'id')

    def test_delete_instance(self):
        inst = _make_instance(self.vuln)
        url = reverse('vulnerability-instance-update', args=[self.vuln.id, inst.id])
        r = self.client.delete(url)
        self.assertIn(r.status_code, [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT])
        self.assertEqual(VulnerableInstance.objects.count(), 0)

    def test_instance_for_wrong_vuln_returns_404(self):
        other_vuln = Vulnerability.objects.create(
            project=self.project, vulnerabilityname="CSRF", vulnerabilityseverity="Medium",
        )
        inst = _make_instance(other_vuln)
        url = reverse('vulnerability-instance-update', args=[self.vuln.id, inst.id])
        r = self.client.patch(url, {'Parameter': 'hacked'}, format='json')
        self.assertEqual(r.status_code, status.HTTP_404_NOT_FOUND)

    def test_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)


class ProjectAllInstancesTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project()
        self.url = reverse('project-all-instances', args=[self.project.id])

    def test_lists_all_instances_across_vulns(self):
        v1 = _make_vuln(self.project)
        v2 = Vulnerability.objects.create(
            project=self.project, vulnerabilityname="SQLi", vulnerabilityseverity="Critical",
        )
        _make_instance(v1, 'https://a.com')
        _make_instance(v2, 'https://b.com')
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        data = r.data if isinstance(r.data, list) else r.data.get('results', [])
        self.assertEqual(len(data), 2)

    def test_empty_project_returns_empty_list(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        data = r.data if isinstance(r.data, list) else r.data.get('results', [])
        self.assertEqual(len(data), 0)

    def test_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
