"""Tests for project CRUD and scope endpoints."""
from datetime import date

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import Project, ProjectScope, Vulnerability


def _make_user(**kw):
    d = dict(email="user@c.com", password="Pass1!", username="user", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _project_payload(**kw):
    d = dict(
        name="Test Project",
        description="desc",
        projecttype="Web",
        startdate="2026-01-01",
        enddate="2026-01-31",
        testingtype="Gray Box",
        status="In Progress",
    )
    d.update(kw)
    return d


def _make_project(name="Proj", owner=None):
    p = Project.objects.create(
        name=name, description="d", projecttype="Web",
        startdate=date(2026, 1, 1), enddate=date(2026, 1, 31),
        testingtype="Gray Box", status="In Progress", standard=[],
    )
    if owner:
        p.owner.set([owner])
    return p


# ── Project list / create ─────────────────────────────────────────────────────

class ProjectListCreateTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)
        self.url = reverse('project-list')

    def test_create_project(self):
        r = self.client.post(self.url, _project_payload(), format='json')
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Project.objects.count(), 1)
        self.assertEqual(r.data['name'], 'Test Project')

    def test_list_projects(self):
        _make_project('A')
        _make_project('B')
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 2)

    def test_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_missing_name_rejected(self):
        payload = _project_payload()
        payload.pop('name')
        r = self.client.post(self.url, payload, format='json')
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)


# ── Project detail / update / delete ─────────────────────────────────────────

class ProjectDetailTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project('Alpha', owner=self.user)
        self.url = reverse('project-detail', args=[self.project.id])

    def test_get_project(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data['name'], 'Alpha')

    def test_patch_project_name(self):
        r = self.client.patch(self.url, {'name': 'Beta'}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.project.refresh_from_db()
        self.assertEqual(self.project.name, 'Beta')

    def test_patch_project_status(self):
        r = self.client.patch(self.url, {'status': 'Completed'}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.project.refresh_from_db()
        self.assertEqual(self.project.status, 'Completed')

    def test_delete_project(self):
        r = self.client.delete(self.url)
        self.assertIn(r.status_code, [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT])
        self.assertEqual(Project.objects.filter(pk=self.project.pk).count(), 0)

    def test_get_nonexistent_returns_404(self):
        url = reverse('project-detail', args=[99999])
        r = self.client.get(url)
        self.assertEqual(r.status_code, status.HTTP_404_NOT_FOUND)

    def test_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)


# ── Dashboard summary ─────────────────────────────────────────────────────────

class DashboardSummaryTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)
        self.url = reverse('dashboard-summary')

    def test_returns_counts(self):
        project = _make_project()
        Vulnerability.objects.create(
            project=project, vulnerabilityname="XSS", vulnerabilityseverity="Critical",
        )
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIn('total_vulnerabilities', r.data)
        self.assertIn('critical_vulnerabilities', r.data)
        self.assertGreaterEqual(r.data['total_vulnerabilities'], 1)

    def test_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)


# ── Scope CRUD ────────────────────────────────────────────────────────────────

class ScopeCRUDTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project(owner=self.user)
        self.list_url = reverse('project-scope-list', args=[self.project.id])

    def test_add_scope(self):
        r = self.client.post(self.list_url, [{'scope': 'https://example.com'}], format='json')
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(ProjectScope.objects.count(), 1)

    def test_list_scopes(self):
        ProjectScope.objects.create(project=self.project, scope='https://a.com')
        ProjectScope.objects.create(project=self.project, scope='https://b.com')
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        # Response may include asset profiles too; check at least 2 items
        self.assertGreaterEqual(len(r.data), 2)

    def test_update_scope(self):
        scope = ProjectScope.objects.create(project=self.project, scope='https://old.com')
        url = reverse('project-scope-update', args=[self.project.id, scope.id])
        r = self.client.patch(url, {'scope': 'https://new.com'}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        scope.refresh_from_db()
        self.assertEqual(scope.scope, 'https://new.com')

    def test_delete_scope(self):
        scope = ProjectScope.objects.create(project=self.project, scope='https://del.com')
        url = reverse('project-scope-update', args=[self.project.id, scope.id])
        r = self.client.delete(url)
        self.assertIn(r.status_code, [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT])
        self.assertEqual(ProjectScope.objects.count(), 0)

    def test_scope_for_wrong_project_returns_404(self):
        other_project = _make_project('Other')
        scope = ProjectScope.objects.create(project=other_project, scope='https://x.com')
        url = reverse('project-scope-update', args=[self.project.id, scope.id])
        r = self.client.patch(url, {'scope': 'https://hacked.com'}, format='json')
        self.assertEqual(r.status_code, status.HTTP_404_NOT_FOUND)

    def test_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
