"""Tests for finding comments CRUD."""
from datetime import date

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import Project, Vulnerability, FindingComment


def _make_staff(**kw):
    d = dict(email="staff@c.com", password="Pass1!", username="staff", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_project(name="Proj"):
    return Project.objects.create(
        name=name, description="d", projecttype="Web",
        startdate=date(2026, 1, 1), enddate=date(2026, 1, 31),
        testingtype="Gray Box", status="In Progress", standard=[],
    )


def _make_vuln(project, name="SQL Injection"):
    return Vulnerability.objects.create(
        project=project, vulnerabilityname=name, vulnerabilityseverity="High",
    )


class CommentCRUDTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project()
        self.vuln = _make_vuln(self.project)
        self.list_url = reverse('vulnerability-comments', args=[self.vuln.id])

    def test_create_comment(self):
        r = self.client.post(self.list_url, {"body": "Needs fix"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(FindingComment.objects.count(), 1)

    def test_list_comments(self):
        FindingComment.objects.create(vulnerability=self.vuln, author=self.user, body="First")
        FindingComment.objects.create(vulnerability=self.vuln, author=self.user, body="Second")
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 2)

    def test_edit_own_comment(self):
        comment = FindingComment.objects.create(vulnerability=self.vuln, author=self.user, body="Old")
        url = reverse('vulnerability-comment-detail', args=[self.vuln.id, comment.id])
        r = self.client.patch(url, {"body": "Updated"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        comment.refresh_from_db()
        self.assertEqual(comment.body, "Updated")

    def test_delete_own_comment(self):
        comment = FindingComment.objects.create(vulnerability=self.vuln, author=self.user, body="Gone")
        url = reverse('vulnerability-comment-detail', args=[self.vuln.id, comment.id])
        r = self.client.delete(url)
        self.assertEqual(r.status_code, status.HTTP_204_NO_CONTENT)
        # Soft-delete: record still exists but is_deleted=True
        comment.refresh_from_db()
        self.assertTrue(comment.is_deleted)

    def test_unauthenticated_cannot_read_comments(self):
        self.client.logout()
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
