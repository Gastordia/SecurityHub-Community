"""Tests for project assets CRUD."""
from datetime import date

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import Project
from assets.models import Asset


def _make_staff(**kw):
    d = dict(email="staff@assets.com", password="Pass1!", username="astaff", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_project(name="AssetProj"):
    return Project.objects.create(
        name=name, description="d", projecttype="Web",
        startdate=date(2026, 1, 1), enddate=date(2026, 1, 31),
        testingtype="Gray Box", status="In Progress", standard=[],
    )


class AssetCRUDTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project()
        self.list_url = reverse('asset-list', args=[self.project.id])

    def test_create_asset(self):
        r = self.client.post(self.list_url, {
            "ip": "10.0.0.1",
            "hostname": "web01",
            "criticality": "high",
        }, format='json')
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Asset.objects.count(), 1)

    def test_list_assets(self):
        Asset.objects.create(project=self.project, ip="10.0.0.1", hostname="web01")
        Asset.objects.create(project=self.project, ip="10.0.0.2", hostname="db01")
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 2)

    def test_update_asset(self):
        asset = Asset.objects.create(project=self.project, ip="10.0.0.1", hostname="old")
        url = reverse('asset-detail', args=[self.project.id, asset.id])
        r = self.client.patch(url, {"hostname": "new"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        asset.refresh_from_db()
        self.assertEqual(asset.hostname, "new")

    def test_delete_asset(self):
        asset = Asset.objects.create(project=self.project, ip="10.0.0.1", hostname="gone")
        url = reverse('asset-detail', args=[self.project.id, asset.id])
        r = self.client.delete(url)
        self.assertEqual(r.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Asset.objects.filter(id=asset.id).exists())

    def test_unauthenticated_cannot_list(self):
        self.client.logout()
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
