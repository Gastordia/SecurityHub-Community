"""Tests for dashboard trend, MTTR, and snapshot endpoints."""
from datetime import date
from unittest.mock import patch

from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from project.models import Project
from dashboard.models import DashboardSnapshot


def _make_staff(**kw):
    d = dict(email="staff@dash.com", password="Pass1!", username="dstaff", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_regular(**kw):
    d = dict(email="reg@dash.com", password="Pass1!", username="dreg", is_staff=False)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


def _make_project(name="Dash Proj"):
    return Project.objects.create(
        name=name, description="d", projecttype="Web",
        startdate=date(2026, 1, 1), enddate=date(2026, 1, 31),
        testingtype="Gray Box", status="In Progress", standard=[],
    )


class TrendTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project()
        self.url = reverse('dashboard-trend', args=[self.project.id])

    def test_trend_returns_empty_list_when_no_snapshots(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(r.data, [])

    def test_trend_returns_snapshot_data(self):
        from django.utils.timezone import now
        today = now().date()
        DashboardSnapshot.objects.create(
            project=self.project, date=today,
            critical_open=2, high_open=5, medium_open=10,
            low_open=3, informational_open=1, total_open=21,
        )
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 1)
        self.assertEqual(r.data[0]['critical_open'], 2)

    def test_unauthenticated_cannot_get_trend(self):
        self.client.logout()
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)


class MTTRTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.project = _make_project("MTTR Proj")
        self.url = reverse('dashboard-mttr', args=[self.project.id])

    def test_mttr_returns_nulls_when_no_data(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertIsNone(r.data['critical'])
        self.assertIsNone(r.data['high'])

    def test_mttr_computes_average(self):
        from django.utils.timezone import now
        today = now().date()
        from datetime import timedelta
        DashboardSnapshot.objects.create(
            project=self.project, date=today - timedelta(days=1),
            critical_open=0, high_open=0, medium_open=0,
            low_open=0, informational_open=0, total_open=0,
            mttr_critical=4.0, mttr_high=10.0,
        )
        DashboardSnapshot.objects.create(
            project=self.project, date=today,
            critical_open=0, high_open=0, medium_open=0,
            low_open=0, informational_open=0, total_open=0,
            mttr_critical=6.0, mttr_high=20.0,
        )
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertAlmostEqual(r.data['critical'], 5.0)
        self.assertAlmostEqual(r.data['high'], 15.0)


class SnapshotNowTests(APITestCase):
    def setUp(self):
        self.staff = _make_staff()
        self.regular = _make_regular()
        self.project = _make_project("Snap Proj")
        self.url = reverse('dashboard-snapshot', args=[self.project.id])

    @patch('dashboard.tasks.take_daily_snapshot')
    def test_staff_can_trigger_snapshot(self, mock_snap):
        def side_effect(project):
            DashboardSnapshot.objects.create(
                project=project, date=date.today(),
                critical_open=0, high_open=0, medium_open=0,
                low_open=0, informational_open=0, total_open=0,
            )
        mock_snap.side_effect = side_effect
        self.client.force_authenticate(user=self.staff)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)

    def test_non_staff_cannot_trigger_snapshot(self):
        self.client.force_authenticate(user=self.regular)
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_cannot_trigger_snapshot(self):
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)
