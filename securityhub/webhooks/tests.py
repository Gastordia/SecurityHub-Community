"""Tests for webhook config CRUD and delivery list."""
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

from accounts.models import CustomUser
from webhooks.models import WebhookConfig, WebhookDelivery


def _make_staff(**kw):
    d = dict(email="staff@wh.com", password="Pass1!", username="whstaff", is_staff=True)
    d.update(kw)
    return CustomUser.objects.create_user(**d)


VALID_PAYLOAD = {
    "name": "CI Hook",
    "url": "https://hooks.example.com/notify",
    "events": ["finding.created"],
    "enabled": True,
}


class WebhookConfigCRUDTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.list_url = reverse('webhook-list')

    def test_create_webhook(self):
        r = self.client.post(self.list_url, VALID_PAYLOAD, format='json')
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.assertEqual(WebhookConfig.objects.count(), 1)

    def test_list_webhooks(self):
        WebhookConfig.objects.create(
            name="H1", url="https://a.example.com", events=[], created_by=self.user,
        )
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 1)

    def test_update_webhook_via_patch(self):
        wh = WebhookConfig.objects.create(
            name="Old", url="https://a.example.com", events=[], created_by=self.user,
        )
        url = reverse('webhook-detail', args=[wh.id])
        r = self.client.patch(url, {"name": "New"}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        wh.refresh_from_db()
        self.assertEqual(wh.name, "New")

    def test_delete_webhook(self):
        wh = WebhookConfig.objects.create(
            name="Del", url="https://a.example.com", events=[], created_by=self.user,
        )
        url = reverse('webhook-detail', args=[wh.id])
        r = self.client.delete(url)
        self.assertEqual(r.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(WebhookConfig.objects.filter(id=wh.id).exists())

    def test_disable_webhook_via_patch(self):
        wh = WebhookConfig.objects.create(
            name="Toggle", url="https://a.example.com", events=[], enabled=True, created_by=self.user,
        )
        url = reverse('webhook-detail', args=[wh.id])
        r = self.client.patch(url, {"enabled": False}, format='json')
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        wh.refresh_from_db()
        self.assertFalse(wh.enabled)

    def test_unauthenticated_cannot_list(self):
        self.client.logout()
        r = self.client.get(self.list_url)
        self.assertEqual(r.status_code, status.HTTP_401_UNAUTHORIZED)


class WebhookDeliveryTests(APITestCase):
    def setUp(self):
        self.user = _make_staff()
        self.client.force_authenticate(user=self.user)
        self.wh = WebhookConfig.objects.create(
            name="Hook", url="https://a.example.com", events=[], created_by=self.user,
        )

    def test_delivery_list_empty(self):
        url = reverse('webhook-deliveries', args=[self.wh.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 0)

    def test_delivery_list_returns_records(self):
        WebhookDelivery.objects.create(
            config=self.wh, event_type="vulnerability.created",
            payload={"id": "abc"}, response_status=200, success=True,
        )
        url = reverse('webhook-deliveries', args=[self.wh.id])
        r = self.client.get(url)
        self.assertEqual(r.status_code, status.HTTP_200_OK)
        self.assertEqual(len(r.data), 1)
