from uuid import uuid4

from django.conf import settings
from django.db import models


WEBHOOK_EVENTS = [
    ('finding.created', 'Finding Created'),
    ('finding.status_changed', 'Finding Status Changed'),
    ('finding.severity_critical', 'Critical Finding Created'),
    ('report.generated', 'Report Generated'),
    ('parser.import_complete', 'Parser Import Complete'),
]


class WebhookConfig(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    name = models.CharField(max_length=100)
    url = models.URLField(max_length=500)
    secret = models.CharField(max_length=200, blank=True)  # HMAC signing secret
    events = models.JSONField(default=list)  # list of event type strings from WEBHOOK_EVENTS
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='webhook_configs',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.url})'


class WebhookDelivery(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    config = models.ForeignKey(
        WebhookConfig,
        on_delete=models.CASCADE,
        related_name='deliveries',
    )
    event_type = models.CharField(max_length=50)
    payload = models.JSONField()
    response_status = models.IntegerField(null=True, blank=True)
    response_body = models.TextField(null=True, blank=True, max_length=2000)
    success = models.BooleanField(default=False)
    delivered_at = models.DateTimeField(auto_now_add=True)
    attempt = models.IntegerField(default=1)

    class Meta:
        ordering = ['-delivered_at']

    def __str__(self):
        return f'{self.event_type} -> {self.config.url} (attempt {self.attempt})'
