import hashlib
import hmac
import json
import logging
import time

import requests
from django.utils import timezone

logger = logging.getLogger(__name__)


def _sign_payload(secret: str, payload_bytes: bytes) -> str:
    return 'sha256=' + hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


def deliver_webhook(config, event_type: str, payload: dict, max_retries: int = 3):
    """Deliver a webhook payload to config.url with HMAC signing and retry."""
    from .models import WebhookDelivery

    payload_bytes = json.dumps(payload, default=str).encode()
    headers = {
        'Content-Type': 'application/json',
        'X-SecurityHub-Event': event_type,
        'X-SecurityHub-Delivery': str(config.id),
    }
    if config.secret:
        headers['X-Hub-Signature-256'] = _sign_payload(config.secret, payload_bytes)

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(config.url, data=payload_bytes, headers=headers, timeout=10)
            success = 200 <= resp.status_code < 300
            WebhookDelivery.objects.create(
                config=config,
                event_type=event_type,
                payload=payload,
                response_status=resp.status_code,
                response_body=resp.text[:2000],
                success=success,
                attempt=attempt,
            )
            if success:
                return
            if attempt < max_retries:
                time.sleep(2 ** attempt)  # exponential backoff
        except Exception as e:
            logger.warning(
                "Webhook delivery attempt %s failed for %s: %s",
                attempt,
                config.url,
                e,
            )
            WebhookDelivery.objects.create(
                config=config,
                event_type=event_type,
                payload=payload,
                success=False,
                attempt=attempt,
            )
            if attempt < max_retries:
                time.sleep(2 ** attempt)


def fire_event(event_type: str, payload: dict):
    """
    Find all enabled WebhookConfigs subscribed to event_type and deliver in background threads.
    """
    import threading

    from .models import WebhookConfig

    configs = WebhookConfig.objects.filter(enabled=True)
    for config in configs:
        if event_type in (config.events or []):
            t = threading.Thread(
                target=deliver_webhook,
                args=(config, event_type, payload),
                daemon=True,
            )
            t.start()


def build_finding_payload(finding) -> dict:
    return {
        'id': str(finding.id),
        'title': finding.vulnerabilityname,
        'severity': finding.vulnerabilityseverity,
        'status': finding.status,
        'project_id': str(finding.project_id),
        'created': finding.created.isoformat() if finding.created else None,
    }


def build_slack_payload(event_type: str, data: dict) -> dict:
    """Format payload as a Slack Block Kit message."""
    severity = data.get('severity', 'Unknown')
    color_map = {
        'Critical': '#FF491C',
        'High': '#F66E09',
        'Medium': '#FBBC02',
        'Low': '#20B803',
    }
    color = color_map.get(severity, '#666666')
    return {
        'attachments': [{
            'color': color,
            'blocks': [
                {
                    'type': 'header',
                    'text': {'type': 'plain_text', 'text': f'SecurityHub: {event_type}'},
                },
                {
                    'type': 'section',
                    'fields': [
                        {'type': 'mrkdwn', 'text': f'*Finding:*\n{data.get("title", "N/A")}'},
                        {'type': 'mrkdwn', 'text': f'*Severity:*\n{severity}'},
                    ],
                },
            ],
        }]
    }


def build_teams_payload(event_type: str, data: dict) -> dict:
    """Format payload as a Microsoft Teams Adaptive Card."""
    return {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'themeColor': 'FF491C',
        'summary': f'SecurityHub: {event_type}',
        'sections': [{
            'activityTitle': f'SecurityHub: {event_type}',
            'facts': [
                {'name': k, 'value': str(v)}
                for k, v in data.items()
                if v
            ],
        }],
    }
