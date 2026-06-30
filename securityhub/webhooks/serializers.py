from rest_framework import serializers

from .models import WEBHOOK_EVENTS, WebhookConfig, WebhookDelivery

VALID_EVENT_TYPES = {key for key, _ in WEBHOOK_EVENTS}


class WebhookConfigSerializer(serializers.ModelSerializer):
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = WebhookConfig
        fields = [
            'id',
            'name',
            'url',
            'secret',
            'events',
            'enabled',
            'created_by',
            'created_at',
        ]
        read_only_fields = ['id', 'created_by', 'created_at']
        extra_kwargs = {
            'secret': {'write_only': True},
        }

    def validate_events(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("events must be a list.")
        invalid = [e for e in value if e not in VALID_EVENT_TYPES]
        if invalid:
            raise serializers.ValidationError(
                f"Invalid event type(s): {invalid}. "
                f"Valid choices are: {sorted(VALID_EVENT_TYPES)}"
            )
        return value


class WebhookDeliverySerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookDelivery
        fields = [
            'id',
            'config',
            'event_type',
            'payload',
            'response_status',
            'response_body',
            'success',
            'delivered_at',
            'attempt',
        ]
        read_only_fields = fields
