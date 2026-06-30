import logging

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import WebhookConfig, WebhookDelivery
from .serializers import WebhookConfigSerializer, WebhookDeliverySerializer
from .services import deliver_webhook

logger = logging.getLogger(__name__)


class WebhookConfigListCreateView(APIView):
    """List all webhook configs for the authenticated user, or create a new one."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        configs = WebhookConfig.objects.filter(created_by=request.user)
        serializer = WebhookConfigSerializer(configs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = WebhookConfigSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WebhookConfigDetailView(APIView):
    """Retrieve, update, or delete a specific webhook config."""

    permission_classes = [IsAuthenticated]

    def _get_config(self, pk, user):
        return get_object_or_404(WebhookConfig, pk=pk, created_by=user)

    def get(self, request, pk):
        config = self._get_config(pk, request.user)
        serializer = WebhookConfigSerializer(config)
        return Response(serializer.data)

    def put(self, request, pk):
        config = self._get_config(pk, request.user)
        serializer = WebhookConfigSerializer(config, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        config = self._get_config(pk, request.user)
        serializer = WebhookConfigSerializer(config, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        config = self._get_config(pk, request.user)
        config.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class WebhookDeliveryListView(APIView):
    """List the last 50 deliveries for a specific webhook config."""

    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        config = get_object_or_404(WebhookConfig, pk=pk, created_by=request.user)
        deliveries = WebhookDelivery.objects.filter(config=config)[:50]
        serializer = WebhookDeliverySerializer(deliveries, many=True)
        return Response(serializer.data)


class WebhookTestView(APIView):
    """Send a test ping payload to a webhook config's URL."""

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        config = get_object_or_404(WebhookConfig, pk=pk, created_by=request.user)
        test_payload = {
            'event': 'test',
            'message': 'This is a test delivery from SecurityHub.',
            'webhook_id': str(config.id),
            'webhook_name': config.name,
        }
        try:
            deliver_webhook(config, event_type='test', payload=test_payload, max_retries=1)
        except Exception as e:
            logger.warning("Webhook test delivery failed for config %s: %s", config.id, e)
            return Response(
                {'detail': f'Test delivery failed: {e}'},
                status=status.HTTP_502_BAD_GATEWAY,
            )
        # Check last delivery record for success/failure details
        last = WebhookDelivery.objects.filter(config=config, event_type='test').first()
        if last and last.success:
            return Response({'detail': 'Test delivery succeeded.', 'response_status': last.response_status})
        elif last:
            return Response(
                {
                    'detail': 'Test delivery failed.',
                    'response_status': last.response_status,
                    'response_body': last.response_body,
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )
        return Response({'detail': 'Test delivery sent.'})
