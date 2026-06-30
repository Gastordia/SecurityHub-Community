from django.urls import path

from .views import (
    WebhookConfigDetailView,
    WebhookConfigListCreateView,
    WebhookDeliveryListView,
    WebhookTestView,
)

urlpatterns = [
    path('', WebhookConfigListCreateView.as_view(), name='webhook-list'),
    path('<uuid:pk>/', WebhookConfigDetailView.as_view(), name='webhook-detail'),
    path('<uuid:pk>/deliveries/', WebhookDeliveryListView.as_view(), name='webhook-deliveries'),
    path('<uuid:pk>/test/', WebhookTestView.as_view(), name='webhook-test'),
]
