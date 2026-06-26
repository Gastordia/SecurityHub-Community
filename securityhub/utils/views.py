"""
Base views for the community edition.
Organization/tenant scoping is removed; all querysets are unfiltered.
"""
import logging
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
logger = logging.getLogger(__name__)


class TenantScopedAPIView(APIView):
    """
    Base view that provides scoped() and get_user_queryset() helpers.
    In the community edition these return the full queryset (no tenant filtering).
    """
    permission_classes = [IsAuthenticated]

    def scoped(self, queryset):
        return queryset

    def get_user_queryset(self, queryset):
        return queryset


from rest_framework.viewsets import ModelViewSet


class TenantScopedModelViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    resource = None

    def get_queryset(self):
        return super().get_queryset()

    def scoped(self, queryset):
        return queryset

    def get_user_queryset(self, queryset):
        return queryset


def get_scoped_project(request, project_id):
    from project.models import Project
    return Project.objects.filter(pk=project_id).first()
