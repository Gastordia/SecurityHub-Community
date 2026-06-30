import logging

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from project.models import Vulnerability
from utils.throttles import TenantAwareThrottle
from utils.views import get_scoped_project

from .models import Asset
from .serializers import AssetDetailSerializer, AssetSerializer

logger = logging.getLogger(__name__)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def project_assets(request, id):
    """
    GET  /api/project/projects/<id>/assets/  — list all assets for the project,
                                               ordered by risk_score descending.
    POST /api/project/projects/<id>/assets/  — create a new asset for the project.
    """
    project = get_scoped_project(request, id)
    if project is None:
        logger.warning('project_assets: project %s not found for user %s', id, request.user.id)
        return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        assets = list(Asset.objects.filter(project=project).prefetch_related('vulnerabilities'))
        # Sort by risk_score descending (computed property, not a DB field)
        assets.sort(key=lambda a: a.risk_score, reverse=True)
        serializer = AssetSerializer(assets, many=True)
        return Response(serializer.data)

    # POST — create a new asset
    vulnerability_ids = request.data.get('vulnerability_ids', [])
    data = {k: v for k, v in request.data.items() if k != 'vulnerability_ids'}
    data['project'] = str(project.pk)

    serializer = AssetSerializer(data=data)
    if not serializer.is_valid():
        logger.warning('project_assets POST: validation error for user %s: %s', request.user.id, serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    asset = serializer.save()

    if vulnerability_ids:
        vulns = Vulnerability.objects.filter(pk__in=vulnerability_ids, project=project)
        asset.vulnerabilities.set(vulns)
        logger.debug('project_assets POST: linked %d vulnerabilities to asset %s', vulns.count(), asset.pk)

    return Response(AssetSerializer(asset).data, status=status.HTTP_201_CREATED)


@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def asset_detail(request, id, asset_id):
    """
    GET    /api/project/projects/<id>/assets/<asset_id>/  — retrieve asset detail.
    PUT    /api/project/projects/<id>/assets/<asset_id>/  — full update.
    PATCH  /api/project/projects/<id>/assets/<asset_id>/  — partial update.
    DELETE /api/project/projects/<id>/assets/<asset_id>/  — delete.
    """
    project = get_scoped_project(request, id)
    if project is None:
        logger.warning('asset_detail: project %s not found for user %s', id, request.user.id)
        return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

    try:
        asset = Asset.objects.prefetch_related('vulnerabilities').get(pk=asset_id, project=project)
    except Asset.DoesNotExist:
        logger.warning('asset_detail: asset %s not found in project %s', asset_id, id)
        return Response({'detail': 'Asset not found.'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = AssetDetailSerializer(asset)
        return Response(serializer.data)

    if request.method == 'DELETE':
        asset.delete()
        logger.debug('asset_detail DELETE: asset %s deleted from project %s', asset_id, id)
        return Response(status=status.HTTP_204_NO_CONTENT)

    # PUT / PATCH
    partial = request.method == 'PATCH'
    vulnerability_ids = request.data.get('vulnerability_ids', None)
    data = {k: v for k, v in request.data.items() if k != 'vulnerability_ids'}
    data['project'] = str(project.pk)

    serializer = AssetSerializer(asset, data=data, partial=partial)
    if not serializer.is_valid():
        logger.warning('asset_detail %s: validation error for user %s: %s', request.method, request.user.id, serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    asset = serializer.save()

    if vulnerability_ids is not None:
        vulns = Vulnerability.objects.filter(pk__in=vulnerability_ids, project=project)
        asset.vulnerabilities.set(vulns)
        logger.debug('asset_detail %s: updated vulnerabilities on asset %s', request.method, asset.pk)

    return Response(AssetDetailSerializer(asset).data)
