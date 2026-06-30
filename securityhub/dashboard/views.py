import logging
from datetime import date, timedelta

from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from utils.throttles import TenantAwareThrottle
from utils.views import get_scoped_project

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def project_trend(request, project_id):
    """
    Return the last N days of daily snapshots for a project.

    Query param:
        days (int, default 90, max 365)
    """
    from .models import DashboardSnapshot

    project = get_scoped_project(request, project_id)
    if project is None:
        return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

    try:
        days = int(request.query_params.get('days', 90))
    except (ValueError, TypeError):
        days = 90
    days = min(max(days, 1), 365)

    since = date.today() - timedelta(days=days)
    snapshots = DashboardSnapshot.objects.filter(
        project=project,
        date__gte=since,
    ).order_by('date')

    data = [
        {
            'date': str(snap.date),
            'critical_open': snap.critical_open,
            'high_open': snap.high_open,
            'medium_open': snap.medium_open,
            'low_open': snap.low_open,
            'informational_open': snap.informational_open,
            'total_open': snap.total_open,
        }
        for snap in snapshots
    ]

    logger.info(
        'Trend data retrieved for project %s: %d snapshots over %d days',
        project_id, len(data), days,
    )
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def project_mttr(request, project_id):
    """
    Return average MTTR (mean time to remediate, in days) per severity
    across available snapshots for the last 180 days.

    Response: {"critical": 5.2, "high": 12.1, "medium": 30.4, "low": null}
    """
    from .models import DashboardSnapshot

    project = get_scoped_project(request, project_id)
    if project is None:
        return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

    since = date.today() - timedelta(days=180)
    snapshots = DashboardSnapshot.objects.filter(
        project=project,
        date__gte=since,
    )

    def _avg(values):
        values = [v for v in values if v is not None]
        return sum(values) / len(values) if values else None

    data = {
        'critical': _avg(list(snapshots.values_list('mttr_critical', flat=True))),
        'high': _avg(list(snapshots.values_list('mttr_high', flat=True))),
        'medium': _avg(list(snapshots.values_list('mttr_medium', flat=True))),
        'low': _avg(list(snapshots.values_list('mttr_low', flat=True))),
    }

    logger.info('MTTR data retrieved for project %s', project_id)
    return Response(data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def snapshot_now(request, project_id):
    """
    Manually trigger a snapshot for a single project immediately.
    Returns the created or updated snapshot.
    """
    from .models import DashboardSnapshot
    from .tasks import take_daily_snapshot

    project = get_scoped_project(request, project_id)
    if project is None:
        return Response({'detail': 'Project not found.'}, status=status.HTTP_404_NOT_FOUND)

    take_daily_snapshot(project=project)

    snap = DashboardSnapshot.objects.filter(
        project=project,
        date=date.today(),
    ).first()

    if snap is None:
        return Response({'detail': 'Snapshot could not be created.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    data = {
        'id': str(snap.id),
        'project': str(snap.project_id),
        'date': str(snap.date),
        'critical_open': snap.critical_open,
        'high_open': snap.high_open,
        'medium_open': snap.medium_open,
        'low_open': snap.low_open,
        'informational_open': snap.informational_open,
        'total_open': snap.total_open,
        'mttr_critical': snap.mttr_critical,
        'mttr_high': snap.mttr_high,
        'mttr_medium': snap.mttr_medium,
        'mttr_low': snap.mttr_low,
        'created_at': snap.created_at.isoformat(),
    }

    logger.info('Manual snapshot triggered for project %s on %s', project_id, snap.date)
    return Response(data, status=status.HTTP_201_CREATED)
