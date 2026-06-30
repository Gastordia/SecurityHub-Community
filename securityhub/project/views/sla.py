"""
SLA policy and breach-tracking views.
"""
import logging

from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from utils.throttles import TenantAwareThrottle

from ..models import SLAPolicy, Vulnerability
from ..serializers import SLAPolicySerializer, VulnerabilitySerializer

logger = logging.getLogger(__name__)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def sla_policy(request):
    """GET current SLA policy or PUT to update / create it."""
    policy = SLAPolicy.objects.order_by('-created_at').first()

    if request.method == 'GET':
        if policy is None:
            logger.info('sla_policy GET: no policy exists, returning defaults for user %s', request.user.id)
            # Return default values so the UI always has something to render
            default = SLAPolicy()
            serializer = SLAPolicySerializer(default)
            return Response(serializer.data)
        serializer = SLAPolicySerializer(policy)
        return Response(serializer.data)

    # PUT: create or update
    if policy is None:
        serializer = SLAPolicySerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(
                'sla_policy PUT: invalid data for user %s errors=%s',
                request.user.id, serializer.errors,
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        policy = serializer.save(created_by=request.user)
        logger.info('sla_policy PUT: created new SLA policy %s by user %s', policy.id, request.user.id)
        return Response(SLAPolicySerializer(policy).data, status=status.HTTP_201_CREATED)

    serializer = SLAPolicySerializer(policy, data=request.data, partial=True)
    if not serializer.is_valid():
        logger.warning(
            'sla_policy PUT: invalid data for user %s errors=%s',
            request.user.id, serializer.errors,
        )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    policy = serializer.save()
    logger.info('sla_policy PUT: updated SLA policy %s by user %s', policy.id, request.user.id)
    return Response(SLAPolicySerializer(policy).data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def sla_breached_findings(request):
    """
    Return all findings that are breached or due_soon across all
    user-accessible projects (capped at 100).
    """
    sla = SLAPolicy.objects.order_by('-created_at').first()
    if sla is None:
        logger.info('sla_breached_findings: no SLA policy configured, returning empty list for user %s', request.user.id)
        return Response([])

    now = timezone.now()
    from datetime import timedelta

    severity_day_pairs = [
        ('Critical', sla.critical_days),
        ('High', sla.high_days),
        ('Medium', sla.medium_days),
        ('Low', sla.low_days),
        ('Informational', sla.informational_days),
    ]

    # Collect all finding PKs that are breached or due_soon without pulling
    # everything into memory.  We filter at the DB level per severity bucket.
    from django.db.models import Q
    breach_q = Q()
    due_soon_q = Q()
    for severity, days in severity_day_pairs:
        deadline = now - timedelta(days=days)          # created before this -> breached
        due_soon_start = now - timedelta(days=days - 3)  # created before this -> due_soon
        breach_q |= Q(vulnerabilityseverity=severity, created__lte=deadline)
        due_soon_q |= Q(
            vulnerabilityseverity=severity,
            created__gt=deadline,
            created__lte=due_soon_start,
        )

    combined_q = (breach_q | due_soon_q) & ~Q(status='Confirm Fixed')

    vulns = (
        Vulnerability.objects
        .filter(combined_q)
        .select_related('project', 'created_by', 'last_updated_by')
        .order_by('created')[:100]
    )

    results = []
    for vuln in vulns:
        serializer = VulnerabilitySerializer(vuln)
        data = serializer.data
        data['sla_status'] = vuln.sla_status
        data['sla_deadline'] = vuln.sla_deadline
        results.append(data)

    logger.info(
        'sla_breached_findings: returning %s findings for user %s',
        len(results), request.user.id,
    )
    return Response(results)
