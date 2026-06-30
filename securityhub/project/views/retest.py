"""
Re-test workflow views for vulnerability management.
"""
import logging

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from utils.throttles import TenantAwareThrottle
from utils.views import get_scoped_project

from ..models import Retest, Vulnerability
from ..serializers import RetestSerializer

logger = logging.getLogger(__name__)


def _get_accessible_vulnerability(request, vuln_id):
    """
    Return the Vulnerability if it belongs to a project accessible by the
    requesting user, otherwise return None.
    """
    try:
        vuln = Vulnerability.objects.select_related('project').get(pk=vuln_id)
    except (Vulnerability.DoesNotExist, Exception):
        return None
    project = get_scoped_project(request, vuln.project_id)
    if not project:
        return None
    return vuln


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def vulnerability_retests(request, vuln_id):
    """List or create retests for a vulnerability."""
    vuln = _get_accessible_vulnerability(request, vuln_id)
    if vuln is None:
        logger.warning(
            'vulnerability_retests: vuln %s not found or not accessible for user %s',
            vuln_id, request.user.id,
        )
        return Response(
            {'message': 'Vulnerability not found or access denied'},
            status=status.HTTP_404_NOT_FOUND,
        )

    if request.method == 'GET':
        retests = Retest.objects.filter(vulnerability=vuln).select_related('tester')
        serializer = RetestSerializer(retests, many=True)
        logger.info(
            'vulnerability_retests GET: returned %s retests for vuln %s user %s',
            len(serializer.data), vuln_id, request.user.id,
        )
        return Response(serializer.data)

    # POST: create a new retest
    serializer = RetestSerializer(data=request.data)
    if not serializer.is_valid():
        logger.warning(
            'vulnerability_retests POST: invalid data for vuln %s user %s errors=%s',
            vuln_id, request.user.id, serializer.errors,
        )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    retest = serializer.save(vulnerability=vuln, tester=request.user)
    logger.info(
        'vulnerability_retests POST: created retest %s for vuln %s user %s',
        retest.id, vuln_id, request.user.id,
    )
    return Response(RetestSerializer(retest).data, status=status.HTTP_201_CREATED)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def retest_detail(request, vuln_id, retest_id):
    """Retrieve, update, or delete a specific retest."""
    vuln = _get_accessible_vulnerability(request, vuln_id)
    if vuln is None:
        logger.warning(
            'retest_detail: vuln %s not found or not accessible for user %s',
            vuln_id, request.user.id,
        )
        return Response(
            {'message': 'Vulnerability not found or access denied'},
            status=status.HTTP_404_NOT_FOUND,
        )

    try:
        retest = Retest.objects.select_related('tester').get(pk=retest_id, vulnerability=vuln)
    except Retest.DoesNotExist:
        logger.warning(
            'retest_detail: retest %s not found for vuln %s user %s',
            retest_id, vuln_id, request.user.id,
        )
        return Response({'message': 'Retest not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = RetestSerializer(retest)
        return Response(serializer.data)

    if request.method == 'PUT':
        serializer = RetestSerializer(retest, data=request.data, partial=True)
        if not serializer.is_valid():
            logger.warning(
                'retest_detail PUT: invalid data for retest %s user %s errors=%s',
                retest_id, request.user.id, serializer.errors,
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        updated = serializer.save()
        logger.info(
            'retest_detail PUT: updated retest %s for vuln %s user %s',
            retest_id, vuln_id, request.user.id,
        )
        return Response(RetestSerializer(updated).data)

    # DELETE
    retest.delete()
    logger.info(
        'retest_detail DELETE: deleted retest %s for vuln %s user %s',
        retest_id, vuln_id, request.user.id,
    )
    return Response(status=status.HTTP_204_NO_CONTENT)
