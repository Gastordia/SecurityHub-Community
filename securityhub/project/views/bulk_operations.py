import logging

from django.db import transaction
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from utils.throttles import TenantAwareThrottle
from utils.audit_logging import AuditLogger
from utils.views import get_scoped_project

from ..models import Vulnerability, STATUS_CHOICES

logger = logging.getLogger(__name__)

BULK_ACTIONS = {'change_status', 'change_severity', 'delete'}

VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational'}
VALID_STATUSES = {choice[0] for choice in STATUS_CHOICES}


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def bulk_vulnerability_action(request, id):
    """
    Perform a bulk action on multiple vulnerabilities within a project.

    POST body:
      {
        "action": "change_status" | "change_severity" | "delete",
        "ids": ["<uuid>", ...],          // list of vulnerability UUIDs
        "value": "<status or severity>"  // required for change_status / change_severity
      }
    """
    project = get_scoped_project(request, id)
    if not project:
        return Response({"message": "Project not found or access denied"}, status=status.HTTP_404_NOT_FOUND)

    action = request.data.get('action')
    ids = request.data.get('ids')
    value = request.data.get('value')

    if not action or action not in BULK_ACTIONS:
        return Response(
            {"message": f"Invalid action. Must be one of: {', '.join(sorted(BULK_ACTIONS))}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not ids or not isinstance(ids, list) or len(ids) == 0:
        return Response({"message": "ids must be a non-empty list"}, status=status.HTTP_400_BAD_REQUEST)

    if len(ids) > 200:
        return Response({"message": "Cannot operate on more than 200 findings at once"}, status=status.HTTP_400_BAD_REQUEST)

    if action in ('change_status', 'change_severity') and not value:
        return Response({"message": f"value is required for action '{action}'"}, status=status.HTTP_400_BAD_REQUEST)

    if action == 'change_status' and value not in VALID_STATUSES:
        return Response(
            {"message": f"Invalid status '{value}'. Valid: {', '.join(sorted(VALID_STATUSES))}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if action == 'change_severity' and value not in VALID_SEVERITIES:
        return Response(
            {"message": f"Invalid severity '{value}'. Valid: {', '.join(sorted(VALID_SEVERITIES))}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    queryset = Vulnerability.objects.filter(project=project, id__in=ids)
    matched_count = queryset.count()

    if matched_count == 0:
        return Response({"message": "No matching vulnerabilities found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        with transaction.atomic():
            if action == 'change_status':
                queryset.update(status=value, last_updated_by=request.user)
                detail = f"Status changed to '{value}'"
            elif action == 'change_severity':
                queryset.update(vulnerabilityseverity=value, last_updated_by=request.user)
                detail = f"Severity changed to '{value}'"
            elif action == 'delete':
                queryset.delete()
                detail = "Deleted"
    except Exception as e:
        logger.error("Bulk operation failed: %s", e)
        return Response({"message": "Bulk operation failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    AuditLogger.log_operation(
        user=request.user,
        action=f'BULK_{action.upper()}',
        resource_type='Vulnerability',
        resource_id=str(project.id),
        request=request,
        details={'action': action, 'value': value, 'count': matched_count},
    )

    return Response({
        "affected": matched_count,
        "action": action,
        "detail": detail,
    }, status=status.HTTP_200_OK)
