import logging

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from utils.throttles import TenantAwareThrottle
from utils.views import get_scoped_project

from ..models import FindingComment, Vulnerability
from ..serializers import FindingCommentSerializer

logger = logging.getLogger(__name__)


def _get_accessible_vulnerability(request, vuln_id):
    try:
        vuln = Vulnerability.objects.select_related('project').get(pk=vuln_id)
    except (Vulnerability.DoesNotExist, Exception):
        return None
    return vuln if get_scoped_project(request, vuln.project_id) else None


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def vulnerability_comments(request, vuln_id):
    """List visible comments or create a new comment on a finding."""
    vuln = _get_accessible_vulnerability(request, vuln_id)
    if not vuln:
        return Response({"message": "Not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        qs = FindingComment.objects.filter(vulnerability=vuln, is_deleted=False)
        # Non-staff users cannot see internal comments
        if not request.user.is_staff:
            qs = qs.filter(is_internal=False)
        serializer = FindingCommentSerializer(qs, many=True)
        return Response(serializer.data)

    # POST — create
    serializer = FindingCommentSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    serializer.save(author=request.user, vulnerability=vuln)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def comment_detail(request, vuln_id, comment_id):
    """Retrieve, update, or soft-delete a specific comment."""
    vuln = _get_accessible_vulnerability(request, vuln_id)
    if not vuln:
        return Response({"message": "Not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        comment = FindingComment.objects.get(pk=comment_id, vulnerability=vuln, is_deleted=False)
    except FindingComment.DoesNotExist:
        return Response({"message": "Comment not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        return Response(FindingCommentSerializer(comment).data)

    # Only the author or staff can modify/delete
    if comment.author_id != request.user.id and not request.user.is_staff:
        return Response({"message": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'DELETE':
        comment.is_deleted = True
        comment.save(update_fields=['is_deleted', 'updated_at'])
        return Response(status=status.HTTP_204_NO_CONTENT)

    # PUT / PATCH
    partial = request.method == 'PATCH'
    serializer = FindingCommentSerializer(comment, data=request.data, partial=partial)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    serializer.save()
    return Response(serializer.data)
