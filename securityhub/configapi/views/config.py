from rest_framework.decorators import api_view, permission_classes, throttle_classes
from django.conf import settings
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser  # Keep for non-RBAC endpoints only
from utils.throttles import TenantAwareThrottle
from utils.audit_logging import AuditLogger
from utils.logging_helpers import log_view_start, log_view_success, log_view_error
from utils.input_validation import validate_id_parameter, APIValidationError
from ..models import ReportStandard, ProjectType
from ..serializers import ReportStandardSerializer, ProjectTypeSerializer
import logging
import requests as http_requests
from utils.validators import validate_github_url

logger = logging.getLogger(__name__)

REPORT_STANDARD_LIST_CACHE_KEY = "report_standard_list"
PROJECT_TYPE_LIST_CACHE_KEY = "project_type_list"

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def list_report_standards(request):
    """
    Read-only list of report standards. Populated via sync_report_standards_from_github.
    Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('list_report_standards', request)

    try:
        cache_key = REPORT_STANDARD_LIST_CACHE_KEY
        cached_data = cache.get(cache_key)
        if cached_data:
            log_view_success('list_report_standards', request, {'cached': True, 'count': len(cached_data)},
                           start_ctx['start_time'])
            return Response(cached_data)

        queryset = ReportStandard.objects.all()
        serializer = ReportStandardSerializer(queryset, many=True)

        cache.set(cache_key, serializer.data, 3600)

        AuditLogger.log_data_access(
            user=request.user,
            resource_type='ReportStandard',
            action='LIST',
            org_id=None,
            request=request,
            details={'count': len(serializer.data)}
        )

        log_view_success('list_report_standards', request, {'count': len(serializer.data)},
                        start_ctx['start_time'])
        return Response(serializer.data)

    except Exception as e:
        log_view_error('list_report_standards', request, e)
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def edit_report_standard(request, id):
    """
    Read-only detail view for a single report standard.
    Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('edit_report_standard', request, {'id': id})

    try:
        try:
            id_int = validate_id_parameter(id, 'id')
        except APIValidationError as e:
            log_view_error('edit_report_standard', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)

        try:
            report_standard = ReportStandard.objects.get(pk=id_int)
        except ReportStandard.DoesNotExist:
            log_view_error('edit_report_standard', request, ReportStandard.DoesNotExist(),
                          {'id': id_int})
            return Response(
                {'error': 'Report standard not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = ReportStandardSerializer(report_standard)

        AuditLogger.log_data_access(
            user=request.user,
            resource_type='ReportStandard',
            action='READ',
            org_id=None,
            request=request,
            resource_id=report_standard.id
        )

        log_view_success('edit_report_standard', request, {'report_standard_id': report_standard.id},
                        start_ctx['start_time'])
        return Response(serializer.data)

    except Exception as e:
        log_view_error('edit_report_standard', request, e)
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )



@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
@throttle_classes([TenantAwareThrottle])
def sync_report_standards_from_github(request):
    """
    Pull the report-standards library (a JSON array of {"name": "..."} objects)
    from the configured GitHub URL and upsert every entry. Admin-only.
    """
    github_url = getattr(settings, 'REPORT_STANDARDS_GITHUB_URL', None)
    if not github_url:
        return Response(
            {"message": "REPORT_STANDARDS_GITHUB_URL is not configured in settings."},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if not validate_github_url(github_url):
        return Response({"message": "REPORT_STANDARDS_GITHUB_URL must point to github.com or raw.githubusercontent.com."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        resp = http_requests.get(github_url, timeout=15)
        resp.raise_for_status()
    except http_requests.exceptions.Timeout:
        logger.error("Report standards sync: request to %s timed out", github_url)
        return Response({"message": "Request to GitHub timed out."}, status=status.HTTP_504_GATEWAY_TIMEOUT)
    except http_requests.exceptions.RequestException as exc:
        logger.error("Report standards sync: failed to fetch %s — %s", github_url, exc)
        return Response({"message": f"Failed to fetch library: {exc}"}, status=status.HTTP_502_BAD_GATEWAY)

    try:
        entries = resp.json()
    except ValueError:
        return Response({"message": "Remote file is not valid JSON."}, status=status.HTTP_502_BAD_GATEWAY)

    if not isinstance(entries, list):
        return Response({"message": "Expected a JSON array at the root level."}, status=status.HTTP_502_BAD_GATEWAY)

    created = updated = skipped = 0
    for entry in entries:
        name = (entry.get('name') if isinstance(entry, dict) else None)
        name = name.strip() if isinstance(name, str) else ''
        if not name:
            skipped += 1
            continue
        _, was_created = ReportStandard.objects.update_or_create(name=name)
        if was_created:
            created += 1
        else:
            updated += 1

    cache.delete(REPORT_STANDARD_LIST_CACHE_KEY)

    logger.info("Report standards sync complete: %d created, %d updated, %d skipped", created, updated, skipped)
    return Response({
        "message": "Sync complete.",
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "total": len(entries),
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def list_project_types(request):
    """
    Read-only list of project types. Populated via sync_project_types_from_github.
    Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('list_project_types', request)

    try:
        cache_key = PROJECT_TYPE_LIST_CACHE_KEY
        cached_data = cache.get(cache_key)
        if cached_data:
            log_view_success('list_project_types', request, {'cached': True, 'count': len(cached_data)},
                           start_ctx['start_time'])
            return Response(cached_data)

        queryset = ProjectType.objects.all()
        serializer = ProjectTypeSerializer(queryset, many=True)

        cache.set(cache_key, serializer.data, 3600)

        AuditLogger.log_data_access(
            user=request.user,
            resource_type='ProjectType',
            action='LIST',
            org_id=None,
            request=request,
            details={'count': len(serializer.data)}
        )

        log_view_success('list_project_types', request, {'count': len(serializer.data)},
                        start_ctx['start_time'])
        return Response(serializer.data)

    except Exception as e:
        log_view_error('list_project_types', request, e)
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def edit_project_type(request, id):
    """
    Read-only detail view for a single project type.
    Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('edit_project_type', request, {'id': id})

    try:
        try:
            id_int = validate_id_parameter(id, 'id')
        except APIValidationError as e:
            log_view_error('edit_project_type', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)

        try:
            project_type = ProjectType.objects.get(pk=id_int)
        except ProjectType.DoesNotExist:
            log_view_error('edit_project_type', request, ProjectType.DoesNotExist(),
                          {'id': id_int})
            return Response(
                {'error': 'Project type not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = ProjectTypeSerializer(project_type)

        AuditLogger.log_data_access(
            user=request.user,
            resource_type='ProjectType',
            action='READ',
            org_id=None,
            request=request,
            resource_id=project_type.id
        )

        log_view_success('edit_project_type', request, {'project_type_id': project_type.id},
                        start_ctx['start_time'])
        return Response(serializer.data)

    except Exception as e:
        log_view_error('edit_project_type', request, e)
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )



@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
@throttle_classes([TenantAwareThrottle])
def sync_project_types_from_github(request):
    """
    Pull the project-types library (a JSON array of {"name": "..."} objects)
    from the configured GitHub URL and upsert every entry. Admin-only.
    """
    github_url = getattr(settings, 'PROJECT_TYPES_GITHUB_URL', None)
    if not github_url:
        return Response(
            {"message": "PROJECT_TYPES_GITHUB_URL is not configured in settings."},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if not validate_github_url(github_url):
        return Response({"message": "PROJECT_TYPES_GITHUB_URL must point to github.com or raw.githubusercontent.com."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        resp = http_requests.get(github_url, timeout=15)
        resp.raise_for_status()
    except http_requests.exceptions.Timeout:
        logger.error("Project types sync: request to %s timed out", github_url)
        return Response({"message": "Request to GitHub timed out."}, status=status.HTTP_504_GATEWAY_TIMEOUT)
    except http_requests.exceptions.RequestException as exc:
        logger.error("Project types sync: failed to fetch %s — %s", github_url, exc)
        return Response({"message": f"Failed to fetch library: {exc}"}, status=status.HTTP_502_BAD_GATEWAY)

    try:
        entries = resp.json()
    except ValueError:
        return Response({"message": "Remote file is not valid JSON."}, status=status.HTTP_502_BAD_GATEWAY)

    if not isinstance(entries, list):
        return Response({"message": "Expected a JSON array at the root level."}, status=status.HTTP_502_BAD_GATEWAY)

    created = updated = skipped = 0
    for entry in entries:
        name = (entry.get('name') if isinstance(entry, dict) else None)
        name = name.strip() if isinstance(name, str) else ''
        if not name:
            skipped += 1
            continue
        _, was_created = ProjectType.objects.update_or_create(name=name)
        if was_created:
            created += 1
        else:
            updated += 1

    cache.delete(PROJECT_TYPE_LIST_CACHE_KEY)

    logger.info("Project types sync complete: %d created, %d updated, %d skipped", created, updated, skipped)
    return Response({
        "message": "Sync complete.",
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "total": len(entries),
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
def ping(request):
    """
    Health check endpoint. No authentication required.
    """
    logger.debug("Health check ping", extra={
        'request_id': getattr(request, 'request_id', None),
        'ip_address': request.META.get('REMOTE_ADDR'),
    })
    return Response({'status': 'ok', 'message': 'Server is up and running!'}, status=status.HTTP_200_OK)


# ============================================================================
# TEMPLATE MANAGEMENT ENDPOINTS
# ============================================================================

TEMPLATE_LIST_CACHE_KEY = "template_list"


