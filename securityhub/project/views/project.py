import logging

from configapi.bundled_docx_templates import get_bundled_docx_template
from django.core.exceptions import ObjectDoesNotExist
from django.core.cache import cache
from rest_framework_simplejwt.tokens import AccessToken
from datetime import timedelta
from rest_framework import status
from rest_framework.decorators import (api_view, permission_classes, throttle_classes)
from rest_framework.permissions import IsAuthenticated  # Keep for non-RBAC endpoints only
from rest_framework.response import Response
from django.db.models import Q
from django.utils import timezone
from utils.filters import (ProjectFilter,
                           paginate_queryset)
from utils.throttles import TenantAwareThrottle
from utils.audit_logging import AuditLogger
from utils.logging_helpers import log_view_start, log_view_success, log_view_error
from utils.input_validation import validate_id_parameter, APIValidationError
from utils.views import TenantScopedAPIView, get_scoped_project
from utils.validators import get_base_url
from ..models import Project, Vulnerability, CONFIRMED
from ..report import CheckReport
from ..serializers import ProjectSerializer

logger = logging.getLogger(__name__)



@api_view(['GET', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def getproject(request, id):
    """
    Get, update, or delete project detail.
    - GET: Requires authentication (IsAuthenticated)
    - PATCH: Requires authentication (IsAuthenticated)
    - DELETE: Requires authentication (IsAuthenticated)
    """
    start_ctx = log_view_start('getproject', request, {'id': id})
    
    try:
        org_id = None
        
        # Validate ID parameter
        try:
            id_int = validate_id_parameter(id, 'id')
        except APIValidationError as e:
            log_view_error('getproject', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)

        from utils.views import get_scoped_project
        project = get_scoped_project(request, id_int)
        if not project:
            log_view_error('getproject', request, ObjectDoesNotExist(),
                          {'id': id_int, 'org_id': org_id})
            return Response({"message": "Project not found"}, status=status.HTTP_404_NOT_FOUND)

        # Handle different HTTP methods
        if request.method == 'GET':
            serializer = ProjectSerializer(project, many=False, context={'request': request})
            
            # Log audit event
            AuditLogger.log_data_access(
                user=request.user,
                resource_type='Project',
                action='READ',
                org_id=org_id,
                request=request,
                resource_id=project.id
            )
            
            log_view_success('getproject', request, {'project_id': project.id}, start_ctx['start_time'])
            return Response(serializer.data)
        
        elif request.method == 'PATCH':
            # Store old values for audit
            old_status = project.status
            old_name = project.name
            
            serializer = ProjectSerializer(instance=project, data=request.data, context={'request': request}, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                
                # Log audit event
                AuditLogger.log_operation(
                    user=request.user,
                    action='PROJECT_UPDATED',
                    resource_type='Project',
                    resource_id=project.id,
                    org_id=org_id,
                    request=request,
                    details={
                        'updated_fields': list(request.data.keys()),
                        'old_status': old_status,
                        'new_status': project.status,
                        'old_name': old_name,
                        'new_name': project.name
                    }
                )
                
                respdata = {'Status': "Success"}
                respdata.update(serializer.data)
                
                log_view_success('getproject', request, {'project_id': project.id, 'action': 'UPDATE'}, start_ctx['start_time'])
                return Response(respdata)
            else:
                log_view_error('getproject', request, ValueError("Validation failed"), 
                              {'errors': serializer.errors})
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        elif request.method == 'DELETE':
            # Store project details for audit before deletion
            deleted_project = {
                'id': project.id,
                'name': project.name,
                'status': project.status
            }
            
            project.delete()
            
            # Clear tenant-aware cache
            cache_key = f'all_project_data:org={org_id}'
            cache.delete(cache_key)
            
            # Log audit event
            AuditLogger.log_operation(
                user=request.user,
                action='PROJECT_DELETED',
                resource_type='Project',
                org_id=org_id,
                request=request,
                details={'deleted_project': deleted_project}
            )
            
            log_view_success('getproject', request, {'project_id': id_int, 'action': 'DELETE'}, start_ctx['start_time'])
            return Response({'Status': "Success", "message": "Project deleted successfully"}, status=status.HTTP_200_OK)
        
        else:
            return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
        
    except Exception as e:
        log_view_error('getproject', request, e)
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)







class GetAllProjects(TenantScopedAPIView):
    """
    Get all projects (GET) or create new project (POST).
    """
    throttle_classes = [TenantAwareThrottle]
    
    def delete(self, request):
        """Bulk delete projects"""
        start_ctx = log_view_start('GetAllProjects.delete', request)
        try:
            # Validate input
            if not request.data or not isinstance(request.data, list):
                log_view_error('GetAllProjects.delete', request, ValueError("Invalid request data"))
                return Response({"message": "Invalid request data"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Use utility to validate IDs
            from utils.input_validation import validate_id_parameter, APIValidationError
            try:
                project_ids = [validate_id_parameter(pid, 'id') for pid in request.data]
            except APIValidationError as e:
                log_view_error('GetAllProjects.delete', request, e)
                return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)
            
            # Apply tenant scoping natively via TenantScopedAPIView
            projects_to_delete = self.scoped(Project.objects.filter(id__in=project_ids))
            deleted_projects = list(projects_to_delete.values('id', 'name', 'status'))
            count = projects_to_delete.count()
            
            if count == 0:
                log_view_success('GetAllProjects.delete', request, {'deleted_count': 0}, start_ctx['start_time'])
                return Response({'Status': "Success", "message": "No projects found or access denied", "deleted_count": 0}, status=status.HTTP_200_OK)
                
            projects_to_delete.delete()
            
            # Log audit event
            org_id = None
            AuditLogger.log_operation(
                user=request.user,
                action='PROJECT_DELETED',
                resource_type='Project',
                org_id=org_id,
                request=request,
                details={'deleted_count': count, 'deleted_projects': deleted_projects}
            )
            
            log_view_success('GetAllProjects.delete', request, {'deleted_count': count}, start_ctx['start_time'])
            respdata = {'Status': "Success", 'message': 'Projects deleted successfully', "deleted_count": count}
            return Response(respdata, status=status.HTTP_200_OK)
            
        except Exception as e:
            log_view_error('GetAllProjects.delete', request, e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get(self, request):
        start_ctx = log_view_start('GetAllProjects.get', request)
        
        try:
            from utils.pagination import StandardResultsSetPagination
            projects = self.scoped(Project.objects.prefetch_related('owner').order_by('-id'))
            projects = self.get_user_queryset(projects)

            paginator = StandardResultsSetPagination()
            page = paginator.paginate_queryset(projects, request)
            if page is not None:
                serializer = ProjectSerializer(page, many=True)
                org_id = None
                AuditLogger.log_data_access(
                    user=request.user,
                    resource_type='Project',
                    action='LIST',
                    org_id=org_id,
                    request=request,
                    details={'count': paginator.page.paginator.count}
                )
                log_view_success('GetAllProjects.get', request, {'count': paginator.page.paginator.count}, start_ctx['start_time'])
                return paginator.get_paginated_response(serializer.data)

            serializer = ProjectSerializer(projects, many=True)
            org_id = None
            AuditLogger.log_data_access(
                user=request.user,
                resource_type='Project',
                action='LIST',
                org_id=org_id,
                request=request,
                details={'count': len(serializer.data)}
            )
            log_view_success('GetAllProjects.get', request, {'count': len(serializer.data)}, start_ctx['start_time'])
            return Response({'count': len(serializer.data), 'next': None, 'previous': None, 'results': serializer.data})
            
        except Exception as e:
            log_view_error('GetAllProjects.get', request, e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """
        Create a new project. Requires authentication (IsAuthenticated).
        """
        start_ctx = log_view_start('GetAllProjects.post', request)
        try:
            org_id = None
            serializer = ProjectSerializer(data=request.data, context={'request': request})
            if serializer.is_valid(raise_exception=True):
                project = serializer.save()

                AuditLogger.log_operation(
                    user=request.user,
                    action='PROJECT_CREATED',
                    resource_type='Project',
                    resource_id=project.id,
                    org_id=org_id,
                    request=request,
                    details={'name': project.name, 'status': project.status}
                )
                log_view_success('GetAllProjects.post', request, {'project_id': project.id}, start_ctx['start_time'])
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            log_view_error('GetAllProjects.post', request, e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class GetMyProjects(TenantScopedAPIView):
    """
    Get current user's projects.
    """
    throttle_classes = [TenantAwareThrottle]
    
    def get(self, request):
        start_ctx = log_view_start('GetMyProjects.get', request)
        
        try:
            combined_projects = Project.objects.filter(
                Q(owner=request.user) &
                Q(status__in=['Upcoming', 'In Progress', 'Delay', 'On Hold'])
            ).distinct()
            combined_projects = self.scoped(combined_projects)
            combined_projects = combined_projects.prefetch_related('owner').order_by('-id')

            serializer = ProjectSerializer(combined_projects, many=True)
            
            # Log audit event
            org_id = None
            AuditLogger.log_data_access(
                user=request.user,
                resource_type='Project',
                action='LIST_OWN',
                org_id=org_id,
                request=request,
                details={'count': len(serializer.data)}
            )
            
            response_data = {
                "results": serializer.data
            }
            
            log_view_success('GetMyProjects.get', request, {'count': len(serializer.data)}, start_ctx['start_time'])
            return Response(response_data)
            
        except Exception as e:
            log_view_error('GetMyProjects.get', request, e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def get_all_projects_filter(request):
    """
    Get all projects with filtering. Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('get_all_projects_filter', request)
    
    try:
        org_id = None
        _ALLOWED_PROJECT_SORT = {'id', 'name', 'start_date', 'end_date', 'status', 'created_at', 'updated_at'}
        sort_order = request.GET.get('order_by', 'desc')
        sort_field = request.GET.get('sort', 'id') or 'id'
        if sort_field not in _ALLOWED_PROJECT_SORT:
            sort_field = 'id'

        projects = Project.objects.prefetch_related('owner')

        project_filter = ProjectFilter(request.GET, queryset=projects)
        filtered_queryset = project_filter.qs

        if sort_order == 'asc':
            filtered_queryset = filtered_queryset.order_by(sort_field)
        else:
            filtered_queryset = filtered_queryset.order_by('-' + sort_field)

        paginator, paginated_queryset = paginate_queryset(filtered_queryset, request)
        serializer = ProjectSerializer(paginated_queryset, many=True)
        
        # Log audit event
        AuditLogger.log_data_access(
            user=request.user,
            resource_type='Project',
            action='LIST_FILTERED',
            org_id=org_id,
            request=request,
            details={'count': len(serializer.data), 'filters': dict(request.GET)}
        )
        
        log_view_success('get_all_projects_filter', request, {'count': len(serializer.data)}, start_ctx['start_time'])
        return paginator.get_paginated_response(serializer.data)
        
    except Exception as e:
        log_view_error('get_all_projects_filter', request, e)
        return Response({
            'message': 'Failed to fetch projects',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def report_validation(report_type, project):
    """
    Validate project report requirements.

    Args:
        report_type: Type of report ('Audit' or 'Re-Audit')
        project: Project instance

    Returns:
        Response with error details if validation fails, None if validation passes
    """
    # Validate report_type is not None
    if not report_type:
        return Response({"Status": "Failed", "Message": "Report type is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Validating report type
    if report_type not in ['Audit', 'Re-Audit']:
        return Response({"Status": "Failed", "Message": "Report type is incorrect. Only Audit or Re-Audit are supported"}, status=status.HTTP_400_BAD_REQUEST)

    if report_type == 'Re-Audit':
        pass  # Re-Audit type accepted without retest model in community edition

    # Check if project has scope
    if not project.projectscope_set.exists():
        return Response({"Status": "Failed", "Message": "Project has no Scope added, Kindly add Scope to generate project"}, status=status.HTTP_400_BAD_REQUEST)

    # Checking if project has any vulnerabilities added
    vulnerabilities = project.vulnerability_set.all()
    if not vulnerabilities.exists():
        return Response({"Status": "Failed", "Message": "Project has no vulnerabilities, Kindly add vulnerabilities to generate project"}, status=status.HTTP_400_BAD_REQUEST)

    # Checking if vulnerabilities have instances — skip those without (scanner artifacts)
    # Require at least one vulnerability to have an instance for meaningful reports
    vulns_with_instances = [v for v in vulnerabilities if v.instances.count() > 0]
    if not vulns_with_instances:
        return Response({"Status": "Failed", "Message": "No vulnerabilities have instances/findings added. Kindly add at least one vulnerability with an instance to generate a report."}, status=status.HTTP_400_BAD_REQUEST)

    # If all validations pass, return None
    logger.info("All validations passed for project %s — %d vulns with instances", project.id, len(vulns_with_instances))
    return None



@api_view(['POST','GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def project_report(request, id):
    """
    Generate project report. Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('project_report', request, {'id': id})
    
    try:
        org_id = None
        
        # Validate ID parameter
        try:
            pk_int = validate_id_parameter(id, 'id')
        except APIValidationError as e:
            log_view_error('project_report', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)

        # Apply tenant scoping before fetching
        from utils.views import get_scoped_project
        project = get_scoped_project(request, pk_int)
        if not project:
            log_view_error('project_report', request, Project.DoesNotExist(),
                          {'pk': pk_int, 'org_id': org_id})
            return Response({"message": "Project not found"}, status=status.HTTP_404_NOT_FOUND)
        
        is_staff = request.user.is_staff
        is_superuser = request.user.is_superuser

        # Accept both query params (legacy) and request body (new frontend)
        report_format = request.data.get('format') or request.query_params.get('Format')
        report_type = request.data.get('report_type') or request.query_params.get('Type')
        template_id = request.data.get('template_id') or request.query_params.get('template_id')

        allowed_formats = ['pdf', 'docx']

        if report_format not in allowed_formats:
            log_view_error('project_report', request, ValueError("Invalid report format"),
                          {'format': report_format, 'allowed': allowed_formats})
            return Response(
                {"error": "Invalid report format."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate template_id if provided
        template_id_int = None
        if template_id:
            try:
                template_id_int = int(template_id)
                bundled_template = (
                    get_bundled_docx_template(template_id_int)
                    if report_format == 'docx'
                    else None
                )
                if not bundled_template:
                    # Verify template exists and is accessible
                    from configapi.models import ReportTemplate
                    template = ReportTemplate.objects.filter(
                        id=template_id_int,
                        format__in=[report_format, 'html' if report_format == 'pdf' else report_format],
                        is_active=True
                    ).filter(is_public=True).first()
                    if not template:
                        logger.warning(f"Template {template_id_int} not found or not accessible, ignoring")
                        template_id_int = None
            except (ValueError, TypeError):
                logger.warning(f"Invalid template_id: {template_id}, ignoring")
                template_id_int = None

        response = report_validation(report_type, project)
        if response:
            return response

    except Exception as e:
        log_view_error('project_report', request, e)
        return Response({"message": "Project not found"}, status=status.HTTP_404_NOT_FOUND)

    url = get_base_url(request)
    standard = project.standard

    # Short-lived access token scoped to report image fetching only
    _token = AccessToken.for_user(request.user)
    _token.set_exp(lifetime=timedelta(minutes=10))
    _token['report_image_access'] = True
    access_token = str(_token)

    output = CheckReport(report_format, report_type, pk_int, url, standard, request, access_token, is_staff, template_id=template_id_int, user=request.user)
    
    # Log audit event
    AuditLogger.log_operation(
        user=request.user,
        action='PROJECT_REPORT_GENERATED',
        resource_type='Project',
        resource_id=project.id,
        org_id=org_id,
        request=request,
        details={'report_format': report_format, 'report_type': report_type}
    )
    
    log_view_success('project_report', request, {'project_id': project.id, 'format': report_format}, start_ctx['start_time'])
    return output



@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def dashboard_summary(request):
    """
    Aggregate vulnerability counts for the dashboard overview cards.
    """
    start_ctx = log_view_start('dashboard_summary', request)

    vulnerabilities = Vulnerability.objects.all()
    total = vulnerabilities.count()
    critical = vulnerabilities.filter(vulnerabilityseverity__iexact='Critical').count()
    high = vulnerabilities.filter(vulnerabilityseverity__iexact='High').count()
    resolved = vulnerabilities.filter(status=CONFIRMED).count()

    data = {
        'total_vulnerabilities': total,
        'critical_vulnerabilities': critical,
        'high_vulnerabilities': high,
        'resolved_vulnerabilities': resolved,
    }
    log_view_success('dashboard_summary', request, data, start_ctx['start_time'])
    return Response(data, status=status.HTTP_200_OK)
