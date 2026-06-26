import logging
import tempfile
import os

from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import (api_view, permission_classes, throttle_classes)
from rest_framework.permissions import IsAuthenticated  # Keep for non-RBAC endpoints only
from rest_framework.response import Response
from utils.throttles import TenantAwareThrottle
from utils.audit_logging import AuditLogger
from utils.logging_helpers import log_view_start, log_view_success, log_view_error
from utils.views import get_scoped_project
from utils.input_validation import validate_id_parameter, validate_file_upload, APIValidationError

from ..models import (ProjectScope, Project)
from ..serializers import ProjectScopeSerializer
from utils.services.scope_service import ScopeService

logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def nmap_scope_upload_view(request, id):
    """
    Render the Nmap scope upload page.
    Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('nmap_scope_upload_view', request, {'project_id': id})
    
    try:
        
        # Validate project_id
        try:
            project_id_int = validate_id_parameter(id, 'project_id')
        except APIValidationError as e:
            log_view_error('nmap_scope_upload_view', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get project with tenant scoping
        project = get_scoped_project(request, project_id_int)
        if not project:
            log_view_error('nmap_scope_upload_view', request, Project.DoesNotExist(), 
                          {'project_id': project_id_int})
            return Response({
                'success': False,
                'error': 'Project not found or access denied'
            }, status=status.HTTP_404_NOT_FOUND)
        
        context = {
            'project_id': project_id_int,
            'project': project,
            'page_title': 'Nmap Scope Upload'
        }
        
        log_view_success('nmap_scope_upload_view', request, {'project_id': project_id_int}, start_ctx['start_time'])
        return render(request, 'nmap_scope_upload.html', context)
    except Exception as e:
        log_view_error('nmap_scope_upload_view', request, e)
        return Response({
            'success': False,
            'error': 'Project not found'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def upload_nmap_scope(request, id):
    """
    Upload Nmap scan results and convert to scope inventory. Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('upload_nmap_scope', request, {'project_id': id})
    
    try:
        
        # Validate project_id
        try:
            project_id_int = validate_id_parameter(id, 'project_id')
        except APIValidationError as e:
            log_view_error('upload_nmap_scope', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate project exists with tenant scoping
        project = get_scoped_project(request, project_id_int)
        if not project:
            log_view_error('upload_nmap_scope', request, Project.DoesNotExist(), 
                          {'project_id': project_id_int})
            return Response({
                'success': False,
                'error': 'Project not found or access denied'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Debug logging
        logger.info(f"Request FILES keys: {list(request.FILES.keys())}")
        logger.info(f"Request content type: {request.content_type}")
        logger.info(f"Request data keys: {list(request.data.keys()) if hasattr(request.data, 'keys') else 'No data'}")
        
        # Check if file was uploaded
        if 'file' not in request.FILES:
            log_view_error('upload_nmap_scope', request, ValueError("No file uploaded"))
            return Response({
                'success': False,
                'error': f'No file uploaded. Available keys: {list(request.FILES.keys())}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_file = request.FILES['file']
        
        # Validate file upload
        try:
            validate_file_upload(uploaded_file, category='scan')
        except APIValidationError as e:
            log_view_error('upload_nmap_scope', request, e)
            return Response({
                'success': False,
                'error': e.message
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate file extension and detect scanner type
        file_name = uploaded_file.name.lower()
        scanner_type = None
        
        if file_name.endswith('.xml'):
            # Try to detect scanner type from filename or content
            if 'nmap' in file_name:
                scanner_type = 'nmap'
            elif 'nessus' in file_name:
                scanner_type = 'nessus'
            elif 'openvas' in file_name:
                scanner_type = 'openvas'
            elif 'burp' in file_name:
                scanner_type = 'burp'
            else:
                # Default to nmap for XML files
                scanner_type = 'nmap'
        elif file_name.endswith('.csv'):
            scanner_type = 'nessus'  # Nessus CSV format
        elif file_name.endswith('.nessus'):
            scanner_type = 'nessus'  # Nessus native format
        else:
            return Response({
                'success': False,
                'error': 'Invalid file format. Please upload an XML, CSV, or .nessus file.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Save uploaded file to temporary location
        temp_file_path = save_uploaded_file(uploaded_file)
        
        try:
            result = {'success': True, 'scope_items': [], 'asset_profiling': {}}
            
            # For Nmap files, create scope entries
            if scanner_type == 'nmap':
                scope_service = ScopeService()
                scope_result = scope_service.parse_nmap_to_scope(temp_file_path, pk)
                
                if not scope_result['success']:
                    return Response({
                        'success': False,
                        'error': scope_result['error']
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                result['scope_items'] = scope_result['scope_items']
                result['statistics'] = scope_result.get('statistics', {})
            
            
            # Save scope items to database (only for Nmap files)
            save_result = {'success': True, 'saved_count': 0, 'skipped_count': 0, 'total_processed': 0}
            
            if scanner_type == 'nmap' and result['scope_items']:
                scope_service = ScopeService()
                save_result = scope_service.save_scope_to_database(
                    result['scope_items'], 
                    pk, 
                    request.user
                )
                
                if not save_result['success']:
                    return Response({
                        'success': False,
                        'error': save_result['error']
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Return success response with statistics
            message = f'Successfully processed scan with {scanner_type} parser'
            if scanner_type == 'nmap':
                message += f' - imported {save_result["saved_count"]} scope items'
            
            # Build assets summary (already populated by comprehensive processing)
            assets_data = result.get('assets', {
                'total': 0,
                'in_scope': 0,
                'out_of_scope': 0,
                'pending_approval': 0,
                'new': 0,
                'updated': 0
            })
            
            # Build vulnerabilities summary (already populated by comprehensive processing)
            vulnerabilities_data = result.get('vulnerabilities', {
                'total': 0,
                'new': 0,
                'updated': 0
            })
            
            # Get pending approval and out of scope assets (already populated by comprehensive processing)
            pending_approval_assets = result.get('pending_approval_assets', [])
            out_of_scope_assets = result.get('out_of_scope_assets', [])
            findings_processed = result.get('findings_processed', 0)
            
            # Log audit event
            AuditLogger.log_operation(
                user=request.user,
                action='NMAP_SCOPE_UPLOADED',
                resource_type='ProjectScope',
                org_id=None,
                request=request,
                resource_id=project_id_int,
                details={
                    'scanner_type': scanner_type,
                    'saved_count': save_result.get('saved_count', 0),
                    'assets_total': assets_data.get('total', 0),
                    'assets_in_scope': assets_data.get('in_scope', 0),
                    'assets_pending': assets_data.get('pending_approval', 0)
                }
            )
            
            log_view_success('upload_nmap_scope', request, {
                'project_id': project_id_int,
                'scanner_type': scanner_type,
                'saved_count': save_result.get('saved_count', 0),
                'assets_total': assets_data.get('total', 0)
            }, start_ctx['start_time'])
            
            # Return response in format matching asset-integrated scan upload
            return Response({
                'success': True,
                'message': message,
                'data': {
                    'scanner_type': scanner_type,
                    'assets': assets_data,
                    'vulnerabilities': vulnerabilities_data,
                    'findings_processed': findings_processed,
                    'pending_approval_assets': pending_approval_assets,
                    'out_of_scope_assets': out_of_scope_assets
                },
                'statistics': result.get('statistics', {}),
                'saved_count': save_result.get('saved_count', 0),
                'skipped_count': save_result.get('skipped_count', 0),
                'total_processed': save_result.get('total_processed', 0),
                'scope_preview': result['scope_items'][:10] if result['scope_items'] else [],
                'asset_profiling': result.get('asset_profiling', {})
            })
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_file_path)
            
    except Exception as e:
        log_view_error('upload_nmap_scope', request, e)
        return Response({
            'success': False,
            'error': 'Failed to process Nmap file'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def deleteprojectscope(request):
    """
    Delete project scope. Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('deleteprojectscope', request)
    
    try:
        
        # Validate input
        if not isinstance(request.data, list) or not request.data:
            log_view_error('deleteprojectscope', request, ValueError("Invalid input: expected list of IDs"))
            return Response({
                'error': 'Invalid input: expected list of scope IDs'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate all IDs
        try:
            scope_ids = [validate_id_parameter(id_val, 'scope_id') for id_val in request.data]
        except APIValidationError as e:
            log_view_error('deleteprojectscope', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)
        
        scopes = ProjectScope.objects.filter(
            id__in=scope_ids
        )
        
        deleted_count = scopes.count()
        scopes.delete()
        
        # Log audit event
        AuditLogger.log_operation(
            user=request.user,
            action='PROJECT_SCOPE_DELETED',
            resource_type='ProjectScope',
            org_id=None,
            request=request,
            details={'deleted_count': deleted_count, 'requested_ids': scope_ids}
        )
        
        log_view_success('deleteprojectscope', request, {'deleted_count': deleted_count}, start_ctx['start_time'])
        respdata = {'Status': "Success", 'deleted_count': deleted_count}
        return Response(respdata)
        
    except Exception as e:
        log_view_error('deleteprojectscope', request, e)
        return Response({
            'error': 'Failed to delete project scope'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def project_scope_edit(request, id, scope_id):
    """
    Update or delete project scope.
    - PATCH: Edit project scope. Requires authentication (IsAuthenticated).
    - DELETE: Delete project scope. Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('project_scope_edit', request, {'project_id': id, 'scope_id': scope_id})
    
    try:
        
        # Validate project_id
        try:
            project_id_int = validate_id_parameter(id, 'project_id')
        except APIValidationError as e:
            log_view_error('project_scope_edit', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate scope_id
        try:
            scope_id_int = validate_id_parameter(scope_id, 'scope_id')
        except APIValidationError as e:
            log_view_error('project_scope_edit', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get scope with tenant scoping - verify it belongs to the project
        projectscope = ProjectScope.objects.filter(
            pk=scope_id_int,
            project__id=project_id_int
        ).first()
        
        if not projectscope:
            log_view_error('project_scope_edit', request, ProjectScope.DoesNotExist(), 
                          {'scope_id': scope_id_int, 'project_id': project_id_int})
            return Response({"message": "Scope not found or access denied"}, status=status.HTTP_404_NOT_FOUND)
        
        # Handle different HTTP methods
        if request.method == 'PATCH':
            serializer = ProjectScopeSerializer(instance=projectscope, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                
                # Log audit event
                AuditLogger.log_operation(
                    user=request.user,
                    action='PROJECT_SCOPE_EDITED',
                    resource_type='ProjectScope',
                    resource_id=scope_id_int,
                    org_id=None,
                    request=request,
                    details={'project_id': projectscope.project.id}
                )
                
                respdata = {'Status': "Success"}
                respdata.update(serializer.data)
                
                log_view_success('project_scope_edit', request, {'scope_id': scope_id_int, 'action': 'UPDATE'}, start_ctx['start_time'])
                return Response(respdata)
            else:
                log_view_error('project_scope_edit', request, ValueError("Serializer validation failed"), 
                              {'errors': str(serializer.errors)})
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        elif request.method == 'DELETE':
            # Store scope details for audit before deletion
            deleted_scope = {
                'id': projectscope.id,
                'scope_entry': projectscope.scope_entry,
                'project_id': projectscope.project.id
            }
            
            projectscope.delete()
            
            # Log audit event
            AuditLogger.log_operation(
                user=request.user,
                action='PROJECT_SCOPE_DELETED',
                resource_type='ProjectScope',
                org_id=None,
                request=request,
                details={'deleted_scope': deleted_scope}
            )
            
            log_view_success('project_scope_edit', request, {'scope_id': scope_id_int, 'action': 'DELETE'}, start_ctx['start_time'])
            return Response({'Status': "Success", "message": "Scope deleted successfully"}, status=status.HTTP_200_OK)
        
        else:
            return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
            
    except Exception as e:
        log_view_error('project_scope_edit', request, e)
        return Response({"message": "Scope not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def get_project_scopes(request, id):
    """
    Get or create project scopes.
    - GET: List project scopes. Requires authentication (IsAuthenticated).
    - POST: Add project scope. Requires authentication (IsAuthenticated).
    """
    start_ctx = log_view_start('get_project_scopes', request, {'project_id': id})
    
    try:
        
        # Validate project_id
        try:
            project_id_int = validate_id_parameter(id, 'project_id')
        except APIValidationError as e:
            log_view_error('get_project_scopes', request, e)
            return Response({'error': e.message}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get project with tenant scoping
        project = get_scoped_project(request, project_id_int)
        if not project:
            log_view_error('get_project_scopes', request, Project.DoesNotExist(),
                          {'project_id': project_id_int})
            return Response({"message": "Project not found or access denied"}, status=status.HTTP_404_NOT_FOUND)

        # Handle different HTTP methods
        if request.method == 'GET':
            # Get traditional project scopes with tenant scoping
            from django.db import models as django_models
            projectscope = ProjectScope.objects.filter(project=project)
            serializer = ProjectScopeSerializer(projectscope, many=True)
            scope_data = serializer.data
            
            # Log audit event
            AuditLogger.log_data_access(
                user=request.user,
                resource_type='ProjectScope',
                action='LIST',
                org_id=None,
                request=request,
                resource_id=project_id_int,
                details={'scope_count': len(scope_data)}
            )
            
            # Get asset profiles from project metadata
            asset_profiles = []
            asset_profiles_data = {}
            if project.standard and isinstance(project.standard, dict) and 'asset_profiles' in project.standard:
                asset_profiles_data = project.standard['asset_profiles']
            
            # Convert asset profiles to scope-like format and sort by criticality
            criticality_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'neutral': 4}
            
            for asset_id, profile in asset_profiles_data.items():
                # Create a scope-like entry for each asset
                asset_scope = {
                    'id': f"asset_{asset_id}",
                    'scope_entry': asset_id,
                    'description': f"{profile.get('asset_name', 'Unknown Asset')} - {profile.get('asset_type', 'Unknown Type')}",
                    'tags': [
                        profile.get('criticality', 'neutral'),  # Dynamic Asset Profiling uses 'criticality'
                        profile.get('asset_type', 'unknown'),
                        profile.get('asset_category', 'general'),
                        'asset_profile'
                    ],
                    'asset_info': {
                        'asset_id': asset_id,
                        'asset_name': profile.get('asset_name', 'Unknown Asset'),
                        'asset_type': profile.get('asset_type', 'Unknown Type'),
                        'asset_category': profile.get('asset_category', 'General'),
                        'business_criticality': profile.get('criticality', 'neutral'),  # Map to business_criticality for frontend
                        'ip_addresses': profile.get('ip_addresses', []),
                        'hostnames': profile.get('hostnames', []),
                        'services': profile.get('services', []),
                        'ports': profile.get('ports', []),
                        'protocols': profile.get('protocols', []),
                        'vulnerability_count': len(profile.get('vulnerabilities', [])),  # Count actual vulnerabilities
                        'scanner_types': profile.get('data_sources', []),  # Dynamic Asset Profiling uses 'data_sources'
                        'last_scan_date': profile.get('last_updated', ''),
                        'status': 'active',  # Default status
                        'criticality_score': profile.get('criticality_score', 0)
                    },
                    'criticality_order': criticality_order.get(profile.get('criticality', 'neutral'), 4)
                }
                asset_profiles.append(asset_scope)
            
            # Sort asset profiles by criticality (critical first)
            asset_profiles.sort(key=lambda x: x['criticality_order'])
        
            # Combine traditional scopes with asset profiles
            all_scopes = scope_data + asset_profiles
            
            log_view_success('get_project_scopes', request, {
                'project_id': project_id_int,
                'total_scopes': len(all_scopes)
            }, start_ctx['start_time'])
            return Response(all_scopes)
        
        elif request.method == 'POST':
            # Accept both a single scope object and a list
            data = request.data if isinstance(request.data, list) else [request.data]
            serializer = ProjectScopeSerializer(data=data, many=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save(project=project)
                
                # Log audit event
                AuditLogger.log_operation(
                    user=request.user,
                    action='PROJECT_SCOPE_ADDED',
                    resource_type='ProjectScope',
                    org_id=None,
                    request=request,
                    resource_id=project_id_int,
                    details={'scope_count': len(serializer.data)}
                )
                
                log_view_success('get_project_scopes', request, {'project_id': project_id_int, 'count': len(serializer.data), 'action': 'CREATE'}, start_ctx['start_time'])
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                log_view_error('getprojectscopes', request, ValueError("Serializer validation failed"), 
                              {'errors': str(serializer.errors)})
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        else:
            return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
        
    except Exception as e:
        from rest_framework.exceptions import ValidationError as DRFValidationError
        from django.db import IntegrityError
        if isinstance(e, DRFValidationError):
            log_view_error('get_project_scopes', request, e)
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        if isinstance(e, IntegrityError) and 'unique' in str(e).lower():
            return Response({"message": "One or more scopes already exist for this project"}, status=status.HTTP_409_CONFLICT)
        log_view_error('get_project_scopes', request, e)
        return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def save_uploaded_file(uploaded_file):
    """Save uploaded file to temporary location"""
    temp_fd, temp_path = tempfile.mkstemp(suffix='.xml')
    
    try:
        with os.fdopen(temp_fd, 'wb') as temp_file:
            for chunk in uploaded_file.chunks():
                temp_file.write(chunk)
        
        return temp_path
        
    except Exception as e:
        # Clean up on error
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise e

def cleanup_temp_file(temp_file_path):
    """Clean up temporary file"""
    try:
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
    except Exception as e:
        logger.warning(f"Could not clean up temporary file {temp_file_path}: {str(e)}")

