"""
Parser views for project vulnerability uploads
"""

import logging
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

from utils.services.parser_service import ParserService
from utils.views import get_scoped_project
from utils.input_validation import MAX_FILE_SIZES
from ..models import Vulnerability
from vulnerability.models import VulnerabilityDB

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def upload_parser_file(request):
    """
    Universal parser upload endpoint (no project required).
    Useful for testing parsers or general file parsing.
    """
    try:
        if 'file' not in request.FILES:
            return Response({'success': False, 'message': 'No file uploaded'},
                            status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = request.FILES['file']

        max_size = MAX_FILE_SIZES['scan']
        if uploaded_file.size > max_size:
            return Response({'success': False, 'message': f"File size too large. Maximum is {max_size // (1024 * 1024)}MB."},
                            status=status.HTTP_400_BAD_REQUEST)

        parser_service = ParserService()
        result = parser_service.parse_file(uploaded_file)

        if result['success']:
            logger.info(f"Parsed {result['findings_count']} findings from {result['scanner_type']} scan")
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response(result, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Error in upload_parser_file: {str(e)}")
        return Response({'success': False, 'message': f'Internal server error: {str(e)}'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def upload_project_parser_file(request, project_id):
    """
    Upload and parse scanner results for a specific project.
    Handles duplicate checking and stores findings as project vulnerabilities.
    """
    try:
        project = get_scoped_project(request, project_id)
        if not project:
            return Response({'success': False, 'message': 'Project not found'},
                            status=status.HTTP_404_NOT_FOUND)

        if 'file' not in request.FILES:
            return Response({'success': False, 'message': 'No file uploaded'},
                            status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = request.FILES['file']

        max_size = MAX_FILE_SIZES['scan']
        if uploaded_file.size > max_size:
            return Response({'success': False, 'message': f"File size too large. Maximum is {max_size // (1024 * 1024)}MB."},
                            status=status.HTTP_400_BAD_REQUEST)

        parser_service = ParserService()
        result = parser_service.parse_file(uploaded_file)

        if not result['success']:
            return Response(result, status=status.HTTP_400_BAD_REQUEST)

        findings = result.get('findings', [])
        processed_findings = []
        duplicates_found = 0
        new_vulnerabilities = 0

        for finding in findings:
            existing_vuln = Vulnerability.objects.filter(
                project=project,
                vulnerabilityname=finding['title']
            ).first()

            if existing_vuln:
                existing_instance = existing_vuln.instances.filter(
                    URL=finding.get('affected_asset', '')
                ).first()

                if existing_instance:
                    duplicates_found += 1
                    continue

                existing_vuln.instances.create(
                    URL=finding.get('affected_asset', ''),
                    Parameter='',
                    status='Vulnerable'
                )
                incoming_cves = finding.get('cve_ids') or []
                if incoming_cves:
                    current = existing_vuln.cve if isinstance(existing_vuln.cve, list) else []
                    merged = list(dict.fromkeys(current + incoming_cves))
                    if merged != current:
                        existing_vuln.cve = merged
                        existing_vuln.save(update_fields=['cve'])
                processed_findings.append({
                    'title': finding['title'],
                    'status': 'instance_added',
                    'vulnerability_id': existing_vuln.id
                })
            else:
                try:
                    cve_ids = finding.get('cve_ids') or []
                    new_vuln = Vulnerability.objects.create(
                        project=project,
                        vulnerabilityname=finding['title'],
                        vulnerabilitydescription=finding.get('description', ''),
                        vulnerabilityseverity=finding.get('severity', 'Medium'),
                        cvssscore=finding.get('cvss_score', 0.0),
                        cvssvector=finding.get('cvss_vector', ''),
                        vulnerabilitysolution=finding.get('solution', ''),
                        vulnerabilityreferlnk=finding.get('references', [''])[0] if finding.get('references') else '',
                        cwe=finding.get('cwe_ids', []),
                        cve=cve_ids,
                        status='Vulnerable',
                        created_by=request.user,
                        last_updated_by=request.user,
                    )

                    if finding.get('affected_asset'):
                        new_vuln.instances.create(
                            URL=finding.get('affected_asset', ''),
                            Parameter='',
                            status='Vulnerable'
                        )

                    new_vulnerabilities += 1
                    processed_findings.append({
                        'title': finding['title'],
                        'status': 'created',
                        'vulnerability_id': new_vuln.id
                    })

                except Exception as e:
                    logger.error(f"Error creating vulnerability {finding['title']}: {str(e)}")
                    processed_findings.append({
                        'title': finding['title'],
                        'status': 'error',
                        'error': str(e)
                    })

        response_data = {
            'success': True,
            'message': f'Successfully processed {len(findings)} findings from {result["scanner_type"]} scan',
            'scanner_type': result['scanner_type'],
            'total_findings': len(findings),
            'new_vulnerabilities': new_vulnerabilities,
            'duplicates_found': duplicates_found,
            'processed_findings': processed_findings,
            'metadata': result.get('metadata', {}),
        }

        logger.info(f"Project {project_id}: {new_vulnerabilities} new vulnerabilities, {duplicates_found} duplicates")
        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error in upload_project_parser_file: {str(e)}")
        return Response({'success': False, 'message': f'Internal server error: {str(e)}'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_supported_scanners(request):
    """
    Get list of supported scanners with their metadata.
    """
    try:
        parser_service = ParserService()
        scanners = parser_service.get_supported_scanners()
        return Response({'success': True, 'scanners': scanners}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error getting supported scanners: {str(e)}")
        return Response({'success': False, 'message': f'Error getting supported scanners: {str(e)}'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
