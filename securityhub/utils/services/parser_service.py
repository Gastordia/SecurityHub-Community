"""
Universal parser service for handling scanner file uploads
Enhanced with integrated asset profiling and data categorization capabilities
"""

import os
import logging
import re
from typing import Dict, Any, List, Optional, Set
from django.core.files.uploadedfile import UploadedFile
from django.conf import settings
from urllib.parse import urlparse

from ..parsers.registry import ParserRegistry
from ..parsers.models import StandardizedFinding
from ..parsers.register_parsers import register_all_parsers

logger = logging.getLogger(__name__)


class ParserService:
    """
    Enhanced service for handling universal parser uploads with integrated capabilities
    Includes built-in asset profiling and data categorization (migrated from over-engineered services)
    """
    
    def __init__(self, enable_asset_profiling: bool = True):
        # Register all parsers on initialization
        logger.info("[INIT] Initializing Enhanced ParserService...")
        register_all_parsers()
        
        # Initialize integrated capabilities
        self.enable_asset_profiling = enable_asset_profiling
        
        # Initialize asset profiling service
        if self.enable_asset_profiling:
            try:
                from .dynamic_asset_profiling_service import DynamicAssetProfilingService
                self.asset_profiling_service = DynamicAssetProfilingService()
                logger.info("[OK] Asset profiling service initialized")
            except ImportError:
                logger.warning("[WARN] Asset profiling service not available")
                self.asset_profiling_service = None
        else:
            self.asset_profiling_service = None
        
        # MIGRATED: Parser-specific field mappings from DataCategorizationService
        self.parser_asset_mappings = {
            'nmap': {
                'ip_fields': ['ip_address'],
                'hostname_fields': ['hostname'],
                'port_fields': ['ports', 'port', 'total_ports'],
                'service_fields': ['services', 'service'],
                'protocol_fields': ['protocol'],
                'additional_extractors': ['nmap_ports_extractor'],
                'metadata_fields': ['host_status', 'os_info', 'scan_date', 'scan_type', 'extrainfo', 'product', 'version', 'state'],
                'vulnerability_fields': ['component_cpe', 'cvss_score', 'vuln_attributes']
            },
            'nessus': {
                'ip_fields': ['ip'],
                'hostname_fields': ['fqdn', 'host', 'component_name'],
                'port_fields': ['port'],
                'service_fields': ['protocol'],
                'protocol_fields': ['protocol'],
                'endpoint_fields': ['affected_endpoints'],
                'url_fields': ['url'],
                'metadata_fields': ['plugin_id', 'nessus_severity_id', 'component_version', 'epss_score', 'row_data'],
                'vulnerability_fields': ['cve_ids']
            },
            'openvas': {
                'ip_fields': ['host'],
                'hostname_fields': ['host'],
                'port_fields': ['port'],
                'service_fields': [],
                'protocol_fields': [],
                'metadata_fields': ['nvt_oid', 'row_data']
            },
            'burp': {
                'ip_fields': [],
                'hostname_fields': [],
                'port_fields': [],
                'service_fields': [],
                'protocol_fields': [],
                'endpoint_fields': ['affected_endpoints'],
                'url_fields': ['url', 'path'],
                'metadata_fields': ['serial_number', 'confidence', 'location', 'parameter'],
                'request_response_fields': ['request', 'response', 'request_response_pairs']
            },
            'zap': {
                'ip_fields': [],
                'hostname_fields': [],
                'port_fields': [],
                'service_fields': [],
                'protocol_fields': [],
                'url_fields': ['affected_assets'],
                'metadata_fields': ['plugin_id', 'risk_code', 'confidence_score']
            },
            'nuclei': {
                'ip_fields': [],
                'hostname_fields': ['host'],
                'port_fields': [],
                'service_fields': [],
                'protocol_fields': [],
                'url_fields': ['matched_at', 'host'],
                'metadata_fields': ['template_id', 'template_name', 'info']
            },
            'acunetix': {
                'ip_fields': [],
                'hostname_fields': [],
                'port_fields': [],
                'service_fields': [],
                'protocol_fields': [],
                'url_fields': ['start_url'],
                'metadata_fields': ['json_item', 'xml_item', 'report_date', 'scan_date', 'occurrence_count'],
                'request_response_fields': ['request', 'response', 'request_response_pairs'],
                'status_fields': ['active', 'false_positive', 'risk_accepted', 'static_finding', 'dynamic_finding']
            },
            'nexpose': {
                'ip_fields': [],
                'hostname_fields': ['host', 'name'],
                'port_fields': ['port'],
                'service_fields': [],
                'protocol_fields': ['protocol'],
                'endpoint_fields': ['affected_endpoints'],
                'url_fields': ['url'],
                'metadata_fields': ['desc', 'discovered_date', 'refs', 'resolution', 'severity', 'status', 'tags', 'vector'],
                'status_fields': ['duplicate', 'dynamic_finding', 'false_p', 'out_of_scope']
            },
            'appspider': {
                'ip_fields': [],
                'hostname_fields': [],
                'port_fields': [],
                'service_fields': [],
                'protocol_fields': [],
                'url_fields': ['vuln_url'],
                'metadata_fields': ['cwe_id', 'original_severity'],
                'request_response_fields': ['request', 'response']
            },
            'qualys': {
                'ip_fields': ['ip'],
                'hostname_fields': ['host'],
                'port_fields': [],
                'service_fields': [],
                'protocol_fields': [],
                'url_fields': ['url'],
                'metadata_fields': []
            }
        }
        
        logger.info("[OK] Enhanced ParserService initialized with integrated capabilities")
    
    def auto_detect_scanner_type(self, file_path: str) -> str:
        """Superior auto-detection by testing file against all parsers"""
        logger.info(f"[DETECT] Starting superior auto-detection for file: {file_path}")
        
        # Debug: Check if file exists and get file info
        if not os.path.exists(file_path):
            logger.error(f"[ERROR] File does not exist: {file_path}")
            return "unknown"
        
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        logger.info(f"[FILE] File info - Size: {file_size} bytes, Extension: {file_ext}")
        
        try:
            detected_scanners = []
            available_parsers = ParserRegistry.list_parsers()
            total_parsers = len(available_parsers)
            logger.info(f"[TEST] Testing file against {total_parsers} parsers: {available_parsers}")
            
            # Test file against all available parsers
            for i, scanner_type in enumerate(available_parsers):
                logger.info(f"[TEST] Testing parser {i+1}/{total_parsers}: {scanner_type}")
                try:
                    parser = ParserRegistry.create_parser(scanner_type)
                    if not parser:
                        logger.warning(f"[WARN] Failed to create parser instance for {scanner_type}")
                        continue
                    
                    logger.debug(f"[TEST] Created parser instance: {parser.__class__.__name__}")
                    
                    # Test validation
                    logger.debug(f"[DETECT] Running validation for {scanner_type}...")
                    validation_result = parser.validate_file(file_path)
                    logger.info(f"[DETECT] {scanner_type} validation result: {validation_result}")
                    
                    if validation_result:
                        logger.info(f"[OK] Parser {scanner_type} validated successfully")
                        detected_scanners.append(scanner_type)
                    else:
                        logger.debug(f"[ERROR] Parser {scanner_type} validation failed")
                        
                except Exception as e:
                    logger.error(f"[ERROR] Parser {scanner_type} validation error: {str(e)}")
                    import traceback
                    logger.debug(f"[ERROR] Full traceback for {scanner_type}: {traceback.format_exc()}")
                    continue
            
            logger.info(f"[DONE] Auto-detection completed. Found {len(detected_scanners)} compatible parsers: {detected_scanners}")
            
            if detected_scanners:
                # Return the first detected scanner (most likely match)
                best_match = detected_scanners[0]
                logger.info(f"🏆 Best match: {best_match}")
                return best_match
            else:
                logger.warning(f"[WARN] No compatible scanner detected for file: {file_path}")
                return "unknown"
                
        except Exception as e:
            logger.error(f"[ERROR] Error in auto-detection: {str(e)}")
            import traceback
            logger.error(f"[ERROR] Auto-detection error traceback: {traceback.format_exc()}")
            return "unknown"
    
    def parse_file(self, file: UploadedFile, scanner_type: Optional[str] = None) -> Dict[str, Any]:
        """Parse uploaded file and return standardized findings"""
        temp_path = None
        try:
            logger.info(f"📤 Starting file parsing for: {file.name}")
            logger.info(f"[INFO] File size: {file.size} bytes")
            
            # Create temporary file path for parsing
            temp_path = os.path.join(settings.MEDIA_ROOT, 'temp', file.name)
            os.makedirs(os.path.dirname(temp_path), exist_ok=True)
            
            # Save uploaded file temporarily
            with open(temp_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)
            
            logger.info(f"💾 File saved to temporary path: {temp_path}")
            
            # If scanner type not provided, use superior auto-detection
            if not scanner_type:
                logger.info("[DETECT] No scanner type provided, using auto-detection...")
                scanner_type = self.auto_detect_scanner_type(temp_path)
                if scanner_type == "unknown":
                    logger.error("[ERROR] Could not detect scanner type")
                    return {
                        'success': False,
                        'message': 'Could not detect scanner type. Please ensure the file is a valid scan report.',
                        'findings': []
                    }
            
            logger.info(f"[DONE] Using scanner type: {scanner_type}")
            
            # Get parser for detected scanner type
            parser = ParserRegistry.create_parser(scanner_type)
            if not parser:
                logger.error(f"[ERROR] No parser available for scanner type: {scanner_type}")
                return {
                    'success': False,
                    'message': f'No parser available for scanner type: {scanner_type}',
                    'findings': []
                }
            
            logger.info(f"[TEST] Found parser: {parser.__class__.__name__}")
            
            # Parse the file
            logger.info("[DETECT] Starting file parsing...")
            findings = parser.parse_findings(temp_path)
            logger.info(f"[OK] Parsed {len(findings)} findings")
                
            # Convert findings to serializable format
            logger.info("[PROCESSING] Converting findings to serializable format...")
            serialized_findings = []
            for i, finding in enumerate(findings):
                logger.debug(f"[PROCESSING] Processing finding {i+1}/{len(findings)}: {finding.title}")
                # Extract CVE IDs from raw_data
                cve_ids = finding.raw_data.get('cve_ids', []) if finding.raw_data else []
                
                serialized_finding = {
                    'title': finding.title,
                    'description': finding.description,
                    'severity': finding.severity.value,
                    'cvss_score': finding.cvss_score,
                    'cvss_vector': finding.cvss_vector,
                    'cwe_ids': finding.cwe_ids,
                    'cve_ids': cve_ids,  # Add CVE IDs to serialized finding
                    'affected_asset': finding.affected_asset,
                    'evidence': finding.evidence,
                    'solution': finding.solution,
                    'references': finding.references,
                    'scanner_type': finding.scanner_type,
                    'scanner_id': finding.scanner_id,
                    'tags': finding.tags,
                    'raw_data': finding.raw_data
                }
                serialized_findings.append(serialized_finding)
            
            logger.info(f"🎉 Successfully processed {len(serialized_findings)} findings")
            
            return {
                'success': True,
                'message': f'Successfully parsed {len(findings)} findings from {scanner_type} scan',
                'scanner_type': scanner_type,
                'findings_count': len(findings),
                'findings': serialized_findings,
                'metadata': {
                    'scanner_name': parser.get_metadata().name,
                    'scanner_version': parser.get_metadata().version,
                    'supported_formats': parser.get_metadata().supported_formats
                }
            }
                
        except Exception as e:
            logger.error(f"[ERROR] Error parsing file: {str(e)}")
            import traceback
            logger.error(f"[ERROR] Parse error traceback: {traceback.format_exc()}")
            return {
                'success': False,
                'message': f'Error parsing file: {str(e)}',
                'findings': []
            }
        finally:
            # Clean up temporary file
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                    logger.debug(f"[CLEANUP] Cleaned up temporary file: {temp_path}")
                except Exception as e:
                    logger.warning(f"[WARN] Failed to clean up temporary file {temp_path}: {str(e)}")
    
    def get_supported_scanners(self) -> List[Dict[str, Any]]:
        """Get list of supported scanners with metadata"""
        logger.info("[INFO] Getting list of supported scanners...")
        scanners = []
        for scanner_type in ParserRegistry.list_parsers():
            try:
                metadata = ParserRegistry.get_metadata(scanner_type)
                if metadata:
                    scanner_info = {
                        'type': scanner_type,
                        'name': metadata.name,
                        'version': metadata.version,
                        'description': metadata.description,
                        'supported_formats': metadata.supported_formats,
                        'author': metadata.author,
                        'website': metadata.website
                    }
                    scanners.append(scanner_info)
                    logger.debug(f"[INFO] Added scanner: {scanner_type} - {metadata.name}")
            except Exception as e:
                logger.error(f"[ERROR] Failed to get metadata for parser {scanner_type}: {str(e)}")
        
        logger.info(f"[INFO] Found {len(scanners)} supported scanners")
        return scanners
    
    def parse_file_with_asset_profiling(self, file: UploadedFile, project_id: Optional[int] = None, scanner_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse file and automatically update asset profiles
        
        Args:
            file: Uploaded scan file
            project_id: Project ID for asset profiling context
            scanner_type: Optional scanner type (auto-detected if not provided)
            
        Returns:
            Enhanced result with asset profiling information
        """
        logger.info(f"[DETECT] Starting enhanced parsing with asset profiling for project: {project_id}")
        
        # First, parse the file using the base parser service
        parse_result = self.parse_file(file, scanner_type)
        
        if not parse_result['success']:
            logger.error(f"[ERROR] Base parsing failed: {parse_result['message']}")
            return parse_result
        
        # If asset profiling is disabled, return base result
        if not self.enable_asset_profiling:
            logger.info("[INFO] Asset profiling disabled, returning base parse result")
            return parse_result
        
        try:
            # Extract asset data from findings
            asset_data = self._extract_asset_data_from_findings(parse_result['findings'])
            logger.info(f"[INFO] Extracted {len(asset_data)} unique assets from findings")
            
            # Update asset profiles if project_id is provided
            profiling_results = {}
            if project_id and asset_data:
                logger.info(f"[PROCESSING] Updating asset profiles for project {project_id}...")
                profiling_results = self._update_asset_profiles(asset_data, project_id, parse_result['scanner_type'])
            
            # Add asset profiling information to the result
            enhanced_result = parse_result.copy()
            enhanced_result.update({
                'asset_profiling': {
                    'enabled': True,
                    'assets_discovered': len(asset_data),
                    'assets_updated': profiling_results.get('updated_count', 0),
                    'assets_created': profiling_results.get('created_count', 0),
                    'profiling_errors': profiling_results.get('errors', [])
                },
                'asset_data': asset_data
            })
            
            logger.info(f"[OK] Enhanced parsing completed with asset profiling")
            return enhanced_result
            
        except Exception as e:
            logger.error(f"[ERROR] Error in asset profiling: {str(e)}")
            # Return base result if asset profiling fails
            parse_result['asset_profiling'] = {
                'enabled': True,
                'error': str(e),
                'assets_discovered': 0
            }
            return parse_result
    
    def _extract_asset_data_from_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract asset information from parsed findings"""
        assets = {}
        
        for finding in findings:
            affected_asset = finding.get('affected_asset', {})
            if not affected_asset:
                continue
            
            # Handle case where affected_asset is a string (IP address or hostname)
            if isinstance(affected_asset, str):
                # Convert string to asset dictionary
                asset_data = {
                    'ip_address': affected_asset if self._is_valid_ip_address(affected_asset) else None,
                    'hostname': affected_asset if not self._is_valid_ip_address(affected_asset) else None,
                    'name': affected_asset
                }
            else:
                # affected_asset is already a dictionary
                asset_data = affected_asset
            
            # Create asset identifier
            asset_key = self._create_asset_key(asset_data)
            if not asset_key:
                continue
            
            if asset_key not in assets:
                assets[asset_key] = {
                    'asset_id': asset_key,
                    'asset_name': asset_data.get('name', asset_key),
                    'asset_type': self._determine_asset_type(asset_data),
                    'ip_addresses': [],
                    'hostnames': [],
                    'ports': [],
                    'services': [],
                    'vulnerabilities': []
                }
            
            # Add asset details
            asset = assets[asset_key]
            
            # Add IP addresses
            if asset_data.get('ip_address'):
                if asset_data['ip_address'] not in asset['ip_addresses']:
                    asset['ip_addresses'].append(asset_data['ip_address'])
            
            # Add hostnames
            if asset_data.get('hostname'):
                if asset_data['hostname'] not in asset['hostnames']:
                    asset['hostnames'].append(asset_data['hostname'])
            
            # Add ports
            if asset_data.get('port'):
                if asset_data['port'] not in asset['ports']:
                    asset['ports'].append(asset_data['port'])
            
            # Add services
            if asset_data.get('service'):
                service_info = {
                    'name': asset_data['service'],
                    'port': asset_data.get('port'),
                    'protocol': asset_data.get('protocol', 'tcp')
                }
                if service_info not in asset['services']:
                    asset['services'].append(service_info)
            
            # Add vulnerability reference
            vuln_ref = {
                'title': finding.get('title'),
                'severity': finding.get('severity'),
                'cvss_score': finding.get('cvss_score')
            }
            asset['vulnerabilities'].append(vuln_ref)
        
        return list(assets.values())
    
    def _create_asset_key(self, affected_asset: Dict[str, Any]) -> Optional[str]:
        """Create a unique key for an asset"""
        if affected_asset.get('ip_address'):
            return f"ip:{affected_asset['ip_address']}"
        elif affected_asset.get('hostname'):
            return f"hostname:{affected_asset['hostname']}"
        elif affected_asset.get('url'):
            return f"url:{affected_asset['url']}"
        return None
    
    def _determine_asset_type(self, affected_asset: Dict[str, Any]) -> str:
        """Determine the type of asset based on available information"""
        if affected_asset.get('url'):
            return 'web_application'
        elif affected_asset.get('service'):
            return 'network_service'
        elif affected_asset.get('ip_address'):
            return 'network_host'
        elif affected_asset.get('hostname'):
            return 'hostname'
        return 'unknown'
    
    def _update_asset_profiles(self, asset_data: List[Dict[str, Any]], project_id: int, scanner_type: str) -> Dict[str, Any]:
        """Update asset profiles using the dynamic asset profiling service"""
        results = {
            'updated_count': 0,
            'created_count': 0,
            'errors': []
        }
        
        # Check if asset profiling service is available
        if not self.asset_profiling_service:
            logger.warning("[WARN] Asset profiling service not available, skipping asset profile updates")
            return results
        
        try:
            for asset in asset_data:
                try:
                    # Use the asset profiling service to create or update the asset profile
                    profile_result = self.asset_profiling_service.create_or_update_asset_profile(
                        project_id=project_id,
                        asset_data=asset
                    )
                    
                    if profile_result.get('created'):
                        results['created_count'] += 1
                    else:
                        results['updated_count'] += 1
                        
                except Exception as e:
                    error_msg = f"Failed to update profile for asset {asset.get('asset_id')}: {str(e)}"
                    logger.error(f"[ERROR] {error_msg}")
                    results['errors'].append(error_msg)
            
            logger.info(f"[DONE] Asset profiling results: {results['created_count']} created, {results['updated_count']} updated, {len(results['errors'])} errors")
            
        except Exception as e:
            logger.error(f"[ERROR] Error in batch asset profiling: {str(e)}")
            results['errors'].append(f"Batch profiling error: {str(e)}")
        
        return results
    
    def _is_valid_ip_address(self, ip: str) -> bool:
        """Check if a string is a valid IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    # MIGRATED METHODS FROM DataCategorizationService
    
    def categorize_parser_output(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Categorize parser output into asset data and vulnerability data
        MIGRATED from DataCategorizationService
        
        Args:
            findings: List of standardized findings from parser
            
        Returns:
            Dictionary with 'assets' and 'vulnerabilities' keys
        """
        logger.info(f"[INFO] Categorizing {len(findings)} findings")
        
        # Extract asset data and vulnerability data
        assets_data = self._extract_assets_data(findings)
        vulnerabilities_data = self._extract_vulnerabilities_data(findings)
        
        result = {
            'assets': assets_data,
            'vulnerabilities': vulnerabilities_data,
            'summary': {
                'assets_count': len(assets_data),
                'vulnerabilities_count': len(vulnerabilities_data),
                'findings_processed': len(findings)
            }
        }
        
        logger.info(f"[OK] Categorization complete: {len(assets_data)} assets, {len(vulnerabilities_data)} vulnerabilities")
        return result
    
    def _extract_assets_data(self, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Extract asset/scope data from findings using parser-specific mappings
        MIGRATED from DataCategorizationService
        
        Returns:
            Dictionary mapping asset identifiers to asset data
        """
        assets = {}
        
        for finding in findings:
            try:
                # Get the primary asset identifier from the parser
                affected_asset = finding.get('affected_asset')
                if not affected_asset:
                    continue
                
                # Get scanner type to use appropriate mapping
                scanner_type = finding.get('scanner_type', 'unknown')
                
                # Initialize asset if not exists
                if affected_asset not in assets:
                    assets[affected_asset] = self._initialize_asset(affected_asset, finding, scanner_type)
                
                # Update asset with information from this finding using parser-specific extraction
                self._update_asset_from_finding_with_mapping(assets[affected_asset], finding, scanner_type)
                
            except Exception as e:
                logger.warning(f"[WARN] Error extracting asset data from finding: {str(e)}")
                continue
        
        logger.info(f"[INFO] Extracted asset data for {len(assets)} unique assets")
        return assets
    
    def _initialize_asset(self, asset_id: str, finding: Dict[str, Any], scanner_type: str) -> Dict[str, Any]:
        """Initialize asset data structure - MIGRATED from DataCategorizationService"""
        raw_data = finding.get('raw_data', {})
        
        # Determine best asset name based on available data
        asset_name = asset_id
        if self._is_valid_hostname(asset_id):
            asset_name = asset_id
        elif self._is_valid_ip_address(asset_id):
            asset_name = asset_id
        else:
            # Try to extract a better name from raw_data
            asset_name = raw_data.get('host', raw_data.get('hostname', asset_id))
        
        return {
            'asset_id': asset_id,
            'asset_name': asset_name,
            'ip_addresses': set(),
            'hostnames': set(),
            'ports': set(),
            'services': set(),
            'protocols': set(),
            'endpoints': set(),
            'scanner_types': set(),
            'first_seen': None,
            'last_seen': None,
            'vulnerability_count': 0,
            'asset_type': self._determine_asset_type_from_id(asset_id),
            'source_scanners': {scanner_type},
            'enrichment_score': 0,
            'completeness': 'minimal'
        }
    
    def _update_asset_from_finding_with_mapping(self, asset: Dict[str, Any], finding: Dict[str, Any], scanner_type: str) -> None:
        """Update asset data with information from a finding using parser-specific mappings - MIGRATED from DataCategorizationService"""
        raw_data = finding.get('raw_data', {})
        
        # Get mapping for this scanner type
        mapping = self.parser_asset_mappings.get(scanner_type, {})
        
        # Extract IP addresses
        for field in mapping.get('ip_fields', []):
            if raw_data.get(field):
                ip_value = raw_data[field]
                if isinstance(ip_value, str) and self._is_valid_ip_address(ip_value):
                    asset['ip_addresses'].add(ip_value)
        
        # Extract hostnames/FQDNs
        for field in mapping.get('hostname_fields', []):
            if raw_data.get(field):
                hostname_value = raw_data[field]
                if isinstance(hostname_value, str) and hostname_value != raw_data.get('ip', ''):
                    # Only add if it's not the same as IP and is a valid hostname
                    if self._is_valid_hostname(hostname_value):
                        asset['hostnames'].add(hostname_value)
        
        # Extract ports
        for field in mapping.get('port_fields', []):
            port_value = raw_data.get(field)
            if port_value:
                if isinstance(port_value, list):
                    # Handle Nmap-style port lists
                    for port_data in port_value:
                        if isinstance(port_data, dict) and port_data.get('port'):
                            asset['ports'].add(str(port_data['port']))
                elif isinstance(port_value, str) and port_value != '0':
                    asset['ports'].add(port_value)
        
        # Extract services
        for field in mapping.get('service_fields', []):
            service_value = raw_data.get(field)
            if service_value:
                if isinstance(service_value, list):
                    asset['services'].update(service_value)
                elif isinstance(service_value, str):
                    asset['services'].add(service_value)
        
        # Extract protocols
        for field in mapping.get('protocol_fields', []):
            if raw_data.get(field):
                asset['protocols'].add(raw_data[field])
        
        # Extract endpoints
        for field in mapping.get('endpoint_fields', []):
            endpoints = raw_data.get(field, [])
            if isinstance(endpoints, list):
                for endpoint in endpoints:
                    if isinstance(endpoint, dict) and endpoint.get('url'):
                        asset['endpoints'].add(endpoint['url'])
        
        # Extract URLs
        for field in mapping.get('url_fields', []):
            url_value = raw_data.get(field)
            if url_value:
                if isinstance(url_value, list):
                    for url in url_value:
                        if isinstance(url, str):
                            asset['endpoints'].add(url)
                            # Also extract hostname/IP from URL
                            self._extract_asset_info_from_url(asset, url)
                elif isinstance(url_value, str):
                    asset['endpoints'].add(url_value)
                    # Also extract hostname/IP from URL
                    self._extract_asset_info_from_url(asset, url_value)
        
        # Track scanner types
        asset['scanner_types'].add(scanner_type)
        asset['source_scanners'].add(scanner_type)
        
        # Count vulnerabilities
        asset['vulnerability_count'] += 1
    
    def _extract_vulnerabilities_data(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract vulnerability data from findings - MIGRATED from DataCategorizationService
        
        Returns:
            List of vulnerability data dictionaries
        """
        vulnerabilities = []
        
        for finding in findings:
            try:
                vuln_data = {
                    'title': finding.get('title', 'Unknown Vulnerability'),
                    'description': finding.get('description', ''),
                    'severity': finding.get('severity', 'info'),
                    'cvss_score': finding.get('cvss_score', 0.0),
                    'cvss_vector': finding.get('cvss_vector', ''),
                    'cwe_ids': finding.get('cwe_ids', []),
                    'cve_ids': finding.get('raw_data', {}).get('cve_ids', []),
                    'solution': finding.get('solution', ''),
                    'references': finding.get('references', []),
                    'evidence': finding.get('evidence', ''),
                    'affected_asset': finding.get('affected_asset'),
                    'scanner_type': finding.get('scanner_type', 'unknown'),
                    'scanner_id': finding.get('scanner_id', ''),
                    'raw_data': finding.get('raw_data', {})
                }
                
                vulnerabilities.append(vuln_data)
                
            except Exception as e:
                logger.warning(f"[WARN] Error extracting vulnerability data from finding: {str(e)}")
                continue
        
        logger.info(f"[INFO] Extracted {len(vulnerabilities)} vulnerability records")
        return vulnerabilities
    
    def _extract_asset_info_from_url(self, asset: Dict[str, Any], url: str) -> None:
        """Extract hostname/IP and port information from URL - MIGRATED from DataCategorizationService"""
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                if self._is_valid_ip_address(parsed.hostname):
                    asset['ip_addresses'].add(parsed.hostname)
                elif self._is_valid_hostname(parsed.hostname):
                    asset['hostnames'].add(parsed.hostname)
            
            if parsed.port:
                asset['ports'].add(str(parsed.port))
                
            if parsed.scheme:
                asset['protocols'].add(parsed.scheme)
        except Exception as e:
            logger.debug(f"Could not parse URL {url}: {str(e)}")
    
    def _determine_asset_type_from_id(self, asset_id: str) -> str:
        """Determine asset type based on asset identifier - MIGRATED from DataCategorizationService"""
        if self._is_valid_ip_address(asset_id):
            return 'ip_address'
        elif self._is_valid_hostname(asset_id):
            return 'hostname'
        elif asset_id.startswith(('http://', 'https://', 'ftp://', 'tcp://', 'udp://')):
            return 'url'
        else:
            return 'unknown'
    
    def _is_valid_hostname(self, hostname: str) -> bool:
        """Check if string is a valid hostname - MIGRATED from DataCategorizationService"""
        if not hostname or len(hostname) > 253:
            return False
        
        # Check for IP address (not a hostname)
        if self._is_valid_ip_address(hostname):
            return False
        
        # Basic hostname validation
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        
        allowed = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
        return all(allowed.match(part) for part in hostname.split('.'))
