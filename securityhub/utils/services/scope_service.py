"""
Scope Service
Converts Nmap scan results into scope inventory with automatic tagging
"""

import re
import logging
from typing import List, Dict, Any, Set
from utils.parsers.nmap.parser import NmapParser
from utils.parsers.models import StandardizedFinding

logger = logging.getLogger(__name__)


class ScopeService:
    """Service for converting Nmap scan results to scope inventory"""
    
    def __init__(self):
        """Initialize the scope service"""
        self.nmap_parser = NmapParser()
        
        # Service detection patterns for tagging
        self.service_patterns = {
            'web_server': [
                r'http', r'https', r'apache', r'nginx', r'iis', r'tomcat', 
                r'jboss', r'weblogic', r'websphere', r'lighttpd', r'cherokee'
            ],
            'database': [
                r'mysql', r'postgresql', r'oracle', r'sqlserver', r'mongodb', 
                r'redis', r'cassandra', r'elasticsearch', r'couchdb', r'neo4j'
            ],
            'mail_server': [
                r'smtp', r'pop3', r'imap', r'exchange', r'postfix', r'sendmail', 
                r'qmail', r'dovecot', r'cyrus'
            ],
            'file_server': [
                r'ftp', r'sftp', r'smb', r'nfs', r'cifs', r'afp', r'webdav'
            ],
            'dns_server': [
                r'dns', r'bind', r'powerdns', r'nsd', r'knot'
            ],
            'vpn_server': [
                r'openvpn', r'pptp', r'l2tp', r'ipsec', r'wireguard'
            ],
            'remote_access': [
                r'ssh', r'telnet', r'rdp', r'vnc', r'teamviewer', r'anydesk'
            ],
            'monitoring': [
                r'snmp', r'nagios', r'zabbix', r'prometheus', r'grafana'
            ],
            'windows': [
                r'windows', r'active\s*directory', r'domain\s*controller', 
                r'exchange', r'sharepoint', r'iis', r'rdp', r'smb'
            ],
            'linux': [
                r'linux', r'unix', r'ubuntu', r'centos', r'redhat', r'debian', 
                r'fedora', r'suse', r'gentoo', r'arch'
            ],
            'network_device': [
                r'cisco', r'juniper', r'fortinet', r'palo\s*alto', r'check\s*point',
                r'router', r'switch', r'firewall', r'load\s*balancer'
            ],
            'cloud': [
                r'aws', r'azure', r'gcp', r'cloudflare', r'heroku', r'digitalocean'
            ]
        }
    
    def parse_nmap_to_scope(self, file_path: str, project_id: int) -> Dict[str, Any]:
        """
        Parse Nmap scan results and convert to scope inventory
        
        Args:
            file_path: Path to Nmap XML file
            project_id: ID of the project to associate scope with
            
        Returns:
            Dictionary with scope inventory and statistics
        """
        try:
            # Parse Nmap file
            logger.info(f"Starting to parse Nmap file: {file_path}")
            findings = self.nmap_parser.parse_findings(file_path)
            logger.info(f"Nmap parser returned {len(findings)} findings")
            
            # Log first finding structure
            if findings:
                logger.info(f"First finding raw_data: {findings[0].raw_data}")
                logger.info(f"First finding affected_asset: {findings[0].affected_asset}")
                logger.info(f"First finding title: {findings[0].title}")
            
            # Convert findings to scope inventory
            scope_items = self._convert_findings_to_scope(findings)
            
            # Generate statistics
            stats = self._generate_statistics(scope_items)
            
            return {
                'success': True,
                'scope_items': scope_items,
                'statistics': stats,
                'project_id': project_id,
                'total_hosts': len(scope_items)
            }
            
        except Exception as e:
            logger.error(f"Error parsing Nmap to scope: {str(e)}")
            return {
                'success': False,
                'error': f'Error parsing Nmap file: {str(e)}'
            }
    
    def _convert_findings_to_scope(self, findings: List[StandardizedFinding]) -> List[Dict[str, Any]]:
        """Convert Nmap findings to scope inventory items"""
        scope_items = []
        processed_hosts = set()
        
        for finding in findings:
            # Extract host information from finding
            host_info = self._extract_host_info(finding)
            
            if not host_info or host_info['ip'] in processed_hosts:
                continue
            
            processed_hosts.add(host_info['ip'])
            
            # Generate scope item
            scope_item = {
                'ip_address': host_info['ip'],
                'hostname': host_info['hostname'],
                'ports': host_info['ports'],
                'services': host_info['services'],
                'os_info': host_info['os_info'],
                'tags': self._generate_tags(host_info),
                'scope_entry': self._generate_scope_entry(host_info),
                'description': self._generate_description(host_info),
                'nmap_details': host_info.get('nmap_details', {})
            }
            
            scope_items.append(scope_item)
        
        return scope_items
    
    def _extract_host_info(self, finding: StandardizedFinding) -> Dict[str, Any]:
        """Extract host information from Nmap finding"""
        try:
            # Parse the raw data from Nmap finding
            raw_data = finding.raw_data
            logger.info(f"Processing finding with raw_data: {raw_data}")
            
            # Extract IP address
            ip_address = raw_data.get('ip_address', '')
            if not ip_address:
                # Try to extract from affected_asset
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', finding.affected_asset or '')
                if ip_match:
                    ip_address = ip_match.group(1)
                else:
                    # If still no IP, try to extract from scope entry
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', finding.title or '')
                    if ip_match:
                        ip_address = ip_match.group(1)
                    else:
                        logger.warning(f"Could not extract IP address from finding: {finding.title}")
                        return None
            
            # Extract port information - handle both single port and multiple ports
            ports = []
            services = []
            
            # Check if we have port_info (single port) or ports (multiple ports)
            if 'port_info' in raw_data:
                port_info = raw_data.get('port_info', {})
                port = port_info.get('port', '')
                protocol = port_info.get('protocol', 'tcp')
                service = port_info.get('service', '')
                version = port_info.get('version', '')
                
                if port:
                    ports.append({
                        'port': port,
                        'protocol': protocol,
                        'service': service,
                        'version': version,
                        'state': 'open'
                    })
                    if service:
                        services.append(service)
            
            elif 'ports' in raw_data:
                # Handle multiple ports
                for port_data in raw_data.get('ports', []):
                    port = port_data.get('port', '')
                    protocol = port_data.get('protocol', 'tcp')
                    service = port_data.get('service', '')
                    version = port_data.get('version', '')
                    state = port_data.get('state', 'open')
                    
                    if port:
                        ports.append({
                            'port': port,
                            'protocol': protocol,
                            'service': service,
                            'version': version,
                            'state': state
                        })
                        if service:
                            services.append(service)
            
            # Also check for services array in raw_data
            if 'services' in raw_data:
                services.extend(raw_data.get('services', []))
            
            # Extract OS information
            os_info = raw_data.get('os_info', {})
            os_name = os_info.get('name', '')
            os_version = os_info.get('version', '')
            
            # Extract hostname
            hostname = raw_data.get('hostname', '')
            
            return {
                'ip': ip_address,
                'hostname': hostname,
                'ports': ports,
                'services': services,
                'os_info': {
                    'name': os_name,
                    'version': os_version
                },
                'nmap_details': raw_data  # Store full Nmap data for collapsing menu
            }
            
        except Exception as e:
            logger.error(f"Error extracting host info: {str(e)}")
            return None
    
    def _generate_tags(self, host_info: Dict[str, Any]) -> List[str]:
        """Generate tags based on services and OS information"""
        tags = set()
        
        # Add OS-based tags
        os_name = host_info['os_info'].get('name', '').lower()
        if 'windows' in os_name:
            tags.add('windows')
        elif any(os_type in os_name for os_type in ['linux', 'unix', 'ubuntu', 'centos', 'redhat', 'debian']):
            tags.add('linux')
        
        # Add service-based tags
        services_text = ' '.join(host_info['services']).lower()
        
        for tag_type, patterns in self.service_patterns.items():
            for pattern in patterns:
                if re.search(pattern, services_text, re.IGNORECASE):
                    tags.add(tag_type)
                    break
        
        # Add network-based tags
        ip = host_info['ip']
        if self._is_private_ip(ip):
            tags.add('internal')
        else:
            tags.add('external')
        
        # Add port-based tags
        ports = [port['port'] for port in host_info['ports']]
        if any(port in ['80', '443', '8080', '8443'] for port in ports):
            tags.add('web')
        if any(port in ['22', '23', '3389'] for port in ports):
            tags.add('remote_access')
        
        return list(tags)
    
    def _generate_scope_entry(self, host_info: Dict[str, Any]) -> str:
        """Generate scope entry string"""
        ip = host_info['ip']
        hostname = host_info['hostname']
        
        if hostname:
            return f"{hostname} ({ip})"
        else:
            return ip
    
    def _generate_description(self, host_info: Dict[str, Any]) -> str:
        """Generate description for scope item - show only tags"""
        tags = self._generate_tags(host_info)
        if tags:
            return ', '.join(tags)
        return ""
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            # Fallback regex patterns for private IPs
            private_patterns = [
                r'^10\.',
                r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
                r'^192\.168\.',
                r'^127\.',
                r'^169\.254\.'
            ]
            return any(re.match(pattern, ip) for pattern in private_patterns)
    
    def _generate_statistics(self, scope_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics from scope items"""
        stats = {
            'total_hosts': len(scope_items),
            'internal_hosts': 0,
            'external_hosts': 0,
            'windows_hosts': 0,
            'linux_hosts': 0,
            'web_servers': 0,
            'database_servers': 0,
            'mail_servers': 0,
            'file_servers': 0,
            'remote_access_hosts': 0,
            'tag_distribution': {},
            'port_distribution': {},
            'service_distribution': {}
        }
        
        for item in scope_items:
            tags = item['tags']
            
            # Count by network type
            if 'internal' in tags:
                stats['internal_hosts'] += 1
            if 'external' in tags:
                stats['external_hosts'] += 1
            
            # Count by OS
            if 'windows' in tags:
                stats['windows_hosts'] += 1
            if 'linux' in tags:
                stats['linux_hosts'] += 1
            
            # Count by service type
            if 'web_server' in tags:
                stats['web_servers'] += 1
            if 'database' in tags:
                stats['database_servers'] += 1
            if 'mail_server' in tags:
                stats['mail_servers'] += 1
            if 'file_server' in tags:
                stats['file_servers'] += 1
            if 'remote_access' in tags:
                stats['remote_access_hosts'] += 1
            
            # Count tags
            for tag in tags:
                stats['tag_distribution'][tag] = stats['tag_distribution'].get(tag, 0) + 1
            
            # Count ports
            for port_info in item['ports']:
                port = port_info['port']
                stats['port_distribution'][port] = stats['port_distribution'].get(port, 0) + 1
            
            # Count services
            for service in item['services']:
                stats['service_distribution'][service] = stats['service_distribution'].get(service, 0) + 1
        
        return stats
    
    def save_scope_to_database(self, scope_items: List[Dict[str, Any]], project_id: int, user) -> Dict[str, Any]:
        """
        Save scope items to database
        
        Args:
            scope_items: List of scope items to save
            project_id: ID of the project
            user: User creating the scope
            
        Returns:
            Dictionary with save results
        """
        try:
            from project.models import Project, ProjectScope
            
            project = Project.objects.get(id=project_id)
            saved_count = 0
            skipped_count = 0
            
            for item in scope_items:
                try:
                    # Check if scope already exists
                    existing_scope = ProjectScope.objects.filter(
                        project=project,
                        scope=item['scope_entry']
                    ).first()
                    
                    if existing_scope:
                        skipped_count += 1
                        continue
                    
                    # Create new scope item
                    logger.info(f"Saving scope item: {item['scope_entry']}")
                    logger.info(f"Nmap details: {item.get('nmap_details', {})}")
                    
                    ProjectScope.objects.create(
                        project=project,
                        scope=item['scope_entry'],
                        description=item['description'],
                        nmap_details=item.get('nmap_details', {})
                    )
                    saved_count += 1
                    
                except Exception as e:
                    logger.error(f"Error saving scope item {item['scope_entry']}: {str(e)}")
                    skipped_count += 1
                    continue
            
            return {
                'success': True,
                'saved_count': saved_count,
                'skipped_count': skipped_count,
                'total_processed': len(scope_items)
            }
            
        except Exception as e:
            logger.error(f"Error saving scope to database: {str(e)}")
            return {
                'success': False,
                'error': f'Error saving scope to database: {str(e)}'
            }
