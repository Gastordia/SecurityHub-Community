"""
Nmap parser for SecurityHub
Parses Nmap XML output files and converts to standardized findings
"""

import contextlib
import datetime
import ipaddress
import logging
import re
from typing import List, Dict, Any, Optional
from ...xml import parse_xml_safely as parse

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel, StandardizedEndpoint

logger = logging.getLogger(__name__)


class NmapParser(BaseParser):
    """Parser for Nmap XML scan results"""
    
    def __init__(self):
        super().__init__()
        self.scanner_type = "nmap"
    
    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="Nmap",
            version="1.0.0",
            description="Parser for Nmap XML scan results including port scanning, service detection, and vulnerability scanning",
            supported_formats=["xml"],
            author="SecurityHub Team",
            website="https://nmap.org/"
        )

    def validate_file(self, file_path: str) -> bool:
        """Validate if file is a valid Nmap XML report"""
        logger.debug(f"🔍 NmapParser: Starting validation for {file_path}")
        
        if not self.validate_file_extension(file_path, ['.xml']):
            logger.debug(f"❌ NmapParser: Invalid file extension for {file_path}")
            return False
        
        try:
            logger.debug(f"🔍 NmapParser: Parsing XML file...")
            tree = parse(file_path)
            root = tree.getroot()
            logger.debug(f"🔍 NmapParser: Root tag: {root.tag}")
            
            # Check for Nmap XML structure - must have nmaprun root tag
            # Be more specific to avoid conflicts with other XML formats
            is_valid = root.tag == "nmaprun"
            
            # Additional check: if it's nmaprun, it should have scanner attribute
            if is_valid and root.get('scanner') != 'nmap':
                logger.debug(f"🔍 NmapParser: Root is nmaprun but scanner attribute is not 'nmap': {root.get('scanner')}")
                is_valid = False
            
            logger.info(f"🔍 NmapParser: Validation result: {is_valid} (root tag: {root.tag})")
            return is_valid
        except Exception as e:
            logger.error(f"💥 NmapParser: Validation error: {str(e)}")
            return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse Nmap XML file and return standardized findings"""
        try:
            with open(file_path, 'rb') as f:
                return self._parse_nmap_findings(f)
        except Exception as e:
            logger.error(f"Failed to parse Nmap file: {str(e)}")
            return []

    def _parse_nmap_findings(self, file) -> List[StandardizedFinding]:
        """Parse Nmap findings and return standardized format"""
        tree = parse(file)
        root = tree.getroot()
        dupes = {}
        
        if "nmaprun" not in root.tag:
            logger.error("This doesn't seem to be a valid Nmap xml file.")
            return []

        report_date = None
        with contextlib.suppress(ValueError):
            report_date = datetime.datetime.fromtimestamp(
                int(root.attrib["start"]),
            )

        for host in root.findall("host"):
            host_info = "### Host\n\n"

            # Get IP address
            ip_element = host.find("address[@addrtype='ipv4']")
            if ip_element is None:
                continue
            ip = ip_element.attrib["addr"]
            if ip is not None:
                host_info += f"**IP Address:** {ip}\n"

            # Get FQDN
            fqdn_element = host.find("hostnames/hostname[@type='PTR']")
            fqdn = None
            if fqdn_element is not None:
                fqdn = fqdn_element.attrib["name"]
                if fqdn is not None:
                    host_info += f"**FQDN:** {fqdn}\n"

            host_info += "\n\n"

            # Get MAC address
            mac_element = host.find("address[@addrtype='mac']")
            mac_address = mac_element.attrib["addr"] if mac_element is not None else None
            mac_vendor = mac_element.attrib.get("vendor") if mac_element is not None else None

            # Get IPv6
            ipv6_element = host.find("address[@addrtype='ipv6']")
            ipv6_address = ipv6_element.attrib["addr"] if ipv6_element is not None else None

            # Get traceroute hops
            traceroute = []
            trace_element = host.find("trace")
            if trace_element is not None:
                for hop in trace_element.findall("hop"):
                    traceroute.append({
                        'ttl': hop.attrib.get('ttl'),
                        'rtt': hop.attrib.get('rtt'),
                        'host': hop.attrib.get('host'),
                        'ipaddr': hop.attrib.get('ipaddr'),
                    })

            # Infer /24 subnet from IP
            subnet = None
            with contextlib.suppress(ValueError, TypeError):
                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))

            # Get OS information
            os_info = {}
            for os in host.iter("os"):
                for os_match in os.iter("osmatch"):
                    if "name" in os_match.attrib:
                        os_info['name'] = os_match.attrib["name"]
                        host_info += (
                            "**Host OS:** {}\n".format(os_match.attrib["name"])
                        )
                    if "accuracy" in os_match.attrib:
                        os_info['accuracy'] = os_match.attrib["accuracy"]
                        host_info += "**Accuracy:** {}%\n".format(
                            os_match.attrib["accuracy"],
                        )
                host_info += "\n\n"

            # Check if host is up
            status_element = host.find("status")
            host_status = "unknown"
            if status_element is not None:
                host_status = status_element.attrib.get("state", "unknown")
            
            # Skip hosts that are down (only process "up" hosts)
            if host_status == "down":
                logger.debug(f"⏭️ Skipping down host: {ip}")
                continue

            # Create host finding even if no open ports
            host_addr = fqdn or ip
            if not host_addr:
                logger.warning(f"⚠️ Skipping host without IP or hostname")
                continue
                
            dupe_key = f"nmap:{host_addr}"
            
            if dupe_key not in dupes:
                # Create base host finding
                find = StandardizedFinding(
                    title=f"Nmap scan results for {host_addr}",
                    severity=SeverityLevel.INFO,
                    description=host_info,
                    solution="Review if this host should be accessible",
                    affected_asset=host_addr,
                    scanner_type="nmap",
                    scanner_id=f"nmap-host-{host_addr}",
                    raw_data={
                        "ip_address": ip,
                        "hostname": fqdn,
                        "mac_address": mac_address,
                        "mac_vendor": mac_vendor,
                        "ipv6_address": ipv6_address,
                        "subnet": subnet,
                        "traceroute": traceroute,
                        "ports": [],
                        "os_info": os_info,
                        "services": [],
                        "host_status": host_status,
                        "scan_date": report_date.isoformat() if report_date else None,
                        "scan_type": "Standard",
                        "total_ports": 0,
                        "nmap_details": None,  # populated after ports are collected
                    }
                )
                dupes[dupe_key] = find

            # Count total ports scanned
            total_ports = len(host.findall("ports/port"))
            find = dupes[dupe_key]
            find.raw_data['total_ports'] = total_ports
            
            # Process ports
            for port_element in host.findall("ports/port"):
                protocol = port_element.attrib["protocol"]
                port_num = None
                if (
                    "portid" in port_element.attrib
                    and port_element.attrib["portid"].isdigit()
                ):
                    port_num = int(port_element.attrib["portid"])

                # Filter on open ports
                if port_element.find("state").attrib.get("state") != "open":
                    continue
                
                # Build endpoint URL
                host_addr = fqdn or ip
                if protocol == "tcp":
                    url = f"http://{host_addr}:{port_num}" if port_num else f"http://{host_addr}"
                elif protocol == "udp":
                    url = f"udp://{host_addr}:{port_num}" if port_num else f"udp://{host_addr}"
                else:
                    url = f"{protocol}://{host_addr}:{port_num}" if port_num else f"{protocol}://{host_addr}"
                
                endpoint = StandardizedEndpoint(
                    url=url, 
                    protocol=protocol, 
                    port=port_num
                )

                title = f"Open port: {port_num}/{protocol}"
                description = host_info
                description += f"**Port/Protocol:** {port_num}/{protocol}\n"

                # Get service information
                service_info = "\n\n"
                service_element = port_element.find("service")
                if service_element is not None:
                    if "product" in service_element.attrib:
                        service_info += (
                            "**Product:** {}\n".format(service_element.attrib["product"])
                        )

                    if "version" in service_element.attrib:
                        service_info += (
                            "**Version:** {}\n".format(service_element.attrib["version"])
                        )

                    if "extrainfo" in service_element.attrib:
                        service_info += (
                            "**Extra Info:** {}\n".format(service_element.attrib["extrainfo"])
                        )
                    description += service_info
                
                # Get script information
                script_element = port_element.find("script")
                if script_element is not None:
                    if script_id := script_element.attrib.get("id"):
                        description += f"**Script ID:** {script_id}\n"
                    if script_output := script_element.attrib.get("output"):
                        description += f"**Script Output:** {script_output}\n"
                description += "\n\n"

                # Process vulnerability scripts (like vulners)
                for script_element in port_element.findall('script[@id="vulners"]'):
                    self._process_vulners_script(
                        dupes, script_element, endpoint, report_date
                    )

                # Add port to existing host finding
                find = dupes[dupe_key]
                port_data = {
                    'port': port_num,
                    'protocol': protocol,
                    'service': service_element.attrib.get('name', '') if service_element is not None else '',
                    'version': service_element.attrib.get('version', '') if service_element is not None else '',
                    'product': service_element.attrib.get('product', '') if service_element is not None else '',
                    'extrainfo': service_element.attrib.get('extrainfo', '') if service_element is not None else '',
                    'state': 'open'
                }
                
                # Add script information if available
                scripts = []
                for script_element in port_element.findall('script'):
                    script_data = {
                        'id': script_element.attrib.get('id', ''),
                        'output': script_element.attrib.get('output', '')
                    }
                    scripts.append(script_data)
                port_data['scripts'] = scripts
                
                find.raw_data['ports'].append(port_data)
                
                # Add service to services list
                if service_element is not None and service_element.attrib.get('name'):
                    service_name = service_element.attrib.get('name')
                    if service_name not in find.raw_data['services']:
                        find.raw_data['services'].append(service_name)
                
                if description is not None:
                    find.description += description

            # Populate nmap_details after all ports for this host are collected
            find = dupes[dupe_key]
            find.raw_data['nmap_details'] = {
                'ip': ip,
                'hostname': fqdn,
                'mac': mac_address,
                'mac_vendor': mac_vendor,
                'ipv6': ipv6_address,
                'subnet': subnet,
                'os': os_info,
                'ports': find.raw_data['ports'],
                'services': find.raw_data['services'],
                'traceroute': traceroute,
                'host_status': host_status,
                'scan_date': report_date.isoformat() if report_date else None,
            }

        return list(dupes.values())

    def _process_vulners_script(self, dupes: Dict, script_element, endpoint: StandardizedEndpoint, report_date: Optional[datetime.datetime]):
        """Process vulners script output for vulnerability information"""
        try:
            for component_element in script_element.findall("table"):
                component_cpe = component_element.attrib["key"]
                for vuln in component_element.findall("table"):
                    # Convert elements to dict
                    vuln_attributes = {}
                    for elem in vuln.findall("elem"):
                        vuln_attributes[elem.attrib["key"].lower()] = elem.text

                    vuln_id = vuln_attributes.get("id", "unknown")
                    description = "### Vulnerability\n\n"
                    description += "**ID**: `" + str(vuln_id) + "`\n"
                    description += "**CPE**: " + str(component_cpe) + "\n"
                    
                    for attribute in vuln_attributes:
                        description += (
                            "**"
                            + attribute
                            + "**: `"
                            + vuln_attributes[attribute]
                            + "`\n"
                        )
                    
                    # Determine severity from CVSS score
                    cvss_score = vuln_attributes.get("cvss")
                    severity = self._convert_cvss_score(cvss_score) if cvss_score else SeverityLevel.INFO

                    # Extract CVE IDs
                    cve_ids = []
                    if vuln_attributes.get("type") == "cve":
                        cve_ids = [vuln_attributes["id"]]

                    finding = StandardizedFinding(
                        title=vuln_id,
                        severity=severity,
                        description=description,
                        cvss_score=float(cvss_score) if cvss_score else None,
                        cwe_ids=[],
                        affected_asset=endpoint.url,
                        scanner_type="nmap",
                        scanner_id=vuln_id,
                        raw_data={
                            "component_cpe": component_cpe,
                            "cvss_score": cvss_score,
                            "vuln_attributes": vuln_attributes,
                            "cve_ids": cve_ids
                        }
                    )

                    dupe_key = vuln_id
                    if dupe_key in dupes:
                        find = dupes[dupe_key]
                        if description is not None:
                            find.description += "\n-----\n\n" + finding.description
                    else:
                        dupes[dupe_key] = finding
                        
        except Exception as e:
            # Log error but continue processing
            print(f"Error processing vulners script: {str(e)}")

    def _convert_cvss_score(self, raw_value: str) -> SeverityLevel:
        """
        Convert CVSS score to severity level
        According to CVSS official numbers https://nvd.nist.gov/vuln-metrics/cvss
        """
        try:
            val = float(raw_value)
            if val == 0.0:
                return SeverityLevel.INFO
            if val < 4.0:
                return SeverityLevel.LOW
            if val < 7.0:
                return SeverityLevel.MEDIUM
            if val < 9.0:
                return SeverityLevel.HIGH
            return SeverityLevel.CRITICAL
        except (ValueError, TypeError):
            return SeverityLevel.INFO
