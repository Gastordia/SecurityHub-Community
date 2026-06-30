"""
Nessus parser for SecurityHub
Parses Nessus scan results in CSV or XML format
Comprehensive implementation based on Tenable reference parsers
"""

import csv
import contextlib
import io
import json
import logging
import re
import sys
from typing import List, Dict, Any, Optional
from ...xml import parse_xml_safely as parse
from hyperlink._url import SCHEME_PORT_MAP

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel, StandardizedEndpoint

logger = logging.getLogger(__name__)


class NessusParser(BaseParser):
    """Comprehensive parser for Tenable Nessus scan results"""
    
    def __init__(self):
        super().__init__()
        self.scanner_type = "nessus"
    
    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="Nessus",
            version="2.0.0",
            description="Comprehensive parser for Tenable Nessus scan results in CSV or XML format",
            supported_formats=["csv", "xml", "nessus"],
            author="SecurityHub Team",
            website="https://www.tenable.com/"
        )

    def validate_file(self, file_path: str) -> bool:
        """Validate if file is a valid Nessus report"""
        logger.debug("NessusParser: Validating file: %s", file_path)
        
        file_path_str = str(file_path).lower()
        
        if file_path_str.endswith('.csv'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    # Check for common Nessus CSV headers
                    valid_headers = ['Name', 'Plugin Name', 'Severity', 'Risk', 'asset.name']
                    is_valid = any(header in first_line for header in valid_headers)
                    logger.debug("NessusParser: CSV validation result: %s", is_valid)
                    return is_valid
            except Exception as e:
                logger.error("NessusParser: CSV validation error: %s", e)
                return False
        elif file_path_str.endswith(('.xml', '.nessus')):
            try:
                root = parse(file_path).getroot()
                # Check for Nessus XML structure
                is_valid = "NessusClientData_v2" in root.tag
                logger.debug("NessusParser: XML validation result: %s", is_valid)
                return is_valid
            except Exception as e:
                logger.error("NessusParser: XML validation error: %s", e)
                return False

        logger.debug("NessusParser: Unsupported file format: %s", file_path_str)
        return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse Nessus file and return standardized findings"""
        logger.info("NessusParser: Starting to parse findings from %s", file_path)

        if str(file_path).lower().endswith(('.xml', '.nessus')):
            return self._parse_xml_findings(file_path)
        elif str(file_path).lower().endswith('.csv'):
            return self._parse_csv_findings(file_path)
        else:
            logger.error("NessusParser: Filename extension not recognized. Use .xml, .nessus or .csv")
            return []

    def _parse_xml_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse XML findings using comprehensive logic from reference parser"""
        try:
            tree = parse(file_path)
            root = tree.getroot()
            
            if "NessusClientData_v2" not in root.tag:
                logger.error("NessusParser: This doesn't seem to be a valid Nessus XML file.")
                return []
            
            findings = []
            dupes = {}
            
            for report in root.iter("Report"):
                for host in report.iter("ReportHost"):
                    host_metadata = self._extract_xml_host_properties(host)
                    ip = host_metadata.get("ip_address") or host.attrib.get("name", "Unknown")
                    fqdn = host_metadata.get("fqdn")
                    
                    for item in host.iter("ReportItem"):
                        finding = self._parse_xml_item(item, ip, fqdn, host_metadata)
                        if finding:
                            dupe_key = f"nessus:{finding.scanner_id}:{finding.affected_asset}"
                            if dupe_key not in dupes:
                                dupes[dupe_key] = finding
                                findings.append(finding)
                            else:
                                # Merge with existing finding
                                existing = dupes[dupe_key]
                                existing.description += f"\n\n--- Additional Instance ---\n\n{finding.description}"
                                # Merge endpoints
                                if "affected_endpoints" in finding.raw_data:
                                    if "affected_endpoints" not in existing.raw_data:
                                        existing.raw_data["affected_endpoints"] = []
                                    existing.raw_data["affected_endpoints"].extend(finding.raw_data["affected_endpoints"])
            
            logger.info("NessusParser: Successfully parsed %s findings from XML", len(findings))
            return findings

        except Exception as e:
            logger.error("NessusParser: Failed to parse Nessus XML file: %s", e)
            return []

    def _parse_xml_item(
        self,
        item,
        ip: str,
        fqdn: Optional[str] = None,
        host_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[StandardizedFinding]:
        """Parse individual XML item with comprehensive data extraction"""
        try:
            # Basic item information
            title = item.attrib.get("pluginName", "Unknown")
            plugin_id = item.attrib.get("pluginID", "0")
            plugin_family = item.attrib.get("pluginFamily", "")
            
            # Get and clean the port
            port = None
            if float(item.attrib.get("port", "0")) > 0:
                port = item.attrib.get("port")
            
            # Get and clean the protocol
            protocol = str(item.attrib.get("svc_name", ""))
            if protocol:
                protocol = re.sub(r"[^A-Za-z0-9\-\+]+", "", protocol)
                if protocol == "www":
                    protocol = "http"
                if protocol not in SCHEME_PORT_MAP:
                    protocol = re.sub(r"[^A-Za-z0-9\-\+]+", "", item.attrib.get("protocol", protocol))
            
            # Build description with synopsis and plugin output
            description = ""
            synopsis_elem = item.find("synopsis")
            if synopsis_elem is not None and synopsis_elem.text:
                description = f"{synopsis_elem.text}\n\n"
            
            plugin_output_elem = item.find("plugin_output")
            plugin_output_text = None
            if plugin_output_elem is not None and plugin_output_elem.text:
                plugin_output_text = plugin_output_elem.text
                plugin_output = f"Plugin Output: {ip}{f':{port}' if port else ''}"
                plugin_output += f"\n```\n{plugin_output_text}\n```\n\n"
                description += plugin_output
            
            # Determine severity
            nessus_severity_id = int(item.attrib.get("severity", 0))
            severity = self._convert_severity(nessus_severity_id)
            
            # Build impact with comprehensive CVSS information
            impact = ""
            description_elem = item.find("description")
            if description_elem is not None and description_elem.text:
                impact = description_elem.text + "\n\n"
            
            # Add CVSS information to impact
            cvss_fields = [
                ("cvss", "CVSS Score"),
                ("cvssv3", "CVSSv3 Score"),
                ("cvss_vector", "CVSS Vector"),
                ("cvss3_vector", "CVSSv3 Vector"),
                ("cvss_base_score", "CVSS Base Score"),
                ("cvss_temporal_score", "CVSS Temporal Score")
            ]
            
            for field_name, field_label in cvss_fields:
                field_elem = item.find(field_name)
                if field_elem is not None and field_elem.text:
                    impact += f"{field_label}: {field_elem.text}\n"
            
            # Get mitigation/solution
            mitigation = "N/A"
            solution_elem = item.find("solution")
            if solution_elem is not None and solution_elem.text:
                mitigation = solution_elem.text
            
            # Build references
            references = []
            for ref in item.iter("see_also"):
                if ref.text:
                    refs = ref.text.split()
                    references.extend(refs)
            
            for xref in item.iter("xref"):
                if xref.text:
                    references.append(xref.text)

            plugin_publication_date = self._get_xml_text(item, "plugin_publication_date")
            plugin_modification_date = self._get_xml_text(item, "plugin_modification_date")
            script_version = self._get_xml_text(item, "script_version")
            plugin_type = self._get_xml_text(item, "plugin_type")
            risk_factor = self._get_xml_text(item, "risk_factor")
            cvss_score_source = self._get_xml_text(item, "cvss_score_source")
            cvss_score_rationale = self._get_xml_text(item, "cvss_score_rationale")
            exploitability_ease = self._get_xml_text(item, "exploitability_ease")
            stig_severity = self._get_xml_text(item, "stig_severity")
            vuln_publication_date = self._get_xml_text(item, "vuln_publication_date")
            patch_publication_date = self._get_xml_text(item, "patch_publication_date")
            iavb = self._get_xml_text(item, "iavb")
            iavt = self._get_xml_text(item, "iavt")
            asset_inventory = self._get_xml_text(item, "asset_inventory")
            asset_inventory_category = self._get_xml_text(item, "asset_inventory_category")
            hardware_inventory = self._get_xml_text(item, "hardware_inventory")
            os_identification = self._get_xml_text(item, "os_identification")
            thorough_tests = self._get_xml_text(item, "thorough_tests")
            agent = self._get_xml_text(item, "agent")
            see_also_refs = self._get_xml_values(item, "see_also")
            cpe_values = self._get_xml_values(item, "cpe")
            xref_values = self._get_xml_values(item, "xref")
            cisa_known_exploited = self._parse_bool_text(self._get_xml_text(item, "cisa-known-exploited"))
            exploited_by_nessus = self._parse_bool_text(self._get_xml_text(item, "exploited_by_nessus"))
            exploit_available = self._parse_bool_text(self._get_xml_text(item, "exploit_available"))
            in_the_news = self._parse_bool_text(self._get_xml_text(item, "in_the_news"))
            epss_score = self._parse_float_text(self._get_xml_text(item, "epss_score"), max_percent_scale=True)
            cvss_v2_temporal = self._parse_float_text(self._get_xml_text(item, "cvss_temporal_score"))
            cvss_v3_temporal = self._parse_float_text(self._get_xml_text(item, "cvss3_temporal_score"))
            
            # Get CVE information — Nessus may emit multiple <cve> sibling elements
            cve_ids = []
            for cve_elem in item.findall("cve"):
                if cve_elem.text:
                    cve_ids.extend(c.strip() for c in cve_elem.text.split(',') if c.strip())
            
            # Get CWE information
            cwe_ids = []
            cwe_elem = item.find("cwe")
            if cwe_elem is not None and cwe_elem.text:
                cwe_ids = [f"CWE-{cwe.strip()}" for cwe in cwe_elem.text.split(',') if cwe.strip()]
            
            # Get CVSSv3 vector
            cvss_vector = None
            cvssv3_vector_elem = item.find("cvss3_vector")
            if cvssv3_vector_elem is not None and cvssv3_vector_elem.text:
                cvss_vector = cvssv3_vector_elem.text
                if "CVSS:3.0/" not in cvss_vector:
                    cvss_vector = f"CVSS:3.0/{cvss_vector}"
            
            # Get CVSSv3 score — primary source is cvss3_base_score (standard Nessus field);
            # fall back to cvssv3 for any non-standard exports.
            cvss_score = None
            for score_tag in ("cvss3_base_score", "cvssv3"):
                elem = item.find(score_tag)
                if elem is not None and elem.text:
                    try:
                        cvss_score = float(elem.text)
                        break
                    except ValueError:
                        pass

            # If still no CVSSv3, try CVSSv2 base score as last resort
            if cvss_score is None:
                elem = item.find("cvss_base_score")
                if elem is not None and elem.text:
                    try:
                        cvss_score = float(elem.text)
                    except ValueError:
                        pass

            # Derive severity from CVSS score when available
            if cvss_score is not None:
                severity = self._convert_cvss_severity(cvss_score)
            
            component_name, component_version = self._extract_component_from_cpe_values(cpe_values)

            # Create endpoint
            affected_endpoints = []
            if fqdn and "://" in fqdn:
                endpoint_url = fqdn
            else:
                endpoint_url = f"{protocol}://{fqdn or ip}"
                if port and port != "0":
                    endpoint_url += f":{port}"
            
            affected_endpoints.append(StandardizedEndpoint(
                url=endpoint_url,
                protocol=protocol,
                port=int(port) if port and port.isdigit() else None
            ))
            
            metadata = self._extract_host_metadata(
                plugin_id=plugin_id,
                title=title,
                plugin_output=plugin_output_text,
                ip=ip,
                fqdn=fqdn,
                port=port,
            )
            if host_metadata:
                metadata.update(host_metadata)

            references.extend(value for value in see_also_refs if value)
            references.extend(value for value in xref_values if value)
            references = list(dict.fromkeys(references))

            finding_tags = []
            if exploit_available:
                finding_tags.append("exploit-available")
            if cisa_known_exploited:
                finding_tags.append("cisa-kev")
            if exploited_by_nessus:
                finding_tags.append("exploited-by-nessus")
            if in_the_news:
                finding_tags.append("in-the-news")

            # Create finding
            finding = StandardizedFinding(
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                solution=mitigation,
                evidence=impact,
                references=references,
                affected_asset=fqdn or ip,
                scanner_type="nessus",
                scanner_id=plugin_id,
                tags=finding_tags,
                raw_data={
                    "plugin_id": plugin_id,
                    "plugin_family": plugin_family,
                    "plugin_type": plugin_type,
                    "script_version": script_version,
                    "port": port,
                    "protocol": protocol,
                    "host": fqdn or ip,
                    "ip": ip,
                    "fqdn": fqdn,
                    "affected_endpoints": [{"url": endpoint_url, "protocol": protocol, "port": port}],
                    "cve_ids": cve_ids,
                    "cpe_list": cpe_values,
                    "component_cpe": cpe_values[0] if cpe_values else None,
                    "component_name": component_name,
                    "component_version": component_version,
                    "nessus_severity_id": nessus_severity_id,
                    "plugin_output": plugin_output_text,
                    "plugin_publication_date": plugin_publication_date,
                    "plugin_modification_date": plugin_modification_date,
                    "risk_factor": risk_factor,
                    "cvss_score_source": cvss_score_source,
                    "cvss_score_rationale": cvss_score_rationale,
                    "cvss_v2_temporal": cvss_v2_temporal,
                    "cvss_v3_temporal": cvss_v3_temporal,
                    "exploitability_ease": exploitability_ease,
                    "exploit_available": exploit_available,
                    "exploited_by_nessus": exploited_by_nessus,
                    "has_cisa_kev_exploit": cisa_known_exploited,
                    "cisa_known_exploited": cisa_known_exploited,
                    "in_the_news": in_the_news,
                    "epss_score": epss_score,
                    "stig_severity": stig_severity,
                    "vuln_publication_date": vuln_publication_date,
                    "patch_publication_date": patch_publication_date,
                    "iavb": iavb,
                    "iavt": iavt,
                    "asset_inventory": asset_inventory,
                    "asset_inventory_category": asset_inventory_category,
                    "hardware_inventory": hardware_inventory,
                    "os_identification": os_identification,
                    "agent": agent,
                    "thorough_tests": thorough_tests,
                    **metadata,
                }
            )
            
            return finding
            
        except Exception as e:
            logger.error("NessusParser: Error parsing XML item: %s", e)
            return None

    def _parse_csv_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse CSV findings using comprehensive logic from reference parser"""
        try:
            # Read the CSV content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Detect delimiter
            delimiter = self._detect_delimiter(content)
            
            # Set CSV field size limit
            try:
                csv.field_size_limit(2**31 - 1)  # Max 32-bit integer
            except OverflowError:
                csv.field_size_limit(2**30)  # Fallback to 1GB
            
            findings = []
            dupes = {}
            
            reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
            
            # Validate required fields - check for common Nessus CSV column names
            required_fields = ['Name', 'Plugin Name', 'Plugin ID', 'asset.name']
            if not any(field in reader.fieldnames for field in required_fields):
                logger.warning("NessusParser: CSV may be missing standard fields. Available fields: %s", reader.fieldnames)
                # Don't return empty - try to parse anyway as CSV formats vary
            
            for row in reader:
                finding = self._parse_csv_row(row)
                if finding:
                    dupe_key = f"nessus:{finding.scanner_id}:{finding.affected_asset}"
                    if dupe_key not in dupes:
                        dupes[dupe_key] = finding
                        findings.append(finding)
                    else:
                        # Merge with existing finding
                        existing = dupes[dupe_key]
                        existing.description += f"\n\n--- Additional Instance ---\n\n{finding.description}"
                        # Merge endpoints
                        if "affected_endpoints" in finding.raw_data:
                            if "affected_endpoints" not in existing.raw_data:
                                existing.raw_data["affected_endpoints"] = []
                            existing.raw_data["affected_endpoints"].extend(finding.raw_data["affected_endpoints"])
            
            logger.info("NessusParser: Successfully parsed %s findings from CSV", len(findings))
            return findings

        except Exception as e:
            logger.error("NessusParser: Failed to parse Nessus CSV file: %s", e)
            return []

    def _parse_csv_row(self, row: Dict[str, str]) -> Optional[StandardizedFinding]:
        """Parse individual CSV row with comprehensive data extraction"""
        try:
            # Extract title from multiple possible fields
            title = row.get('Name', row.get('Plugin Name', row.get('asset.name')))
            if not title or title == "":
                return None
            
            # Extract severity with fallbacks
            raw_severity = row.get('Risk', row.get('severity', ''))
            if raw_severity == "":
                raw_severity = row.get('Severity', 'Info')
            
            # Try to convert to int if possible
            with contextlib.suppress(ValueError):
                int_severity = int(raw_severity)
                raw_severity = int_severity
            
            severity = self._convert_severity(raw_severity)
            
            # Extract EPSS score if available
            epss_score = None
            epss_score_string = row.get("EPSS Score")
            if epss_score_string:
                if "0." not in epss_score_string:
                    epss_score_string = "0." + epss_score_string
                try:
                    epss_score = float(epss_score_string)
                except ValueError:
                    pass
            
            # Extract description - use Description field, not Synopsis
            description = row.get('Description', row.get('definition.description', ''))
            if not description or description.strip() == "":
                # Fallback to Synopsis if Description is empty
                description = row.get('Synopsis', row.get('definition.synopsis', 'N/A'))
            
            # Extract plugin output separately (for POC/evidence)
            plugin_output = str(row.get('Plugin Output', row.get('output', '')))
            
            # Extract mitigation/solution
            mitigation = str(row.get('Solution', row.get('definition.solution', row.get('Steps to Remediate', 'N/A'))))
            if mitigation == 'N/A' or mitigation.strip() == '':
                mitigation = 'n/a'
            
            # Build references - filter out empty values
            references = []
            see_also = row.get('See Also', row.get('definition.see_also', ''))
            if see_also and see_also.strip() and see_also.strip() != 'N/A':
                # Split by comma and clean up
                refs = [ref.strip() for ref in see_also.split(',') if ref.strip()]
                references.extend(refs)
            
            # Add plugin metadata only if available
            plugin_id = row.get('Plugin ID', row.get('Plugin', '')).strip()
            if plugin_id and plugin_id != '' and plugin_id != 'N/A':
                references.append(f"Tenable Plugin ID: {plugin_id}")
            
            plugin_pub_date = row.get('Plugin Publication Date', '').strip()
            plugin_mod_date = row.get('Plugin Modification Date', '').strip()
            if plugin_pub_date and plugin_pub_date != '' and plugin_pub_date != 'N/A':
                references.append(f"Plugin Publication Date: {plugin_pub_date}")
            if plugin_mod_date and plugin_mod_date != '' and plugin_mod_date != 'N/A':
                references.append(f"Plugin Modification Date: {plugin_mod_date}")
            
            # Extract CVE information - handle empty strings
            cve_ids = []
            cve_text = row.get('CVE', row.get('definition.cve', ''))
            if cve_text and cve_text.strip() and cve_text.strip() != 'N/A':
                cve_matches = re.findall(r"CVE-[0-9]+-[0-9]+", cve_text.upper(), re.IGNORECASE)
                cve_ids = cve_matches
            
            # Extract CVSS information - check both v2 and v3
            cvss_score = None
            # Try CVSS v3.0 first — Nessus exports use either column name
            cvss_text = row.get('CVSS v3.0 Base Score',
                                row.get('CVSS v3.0 Score',
                                        row.get('CVSSv3', row.get('definition.cvss3.base_score', ''))))
            if not cvss_text or cvss_text.strip() == '':
                # Fallback to CVSS v2.0
                cvss_text = row.get('CVSS v2.0 Base Score', row.get('CVSS', ''))
            
            if cvss_text and cvss_text.strip() and cvss_text.strip() != 'N/A':
                try:
                    cvss_score = float(cvss_text.strip())
                except ValueError:
                    pass
            
            # Extract CVSS vector - check multiple possible field names
            cvss_vector = row.get('CVSS v3.0 Vector', row.get('CVSS V3 Vector', row.get('CVSS Vector', '')))
            if not cvss_vector or cvss_vector.strip() == '':
                cvss_vector = row.get('CVSS v2.0 Vector', '')
            
            # Override severity based on CVSS if available
            if cvss_score is not None:
                severity = self._convert_cvss_severity(cvss_score)
            
            # Extract CWE information
            cwe_ids = []
            cwe_text = row.get('CWE', row.get('definition.cwe', ''))
            if cwe_text and cwe_text.strip() and cwe_text.strip() != 'N/A':
                # CWE can be in format "CWE-123" or just "123"
                cwe_matches = re.findall(r"CWE-?([0-9]+)", cwe_text.upper(), re.IGNORECASE)
                cwe_ids = [f"CWE-{cwe}" for cwe in cwe_matches]
            
            # Extract additional CVSS scores
            cvss_v2_temporal = None
            cvss_v2_temporal_text = row.get('CVSS v2.0 Temporal Score', '')
            if cvss_v2_temporal_text and cvss_v2_temporal_text.strip() and cvss_v2_temporal_text.strip() != 'N/A':
                try:
                    cvss_v2_temporal = float(cvss_v2_temporal_text.strip())
                except ValueError:
                    pass
            
            cvss_v3_temporal = None
            cvss_v3_temporal_text = row.get('CVSS v3.0 Temporal Score', '')
            if cvss_v3_temporal_text and cvss_v3_temporal_text.strip() and cvss_v3_temporal_text.strip() != 'N/A':
                try:
                    cvss_v3_temporal = float(cvss_v3_temporal_text.strip())
                except ValueError:
                    pass
            
            # Extract VPR Score
            vpr_score = None
            vpr_text = row.get('VPR Score', '')
            if vpr_text and vpr_text.strip() and vpr_text.strip() != 'N/A':
                try:
                    vpr_score = float(vpr_text.strip())
                except ValueError:
                    pass
            
            # Extract STIG Severity
            stig_severity = row.get('STIG Severity', '').strip()
            
            # Extract Risk Factor (usually same as Risk but keep separate)
            risk_factor = row.get('Risk Factor', row.get('Risk', '')).strip()
            
            # Extract additional reference IDs
            bid = row.get('BID', '').strip()  # Bugtraq ID
            xref = row.get('XREF', '').strip()  # Cross-reference
            mskb = row.get('MSKB', '').strip()  # Microsoft Knowledge Base
            
            # Extract exploit framework information
            metasploit = row.get('Metasploit', '').strip()
            core_impact = row.get('Core Impact', '').strip()
            canvas = row.get('CANVAS', '').strip()
            
            # Add additional references if available
            if bid and bid != '' and bid != 'N/A':
                references.append(f"BID: {bid}")
            if xref and xref != '' and xref != 'N/A':
                references.append(f"XREF: {xref}")
            if mskb and mskb != '' and mskb != 'N/A':
                references.append(f"MSKB: {mskb}")
            if metasploit and metasploit != '' and metasploit != 'N/A':
                references.append(f"Metasploit: {metasploit}")
            if core_impact and core_impact != '' and core_impact != 'N/A':
                references.append(f"Core Impact: {core_impact}")
            if canvas and canvas != '' and canvas != 'N/A':
                references.append(f"CANVAS: {canvas}")
            
            # Extract CPE information
            component_name = None
            component_version = None
            cpe_text = str(row.get('CPE', row.get('definition.cpe', '')))
            if cpe_text:
                cpe_matches = re.findall(r"cpe:/[^\n\ ]+", cpe_text)
                if cpe_matches:
                    # Parse CPE to extract component info
                    cpe_parts = cpe_matches[0].split(':')
                    if len(cpe_parts) >= 4:
                        component_name = cpe_parts[3]  # component name (index 3)
                        if len(cpe_parts) >= 5:
                            component_version = cpe_parts[4]  # component version (index 4)
            
            # Extract endpoint information — use `or` so empty strings also fall through
            host = (row.get('Host') or row.get('asset.host_name')
                    or row.get('DNS Name') or row.get('IP Address', 'localhost'))
            
            protocol = row.get('Protocol', row.get('protocol', ''))
            protocol = protocol.lower() if protocol else None
            
            port = str(row.get('Port', row.get('asset.port', '')))
            if port in ["", "0"]:
                port = None
            
            # Create endpoint URL
            endpoint_url = f"{protocol}://{host}" if protocol else host
            if port and port != "0":
                endpoint_url += f":{port}"
            
            # Build raw_data with all fields
            raw_data = {
                "plugin_id": row.get('Plugin ID', row.get('Plugin', '0')),
                "port": port,
                "protocol": protocol,
                "host": host,
                "epss_score": epss_score,
                "component_name": component_name,
                "component_version": component_version,
                "affected_endpoints": [{"url": endpoint_url, "protocol": protocol, "port": port}],
                "row_data": row,
                "cve_ids": cve_ids,
                "plugin_output": plugin_output,
                # Additional CVSS scores (standardized field names)
                "cvss_v2_temporal": cvss_v2_temporal,
                "cvss_v3_temporal": cvss_v3_temporal,
                "vpr_score": vpr_score,
                # Additional metadata (standardized field names)
                "stig_severity": stig_severity,
                "risk_factor": risk_factor,
                "bid": bid,
                "xref": xref,
                "mskb": mskb,
                # Exploit framework information (standardized field names)
                "metasploit": metasploit,
                "core_impact": core_impact,
                "canvas": canvas,
                # Plugin dates (standardized field names)
                "plugin_publication_date": plugin_pub_date,
                "plugin_modification_date": plugin_mod_date
            }
            raw_data.update(
                self._extract_host_metadata(
                    plugin_id=raw_data["plugin_id"],
                    title=title,
                    plugin_output=plugin_output,
                    ip=host if self._looks_like_ip(host) else row.get('IP Address'),
                    fqdn=host if not self._looks_like_ip(host) else row.get('DNS Name'),
                    port=port,
                )
            )
            
            # Extract exploit framework tags using base parser method
            exploit_framework_tags = []
            if metasploit and metasploit.strip() and metasploit.strip().upper() != 'N/A':
                exploit_framework_tags.append('metasploit')
            if core_impact and core_impact.strip() and core_impact.strip().upper() != 'N/A':
                exploit_framework_tags.append('core_impact')
            if canvas and canvas.strip() and canvas.strip().upper() != 'N/A':
                exploit_framework_tags.append('canvas')
            
            # Create finding
            finding = StandardizedFinding(
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                solution=mitigation,
                evidence=plugin_output if plugin_output and plugin_output.strip() else None,
                references=references,
                affected_asset=host,
                scanner_type="nessus",
                scanner_id=row.get('Plugin ID', row.get('Plugin', '0')),
                tags=exploit_framework_tags,  # Add exploit framework tags
                raw_data=raw_data
            )
            
            return finding
            
        except Exception as e:
            logger.error("NessusParser: Error parsing CSV row: %s", e)
            return None

    def _detect_delimiter(self, content: str) -> str:
        """Detect the delimiter of the CSV file"""
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        first_line = content.split("\n")[0]
        if ";" in first_line:
            return ";"
        return ","  # default to comma if no semicolon found

    def _looks_like_ip(self, value: Optional[str]) -> bool:
        if not value:
            return False
        return bool(re.fullmatch(r"[0-9a-fA-F:\.]+", value.strip()))

    def _extract_host_metadata(
        self,
        plugin_id: str,
        title: str,
        plugin_output: Optional[str],
        ip: Optional[str] = None,
        fqdn: Optional[str] = None,
        port: Optional[str] = None,
    ) -> Dict[str, Any]:
        output = (plugin_output or "").strip()
        if not output:
            return {}

        metadata: Dict[str, Any] = {}
        lowered_title = (title or "").lower()
        os_fingerprints = self._parse_os_fingerprints(output)
        best_os = self._select_best_os_fingerprint(os_fingerprints)

        if os_fingerprints:
            metadata["os_fingerprints"] = os_fingerprints
        if best_os:
            metadata["operating_system"] = best_os.get("name")
            metadata["os_detection_confidence"] = best_os.get("confidence")
            metadata["os_detection_method"] = best_os.get("method")

        if "device type" in lowered_title:
            device_type = self._parse_first_value(output, r"(?im)^\s*Device Type\s*:\s*(.+)$")
            if device_type:
                metadata["device_type"] = device_type

        if "kerberos" in lowered_title:
            kerberos_realm = self._parse_first_value(output, r"(?im)^\s*Realm\s*:\s*(.+)$")
            kerberos_server_time = self._parse_first_value(output, r"(?im)^\s*Server time\s*:\s*(.+)$")
            if kerberos_realm:
                metadata["kerberos_realm"] = kerberos_realm
            if kerberos_server_time:
                metadata["kerberos_server_time"] = kerberos_server_time

        web_server = self._parse_first_value(output, r"(?im)^\s*Server\s*:\s*(.+)$")
        if not web_server:
            web_server = self._parse_first_value(output, r"HTTP:!?[: ]+Server:\s*(.+)")
        if web_server:
            metadata["web_server"] = web_server

        certificate_names = self._parse_certificate_names(output)
        if certificate_names:
            metadata["certificate_names"] = certificate_names

        traceroute = self._parse_traceroute(output)
        if traceroute:
            metadata["traceroute"] = traceroute

        hostnames = [value for value in [fqdn] if value]
        hostnames.extend(certificate_names)
        if hostnames:
            metadata["hostnames"] = sorted({value for value in hostnames if value})

        if ip:
            metadata["ip_address"] = ip
        if port:
            metadata["plugin_port"] = port
        if plugin_id:
            metadata["nessus_plugin_family"] = plugin_id

        return metadata

    def _extract_xml_host_properties(self, host) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {}
        host_properties = host.find("HostProperties")
        if host_properties is None:
            return metadata

        raw_tags: Dict[str, str] = {}
        traceroute_hops: List[str] = []
        cpe_values: List[str] = []
        enumerated_ports: List[str] = []

        for tag in host_properties.findall("tag"):
            name = tag.attrib.get("name")
            value = (tag.text or "").strip()
            if not name or not value:
                continue
            raw_tags[name] = value

            if name.startswith("traceroute-hop-"):
                traceroute_hops.append(value)
            elif name.startswith("cpe"):
                cpe_value = value.split(" -> ", 1)[0].strip()
                if cpe_value:
                    cpe_values.append(cpe_value)
            elif name.startswith("enumerated-ports-"):
                enumerated_ports.append(name.removeprefix("enumerated-ports-"))

        if raw_tags.get("host-fqdn"):
            metadata["fqdn"] = raw_tags["host-fqdn"]
        if raw_tags.get("host-ip"):
            metadata["ip_address"] = raw_tags["host-ip"]
        if raw_tags.get("mac-address"):
            metadata["mac_address"] = raw_tags["mac-address"]
        if raw_tags.get("netbios-name"):
            metadata["netbios_name"] = raw_tags["netbios-name"]
        if raw_tags.get("operating-system"):
            metadata["operating_system"] = raw_tags["operating-system"]
        if raw_tags.get("operating-system-conf"):
            metadata["os_detection_confidence"] = self._parse_int_text(raw_tags["operating-system-conf"])
        if raw_tags.get("operating-system-method"):
            metadata["os_detection_method"] = raw_tags["operating-system-method"]
        if raw_tags.get("system-type"):
            metadata["device_type"] = raw_tags["system-type"]
        if raw_tags.get("Credentialed_Scan") is not None:
            metadata["credentialed_scan"] = self._parse_bool_text(raw_tags["Credentialed_Scan"])
        if raw_tags.get("policy-used"):
            metadata["scan_policy"] = raw_tags["policy-used"]
        if raw_tags.get("patch-summary-total-cves"):
            metadata["patch_summary_total_cves"] = self._parse_int_text(raw_tags["patch-summary-total-cves"])
        if raw_tags.get("HOST_START"):
            metadata["host_scan_start"] = raw_tags["HOST_START"]
        if raw_tags.get("HOST_END"):
            metadata["host_scan_end"] = raw_tags["HOST_END"]
        if raw_tags.get("HOST_START_TIMESTAMP"):
            metadata["host_scan_start_timestamp"] = self._parse_int_text(raw_tags["HOST_START_TIMESTAMP"])
        if raw_tags.get("HOST_END_TIMESTAMP"):
            metadata["host_scan_end_timestamp"] = self._parse_int_text(raw_tags["HOST_END_TIMESTAMP"])
        if raw_tags.get("LastUnauthenticatedResults"):
            metadata["last_unauthenticated_results_timestamp"] = self._parse_int_text(raw_tags["LastUnauthenticatedResults"])
        if raw_tags.get("sinfp-signature"):
            metadata["sinfp_signature"] = raw_tags["sinfp-signature"]
        if raw_tags.get("sinfp-ml-prediction"):
            metadata["sinfp_ml_prediction"] = self._parse_json_text(raw_tags["sinfp-ml-prediction"])
        if traceroute_hops:
            metadata["traceroute"] = traceroute_hops
        if cpe_values:
            metadata["host_cpe_list"] = sorted(set(cpe_values))
        if enumerated_ports:
            metadata["enumerated_ports"] = sorted(set(enumerated_ports))

        return metadata

    def _get_xml_text(self, item, tag_name: str) -> Optional[str]:
        element = item.find(tag_name)
        if element is None or element.text is None:
            return None
        value = element.text.strip()
        return value or None

    def _get_xml_values(self, item, tag_name: str) -> List[str]:
        values = []
        for element in item.findall(tag_name):
            value = (element.text or "").strip()
            if not value:
                continue
            if tag_name in {"see_also"}:
                values.extend(part.strip() for part in value.split() if part.strip())
            else:
                values.append(value)
        return values

    def _parse_bool_text(self, value: Optional[str]) -> Optional[bool]:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0", "none"}:
            return False
        return None

    def _parse_int_text(self, value: Optional[str]) -> Optional[int]:
        if not value:
            return None
        with contextlib.suppress(ValueError, TypeError):
            return int(value)
        return None

    def _parse_float_text(self, value: Optional[str], max_percent_scale: bool = False) -> Optional[float]:
        if not value:
            return None
        with contextlib.suppress(ValueError, TypeError):
            parsed = float(value)
            if max_percent_scale and parsed > 1.0:
                return parsed / 100.0
            return parsed
        return None

    def _parse_json_text(self, value: Optional[str]) -> Any:
        if not value:
            return None
        with contextlib.suppress(ValueError, TypeError, json.JSONDecodeError):
            return json.loads(value)
        return value

    def _extract_component_from_cpe_values(self, cpe_values: List[str]) -> tuple[Optional[str], Optional[str]]:
        for cpe_value in cpe_values:
            cpe_parts = cpe_value.split(':')
            if len(cpe_parts) >= 4:
                component_name = cpe_parts[3] or None
                component_version = cpe_parts[4] if len(cpe_parts) >= 5 else None
                return component_name, component_version
        return None, None

    def _parse_os_fingerprints(self, output: str) -> List[Dict[str, Any]]:
        fingerprints: List[Dict[str, Any]] = []
        pattern = re.compile(
            r"Remote operating system\s*:\s*(?P<name>[^\n]+?)\s*"
            r"(?:\n\s*Confidence level\s*:\s*(?P<confidence>\d+))?"
            r"(?:\n\s*Method\s*:\s*(?P<method>[^\n]+))?"
            r"(?:\n\s*Type\s*:\s*(?P<type>[^\n]+))?"
            r"(?:\n\s*Fingerprint\s*:\s*(?P<fingerprint>.+?))?"
            r"(?=\n\s*Remote operating system\s*:|\n\s*Following fingerprints could not be used|\n\s*To see debug logs|\Z)",
            re.IGNORECASE | re.DOTALL,
        )
        for match in pattern.finditer(output):
            name = (match.group("name") or "").strip()
            if not name:
                continue
            confidence = None
            confidence_text = match.group("confidence")
            if confidence_text:
                with contextlib.suppress(ValueError):
                    confidence = int(confidence_text)
            fingerprints.append({
                "name": name,
                "confidence": confidence,
                "method": (match.group("method") or "").strip() or None,
                "type": (match.group("type") or "").strip() or None,
                "fingerprint": (match.group("fingerprint") or "").strip() or None,
            })
        return fingerprints

    def _select_best_os_fingerprint(self, fingerprints: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not fingerprints:
            return None
        return sorted(
            fingerprints,
            key=lambda item: (item.get("confidence") or -1, len(item.get("name") or "")),
            reverse=True,
        )[0]

    def _parse_first_value(self, text: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            return None
        value = (match.group(1) or "").strip()
        return value or None

    def _parse_certificate_names(self, output: str) -> List[str]:
        names = []
        for name in re.findall(r"/CN:(.+?)(?=i/[A-Z]{1,4}:|s/[A-Z]{1,4}:|/[A-Z]{1,4}:|\n|$)", output):
            cleaned = name.strip().strip(".")
            if cleaned and cleaned.lower() not in {"localhost", "localhosts"}:
                names.append(cleaned)
        return sorted(set(names))

    def _parse_traceroute(self, output: str) -> List[Dict[str, Any]]:
        hops = []
        for ttl, ipaddr, host in re.findall(
            r"(?im)^\s*(\d+)\s+(?:(\d{1,3}(?:\.\d{1,3}){3})|([a-z0-9\.\-]+))\b",
            output,
        ):
            hop_ip = ipaddr or None
            hop_host = host or None
            if not hop_ip and not hop_host:
                continue
            hops.append({
                "ttl": ttl,
                "ipaddr": hop_ip,
                "host": hop_host,
            })
        return hops

    def _convert_severity(self, severity) -> SeverityLevel:
        """Convert Nessus severity to standardized severity level"""
        if isinstance(severity, int):
            return self._int_severity_conversion(severity)
        if isinstance(severity, str):
            return self._string_severity_conversion(severity)
        return SeverityLevel.INFO

    def _int_severity_conversion(self, severity_value: int) -> SeverityLevel:
        """Convert integer severity to standardized severity level"""
        if severity_value == 4:
            return SeverityLevel.CRITICAL
        elif severity_value == 3:
            return SeverityLevel.HIGH
        elif severity_value == 2:
            return SeverityLevel.MEDIUM
        elif severity_value == 1:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def _string_severity_conversion(self, severity_value: str) -> SeverityLevel:
        """Convert string severity to standardized severity level"""
        if not severity_value or len(severity_value) == 0:
            return SeverityLevel.INFO
        
        severity_lower = severity_value.lower()
        if severity_lower in ['critical', '4']:
            return SeverityLevel.CRITICAL
        elif severity_lower in ['high', '3']:
            return SeverityLevel.HIGH
        elif severity_lower in ['medium', '2']:
            return SeverityLevel.MEDIUM
        elif severity_lower in ['low', '1']:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def _convert_cvss_severity(self, cvss_score: float) -> SeverityLevel:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return SeverityLevel.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityLevel.HIGH
        elif cvss_score >= 5.0:
            return SeverityLevel.MEDIUM
        elif cvss_score > 0.0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def get_scan_types(self):
        return ["Nessus Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nessus Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Reports can be imported as CSV or .nessus (XML) report formats."
