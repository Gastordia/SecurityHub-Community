"""
Acunetix parser for SecurityHub
Parses Acunetix XML and Acunetix 360 JSON scan results
"""

import json
import logging
import hashlib
import html2text
import hyperlink
from typing import List, Dict, Any, Optional
from ...xml import parse_xml_safely as parse
from dateutil import parser as date_parser

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel, StandardizedEndpoint

logger = logging.getLogger(__name__)


class AcunetixParser(BaseParser):
    """Parser for Acunetix XML and Acunetix 360 JSON scan results"""
    
    def __init__(self):
        super().__init__()
        self.scanner_type = "acunetix"
    
    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="Acunetix",
            version="1.0.0",
            description="Parser for Acunetix XML and Acunetix 360 JSON scan results",
            supported_formats=["xml", "json"],
            author="SecurityHub Team",
            website="https://www.acunetix.com/"
        )

    def validate_file(self, file_path: str) -> bool:
        """Validate if file is a valid Acunetix report"""
        logger.debug("AcunetixParser: Starting validation for %s", file_path)
        
        file_path_str = str(file_path).lower()
        
        if file_path_str.endswith('.xml'):
            try:
                logger.debug("AcunetixParser: Validating XML file...")
                root = parse(file_path).getroot()
                logger.debug("AcunetixParser: Root tag: %s", root.tag)

                # Check for Acunetix XML structure - look for Scan elements
                is_valid = root.tag == "Scan" or any(child.tag == "Scan" for child in root)
                logger.info("AcunetixParser: XML validation result: %s", is_valid)
                return is_valid
            except Exception as e:
                logger.error("AcunetixParser: XML validation error: %s", e)
                return False
        elif file_path_str.endswith('.json'):
            try:
                logger.debug("AcunetixParser: Validating JSON file...")
                with open(file_path, 'r') as f:
                    data = json.load(f)

                # Check for Acunetix JSON structure
                is_valid = "Vulnerabilities" in data or "Generated" in data
                logger.info("AcunetixParser: JSON validation result: %s", is_valid)
                return is_valid
            except Exception as e:
                logger.error("AcunetixParser: JSON validation error: %s", e)
                return False

        logger.debug("AcunetixParser: Unsupported file format")
        return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse Acunetix file and return standardized findings"""
        logger.info("AcunetixParser: Starting to parse findings from %s", file_path)

        try:
            if ".xml" in str(file_path):
                findings = self._parse_xml_findings(file_path)
                logger.info("AcunetixParser: Successfully parsed %s XML findings", len(findings))
                return findings
            elif ".json" in str(file_path):
                findings = self._parse_json_findings(file_path)
                logger.info("AcunetixParser: Successfully parsed %s JSON findings", len(findings))
                return findings
            else:
                logger.error("AcunetixParser: Unsupported file format. Use .xml or .json")
                return []
        except Exception as e:
            logger.error("AcunetixParser: Failed to parse file: %s", e)
            return []

    def _parse_xml_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse XML findings using reference implementation logic"""
        try:
            tree = parse(file_path)
            root = tree.getroot()
            findings = []
            dupes = {}
            
            logger.debug("AcunetixParser: Processing XML root: %s", root.tag)

            # Process each Scan element
            for scan in root.findall("Scan"):
                logger.debug("AcunetixParser: Processing scan element")
                
                # Get start URL
                start_url = scan.findtext("StartURL")
                if start_url and ":" not in start_url:
                    start_url = "//" + start_url
                
                # Get report date
                report_date = None
                if scan.findtext("StartTime") and scan.findtext("StartTime") != "":
                    try:
                        report_date = date_parser.parse(scan.findtext("StartTime"), dayfirst=True).date()
                        logger.debug("AcunetixParser: Report date: %s", report_date)
                    except Exception as e:
                        logger.warning("AcunetixParser: Could not parse date: %s", e)
                
                # Process each ReportItem (this is the correct element name!)
                for item in scan.findall("ReportItems/ReportItem"):
                    logger.debug("AcunetixParser: Processing report item")
                    
                    finding = self._create_finding_from_xml_item(item, start_url, report_date)
                    if finding:
                        # Create duplicate key
                        dupe_key = hashlib.sha256(
                            "|".join([
                                finding.title,
                                str(finding.affected_asset),
                                str(finding.solution)
                            ]).encode("utf-8")
                        ).hexdigest()
                        
                        if dupe_key in dupes:
                            logger.debug("AcunetixParser: Merging duplicate finding: %s", finding.title)
                            # Merge with existing finding
                            existing = dupes[dupe_key]
                            existing.description += f"\n\n--- Additional Instance ---\n\n{finding.description}"
                            if finding.raw_data.get("request_response_pairs"):
                                existing.raw_data.setdefault("request_response_pairs", []).extend(
                                    finding.raw_data["request_response_pairs"]
                                )
                        else:
                            logger.debug("AcunetixParser: Adding new finding: %s", finding.title)
                            dupes[dupe_key] = finding
                            findings.append(finding)
            
            logger.info("AcunetixParser: Processed %s unique findings from XML", len(findings))
            return findings

        except Exception as e:
            logger.error("AcunetixParser: Failed to parse XML: %s", e)
            return []

    def _create_finding_from_xml_item(self, item, start_url: str, report_date) -> Optional[StandardizedFinding]:
        """Create StandardizedFinding from XML ReportItem"""
        try:
            # Extract basic information
            title = item.findtext("Name") or "Unknown Vulnerability"
            severity_text = item.findtext("Severity") or "Medium"
            description = item.findtext("Description") or ""
            
            # Clean HTML from description
            if description:
                description = html2text.html2text(description).strip()
            
            # Get additional details
            details = item.findtext("Details")
            if details and details.strip():
                description += f"\n\n**Details:**\n{html2text.html2text(details)}"
            
            technical_details = item.findtext("TechnicalDetails")
            if technical_details and technical_details.strip():
                description += f"\n\n**Technical Details:**\n{technical_details}"
            
            # Get impact and solution
            impact = item.findtext("Impact") or ""
            solution = item.findtext("Recommendation") or ""
            
            # Get CWE & CVE information
            cwe_ids = []
            cve_ids = []
            
            # Sometimes Acunetix places CVEs in the CWE block
            cwe_text = item.findtext("CWEList/CWE")
            if cwe_text:
                if cwe_text.startswith("CVE-"):
                    cve_ids.append(cwe_text.strip())
                else:
                    try:
                        cwe_number = int(cwe_text.split("-")[1])
                        cwe_ids = [f"CWE-{cwe_number}"]
                    except (ValueError, IndexError):
                        logger.warning("AcunetixParser: Could not parse CWE: %s", cwe_text)
                        
            # Also parse actual CVE list if present in XML
            for cve_item in item.findall("CVEList/CVE"):
                if cve_item.text and cve_item.text.strip():
                    if cve_item.text.strip() not in cve_ids:
                        cve_ids.append(cve_item.text.strip())
            # Regex fallback from references URLs (may contain CVE IDs)
            for ref in item.findall("References/Reference/URL"):
                if ref.text:
                    cve_ids.extend(self.extract_cve_ids(ref.text))
            cve_ids = list(dict.fromkeys(c.upper() for c in cve_ids if c))
            
            # Get references
            references = []
            for reference in item.findall("References/Reference"):
                url = reference.findtext("URL")
                db = reference.findtext("Database") or url
                if url:
                    references.append(f" * [{db}]({url})")
            
            # Get CVSS information
            cvss_vector = None
            cvss_score = None
            cvss_text = item.findtext("CVSS3/Descriptor")
            if cvss_text:
                try:
                    from cvss import parser as cvss_parser
                    cvss_objects = cvss_parser.parse_cvss_from_text(cvss_text)
                    if cvss_objects:
                        cvss_vector = cvss_objects[0].clean_vector()
                        cvss_score = cvss_objects[0].scores()[0]  # Base score
                except Exception as e:
                    logger.warning("AcunetixParser: Could not parse CVSS: %s", e)

            # Get request/response pairs
            request_response_pairs = []
            if item.findall("TechnicalDetails/Request"):
                for request in item.findall("TechnicalDetails/Request"):
                    request_response_pairs.append({
                        "request": request.text or "",
                        "response": ""
                    })
            
            # Get affected asset
            affected_asset = ""
            if start_url and item.findtext("Affects"):
                try:
                    url = hyperlink.parse(start_url)
                    endpoint = StandardizedEndpoint(
                        url=f"{url.scheme or 'http'}://{url.host}:{url.port or 80}{item.findtext('Affects')}"
                    )
                    affected_asset = endpoint.url
                except Exception as e:
                    logger.warning("AcunetixParser: Could not parse endpoint: %s", e)
                    affected_asset = f"{start_url}{item.findtext('Affects')}"
            
            # Convert severity
            severity_level = self._convert_severity(severity_text)
            
            # Create raw data with all original information
            raw_data = {
                "xml_item": self._element_to_dict(item),
                "start_url": start_url,
                "report_date": str(report_date) if report_date else None,
                "request_response_pairs": request_response_pairs,
                "false_positive": bool(item.findtext("IsFalsePositive")),
                "static_finding": len(request_response_pairs) == 0,
                "dynamic_finding": len(request_response_pairs) > 0,
                "occurrence_count": 1,
                "cve_ids": cve_ids
            }
            
            # Create standardized finding
            finding = StandardizedFinding(
                title=title,
                description=description,
                severity=severity_level,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                affected_asset=affected_asset,
                evidence=technical_details or "",
                solution=solution,
                references=references,
                scanner_type=self.scanner_type,
                scanner_id=f"acunetix_{title.lower().replace(' ', '_')}",
                tags=[],
                raw_data=raw_data
            )
            
            return finding
            
        except Exception as e:
            logger.error("AcunetixParser: Error creating finding from XML item: %s", e)
            return None

    def _parse_json_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse JSON findings using reference implementation logic"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            findings = []
            dupes = {}
            
            # Get scan date
            scan_date = None
            if "Generated" in data:
                try:
                    scan_date = date_parser.parse(data["Generated"], dayfirst=True)
                except Exception as e:
                    logger.warning("AcunetixParser: Could not parse scan date: %s", e)
            
            text_maker = html2text.HTML2Text()
            text_maker.body_width = 0
            
            logger.debug("AcunetixParser: Processing %s JSON vulnerabilities", len(data.get('Vulnerabilities', [])))

            for item in data.get("Vulnerabilities", []):
                logger.debug("AcunetixParser: Processing JSON vulnerability")
                
                finding = self._create_finding_from_json_item(item, scan_date, text_maker)
                if finding:
                    dupe_key = finding.title
                    
                    if dupe_key in dupes:
                        logger.debug("AcunetixParser: Merging duplicate JSON finding: %s", finding.title)
                        # Merge with existing finding
                        existing = dupes[dupe_key]
                        existing.description += f"\n\n--- Additional Instance ---\n\n{finding.description}"
                        if finding.raw_data.get("request_response_pairs"):
                            existing.raw_data.setdefault("request_response_pairs", []).extend(
                                finding.raw_data["request_response_pairs"]
                            )
                    else:
                        logger.debug("AcunetixParser: Adding new JSON finding: %s", finding.title)
                        dupes[dupe_key] = finding
                        findings.append(finding)
            
            logger.info("AcunetixParser: Processed %s unique findings from JSON", len(findings))
            return findings

        except Exception as e:
            logger.error("AcunetixParser: Failed to parse JSON: %s", e)
            return []

    def _create_finding_from_json_item(self, item: Dict, scan_date, text_maker) -> Optional[StandardizedFinding]:
        """Create StandardizedFinding from JSON item"""
        try:
            # Extract basic information
            title = item.get("Name", "Unknown Vulnerability")
            description = text_maker.handle(item.get("Description", ""))
            severity_text = item.get("Severity", "Medium")
            
            # Get CWE & CVE information
            cwe_ids = []
            cve_ids = []
            if item.get("Classification"):
                cwe_raw = str(item["Classification"].get("Cwe", ""))
                if cwe_raw:
                    for cwe_part in [x.strip() for x in cwe_raw.split(",") if x.strip()]:
                        if cwe_part.startswith("CVE-"):
                            if cwe_part not in cve_ids:
                                cve_ids.append(cwe_part)
                        else:
                            try:
                                cwe_number = int(cwe_part)
                                cwe_ids.append(f"CWE-{cwe_number}")
                            except ValueError:
                                logger.warning("AcunetixParser: Could not parse CWE: %s", cwe_part)
                
                # Also check direct Cve field just in case
                cve_raw = str(item["Classification"].get("Cve", ""))
                if cve_raw:
                    for cve_part in [x.strip() for x in cve_raw.split(",") if x.strip()]:
                        if cve_part not in cve_ids:
                            cve_ids.append(cve_part if cve_part.startswith("CVE-") else f"CVE-{cve_part}")

            # Extract CVEs from description and ExtraInformation (regex fallback)
            extra_info = item.get("ExtraInformation", "")
            if isinstance(extra_info, list):
                extra_info = " ".join(str(e.get("Value", "")) for e in extra_info if isinstance(e, dict))
            search_text = " ".join(filter(None, [
                item.get("Description", ""),
                extra_info,
                item.get("ExternalReferences", ""),
            ]))
            for cve in self.extract_cve_ids(search_text):
                if cve not in cve_ids:
                    cve_ids.append(cve)
            cve_ids = list(dict.fromkeys(c.upper() for c in cve_ids if c))

            # Get solution and references
            solution = text_maker.handle(item.get("RemedialProcedure", "")) if item.get("RemedialProcedure") else ""
            references = text_maker.handle(item.get("RemedyReferences", "")) if item.get("RemedyReferences") else ""
            
            # Add lookup ID reference
            if "LookupId" in item:
                lookup_url = f"https://online.acunetix360.com/issues/detail/{item['LookupId']}"
                if references:
                    references = f"{lookup_url}\n{references}"
                else:
                    references = lookup_url
            
            # Get affected asset
            affected_asset = item.get("Url", "")
            
            # Get impact
            impact = text_maker.handle(item.get("Impact", "")) if item.get("Impact") else ""
            
            # Get request/response pairs
            request_response_pairs = []
            request = item.get("HttpRequest", {}).get("Content", "Request Not Found")
            response = item.get("HttpResponse", {}).get("Content", "Response Not Found")
            request_response_pairs.append({
                "request": request,
                "response": response
            })
            
            # Get CVSS information
            cvss_vector = None
            cvss_score = None
            if (item.get("Classification") and 
                item["Classification"].get("Cvss") and 
                item["Classification"]["Cvss"].get("Vector")):
                try:
                    from cvss import parser as cvss_parser
                    cvss_objects = cvss_parser.parse_cvss_from_text(
                        item["Classification"]["Cvss"]["Vector"]
                    )
                    if cvss_objects:
                        cvss_vector = cvss_objects[0].clean_vector()
                        cvss_score = cvss_objects[0].scores()[0]  # Base score
                except Exception as e:
                    logger.warning("AcunetixParser: Could not parse CVSS: %s", e)

            # Convert severity
            severity_level = self._convert_severity(severity_text)
            
            # Check state for risk acceptance
            risk_accepted = False
            active = True
            false_positive = False
            if item.get("State"):
                state = [x.strip() for x in item["State"].split(",")]
                if "AcceptedRisk" in state:
                    risk_accepted = True
                    active = False
                elif "FalsePositive" in state:
                    false_positive = True
                    active = False
            
            # Create raw data
            raw_data = {
                "json_item": item,
                "scan_date": str(scan_date) if scan_date else None,
                "request_response_pairs": request_response_pairs,
                "static_finding": True,
                "dynamic_finding": False,
                "risk_accepted": risk_accepted,
                "active": active,
                "false_positive": false_positive,
                "cve_ids": cve_ids
            }
            
            # Create standardized finding
            finding = StandardizedFinding(
                title=title,
                description=description,
                severity=severity_level,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                affected_asset=affected_asset,
                evidence=impact,
                solution=solution,
                references=[references] if references else [],
                scanner_type=self.scanner_type,
                scanner_id=f"acunetix_{title.lower().replace(' ', '_')}",
                tags=[],
                raw_data=raw_data
            )
            
            return finding
            
        except Exception as e:
            logger.error("AcunetixParser: Error creating finding from JSON item: %s", e)
            return None

    def _convert_severity(self, severity: str) -> SeverityLevel:
        """Convert Acunetix severity to standardized severity"""
        severity_mapping = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO,
            'informational': SeverityLevel.INFO
        }
        
        severity_lower = severity.lower()
        for key, value in severity_mapping.items():
            if key in severity_lower:
                return value
        
        return SeverityLevel.MEDIUM

    def _element_to_dict(self, element) -> Dict:
        """Convert XML element to dictionary for raw_data storage"""
        result = {}
        if element.text and element.text.strip():
            result['text'] = element.text.strip()
        if element.attrib:
            result['attributes'] = dict(element.attrib)
        for child in element:
            child_data = self._element_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        return result


