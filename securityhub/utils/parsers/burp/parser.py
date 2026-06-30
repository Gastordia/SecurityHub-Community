"""
Burp Suite parser for SecurityHub
Parses Burp Suite XML scan results
"""

import base64
import logging
import re
import html2text
from typing import List, Dict, Any, Optional
from ...xml import parse_xml_safely as parse

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel, StandardizedEndpoint

logger = logging.getLogger(__name__)


class BurpParser(BaseParser):
    """Parser for Burp Suite XML scan results"""
    
    def __init__(self):
        super().__init__()
        self.scanner_type = "burp"
    
    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="Burp Suite",
            version="1.0.0",
            description="Parser for Burp Suite XML scan results",
            supported_formats=["xml"],
            author="SecurityHub Team",
            website="https://portswigger.net/burp"
        )

    def validate_file(self, file_path: str) -> bool:
        """Validate if file is a Burp XML report"""
        logger.debug("BurpParser: Starting validation for %s", file_path)
        
        if not str(file_path).lower().endswith('.xml'):
            logger.debug("BurpParser: Invalid file extension for %s", file_path)
            return False

        try:
            logger.debug("BurpParser: Parsing XML file...")
            tree = parse(file_path)
            root = tree.getroot()
            logger.debug("BurpParser: Root tag: %s", root.tag)

            # Check if it has the expected Burp XML structure
            is_valid = root.tag == "issues" or any(child.tag == "issue" for child in root)
            logger.info("BurpParser: Validation result: %s", is_valid)
            return is_valid
        except Exception as e:
            logger.error("BurpParser: Validation error: %s", e)
            return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse Burp XML file and return standardized findings"""
        logger.info("BurpParser: Starting to parse findings from %s", file_path)
        try:
            tree = parse(file_path)
            findings = self._get_items(tree)
            logger.info("BurpParser: Successfully parsed %s findings", len(findings))
            return findings
        except Exception as e:
            logger.error("BurpParser: Failed to parse file: %s", e)
            return []

    def _get_items(self, tree) -> List[StandardizedFinding]:
        """Internal method to get items from XML tree"""
        logger.debug("BurpParser: Processing XML tree...")
        items = {}
        issue_count = 0

        for node in tree.findall("issue"):
            issue_count += 1
            logger.debug("BurpParser: Processing issue %s", issue_count)
            item = self._get_item(node)
            if item:
                dupe_key = item.scanner_id
                if dupe_key in items:
                    logger.debug("BurpParser: Merging duplicate finding: %s", dupe_key)
                    # Add new endpoints and request/response pairs to raw_data
                    if "affected_endpoints" in item.raw_data:
                        if "affected_endpoints" not in items[dupe_key].raw_data:
                            items[dupe_key].raw_data["affected_endpoints"] = []
                        items[dupe_key].raw_data["affected_endpoints"].extend(item.raw_data["affected_endpoints"])
                    
                    if "request_response_pairs" in item.raw_data:
                        if "request_response_pairs" not in items[dupe_key].raw_data:
                            items[dupe_key].raw_data["request_response_pairs"] = []
                        items[dupe_key].raw_data["request_response_pairs"].extend(item.raw_data["request_response_pairs"])
                    
                    items[dupe_key].description += "\n\n" + item.description
                else:
                    logger.debug("BurpParser: Adding new finding: %s", dupe_key)
                    items[dupe_key] = item

        logger.info("BurpParser: Processed %s issues, created %s unique findings", issue_count, len(items))
        return list(items.values())

    def _get_item(self, node) -> Optional[StandardizedFinding]:
        """Parse individual Burp issue"""
        try:
            # Extract basic information using correct element names
            serial_number = node.find("serialNumber")
            serial_number_text = serial_number.text if serial_number is not None else ""
            
            vuln_type = node.find("type")
            vuln_type_text = vuln_type.text if vuln_type is not None else "Unknown"
            
            url = node.get("url", "")
            path = node.find("path")
            path_text = path.text if path is not None else ""
            
            location = node.find("location")
            location_text = location.text if location is not None else ""
            
            # Extract parameter from location
            parameter = None
            if location_text:
                rparameter = re.search(r"(?<=\[)(.*)(\])", location_text)
                if rparameter:
                    parameter = rparameter.group(1)

            # Extract request/response pairs
            request_response_pairs = []
            for request_response in node.findall("./requestresponse"):
                request_elem = request_response.find("request")
                request_text = self._get_clean_base64(request_elem.text) if request_elem is not None else ""
                
                response_elem = request_response.find("response")
                response_text = ""
                if response_elem is not None:
                    response_text = self._get_clean_base64(response_elem.text)
                
                request_response_pairs.append({
                    "request": request_text,
                    "response": response_text
                })

            # Extract collaborator events
            collab_text = ""
            for event in node.findall("./collaboratorEvent"):
                collab_details = []
                
                interaction_type = event.find("interactionType")
                origin_ip = event.find("originIp")
                time_elem = event.find("time")
                
                if interaction_type is not None and origin_ip is not None and time_elem is not None:
                    collab_details.extend((
                        interaction_type.text,
                        origin_ip.text,
                        time_elem.text,
                    ))

                    if collab_details[0] == "DNS":
                        lookup_type = event.find("lookupType")
                        lookup_host = event.find("lookupHost")
                        if lookup_type is not None and lookup_host is not None:
                            collab_details.extend((
                                lookup_type.text,
                                lookup_host.text,
                            ))
                            collab_text += (
                                "The Collaborator server received a "
                                + collab_details[0]
                                + " lookup of type "
                                + collab_details[3]
                                + " for the domain name "
                                + collab_details[4]
                                + " at "
                                + collab_details[2]
                                + " originating from "
                                + collab_details[1]
                                + ". "
                            )

                    for req_resp in event.findall("./requestresponse"):
                        req_elem = req_resp.find("request")
                        resp_elem = req_resp.find("response")
                        
                        req_text = self._get_clean_base64(req_elem.text) if req_elem is not None else ""
                        resp_text = self._get_clean_base64(resp_elem.text) if resp_elem is not None else ""
                        
                        request_response_pairs.append({
                            "request": req_text,
                            "response": resp_text
                        })
                        
                    if collab_details[0] == "HTTP":
                        collab_text += (
                            "The Collaborator server received an "
                            + collab_details[0]
                            + " request at "
                            + collab_details[2]
                            + " originating from "
                            + collab_details[1]
                            + ". "
                        )

            # Clean HTML content
            text_maker = html2text.HTML2Text()
            text_maker.body_width = 0

            # Extract and clean background
            background = self._do_clean(node.findall("issueBackground"))
            if background:
                background = text_maker.handle(background)

            # Extract and clean detail
            detail = self._do_clean(node.findall("issueDetail"))
            if detail:
                detail = text_maker.handle(detail)
                if collab_text:
                    detail = text_maker.handle(detail + "<p>" + collab_text + "</p>")

            # Extract and clean remediation
            remediation = self._do_clean(node.findall("remediationBackground"))
            if remediation:
                remediation = text_maker.handle(remediation)

            remediation_detail = self._do_clean(node.findall("remediationDetail"))
            if remediation_detail:
                remediation = text_maker.handle(remediation_detail + "\n") + remediation

            # Extract and clean references
            references = self._do_clean(node.findall("references"))
            if references:
                references = text_maker.handle(references)

            # Extract severity
            severity_elem = node.find("severity")
            severity_text = severity_elem.text if severity_elem is not None else "Medium"
            if severity_text.lower() == "information":
                severity_text = "Info"

            # Extract confidence — map Burp's text labels to 0-1 float (higher = more confident)
            confidence_elem = node.find("confidence")
            confidence_score = None
            if confidence_elem is not None and confidence_elem.text:
                confidence_text = confidence_elem.text.strip()
                if confidence_text == "Certain":
                    confidence_score = 1.0
                elif confidence_text == "Firm":
                    confidence_score = 0.66
                elif confidence_text == "Tentative":
                    confidence_score = 0.33

            # Extract host and path
            host_elem = node.find("host")
            url_host = host_elem.text if host_elem is not None else ""
            path_elem = node.find("path")
            path_text = path_elem.text if path_elem is not None else ""

            # Extract name
            name_elem = node.find("name")
            name_text = name_elem.text if name_elem is not None else "Unknown Vulnerability"

            # Extract CWE
            cwe_ids = []
            cwe_elem = node.find("vulnerabilityClassifications")
            if cwe_elem is not None and cwe_elem.text:
                cwes = self._do_clean_cwe([cwe_elem])
                if cwes:
                    cwe_ids = [f"CWE-{cwes[0]}"]

            # Extract CVEs from detail, background and references text
            search_text = " ".join(filter(None, [detail, background, references]))
            cve_ids = self.extract_cve_ids(search_text)

            # Convert severity
            severity_level = self._convert_severity(severity_text)

            # Create standardized finding
            finding = StandardizedFinding(
                title=name_text,
                severity=severity_level,
                description=f"URL: {url_host}{path_text}\n\n{detail}\n",
                solution=remediation,
                evidence=background,
                references=[references] if references else [],
                cwe_ids=cwe_ids,
                scanner_type="Burp Suite",
                scanner_id=vuln_type_text,
                raw_data={
                    "serial_number": serial_number_text,
                    "parameter": parameter,
                    "url": url,
                    "path": path_text,
                    "location": location_text,
                    "confidence_score": confidence_score,
                    "request_response_pairs": request_response_pairs,
                    "cve_ids": cve_ids,
                }
            )

            # Store affected endpoint in raw_data since StandardizedFinding doesn't have affected_endpoints
            if url:
                finding.raw_data["affected_endpoints"] = [{"url": url}]

            return finding
            
        except Exception as e:
            logger.error("BurpParser: Error parsing item: %s", e)
            return None

    def _convert_severity(self, severity: str) -> SeverityLevel:
        """Convert Burp severity to standardized severity"""
        severity_mapping = {
            "Critical": SeverityLevel.CRITICAL,
            "High": SeverityLevel.HIGH,
            "Medium": SeverityLevel.MEDIUM,
            "Low": SeverityLevel.LOW,
            "Info": SeverityLevel.INFO
        }
        
        return severity_mapping.get(severity, SeverityLevel.MEDIUM)

    def _get_clean_base64(self, value: str) -> str:
        """Clean and decode base64 string"""
        if value is None:
            return ""
        
        try:
            # Remove any whitespace and newlines
            clean_string = value.strip()
            # Decode base64
            decoded = base64.b64decode(clean_string)
            # Convert to string
            return decoded.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            # decoding of UTF-8 fail when you have a binary payload in the HTTP response
            # so we just cut it to have only the header and add fake body
            try:
                return "\r\n\r\n".join([
                    base64.b64decode(value).split(b"\r\n\r\n")[0].decode(),
                    "<Binary Redacted Data>",
                ])
            except Exception as e:
                logger.warning("BurpParser: Failed to decode base64: %s", e)
                return value
        except Exception as e:
            logger.warning("BurpParser: Failed to decode base64: %s", e)
            return value

    def _do_clean(self, value) -> str:
        """Clean XML element text"""
        myreturn = ""
        if value is not None:
            if len(value) > 0:
                for x in value:
                    if x.text is not None:
                        myreturn += x.text
        return myreturn

    def _do_clean_cwe(self, value) -> List[int]:
        """Extract CWE IDs from vulnerability classifications"""
        if value is None:
            return []
        
        cwes = []
        if len(value) > 0:
            for x in value:
                if x.text is not None:
                    for detected in re.findall(r"CWE-(\d+)", x.text):
                        cwes.append(int(detected))
        return cwes

    def get_scan_types(self):
        return ["Burp Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Burp Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "When the Burp report is generated, the recommended option is Base64 encoding both the request and "
            "response fields. These fields will be processed and made available in the 'Finding View' page."
        )
