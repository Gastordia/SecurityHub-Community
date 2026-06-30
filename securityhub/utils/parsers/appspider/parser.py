"""
AppSpider parser for SecurityHub
Parses AppSpider scan results
"""

import logging
import html2text
from typing import List, Dict, Any, Optional
from ...xml import parse_xml_safely as parse

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel

logger = logging.getLogger(__name__)


class AppSpiderParser(BaseParser):
    """Parser for AppSpider scan results"""
    
    def __init__(self):
        super().__init__()
        self.scanner_type = "appspider"
    
    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="AppSpider",
            version="1.0.0",
            description="Parser for Rapid7 AppSpider XML scan results",
            supported_formats=["xml"],
            author="SecurityHub Team",
            website="https://www.rapid7.com/products/appspider/"
        )

    def validate_file(self, file_path: str) -> bool:
        """Validate if file is a valid AppSpider report"""
        logger.debug("AppSpiderParser: Starting validation for %s", file_path)
        
        if not str(file_path).lower().endswith('.xml'):
            logger.debug("AppSpiderParser: Invalid file extension for %s", file_path)
            return False

        try:
            logger.debug("AppSpiderParser: Parsing XML file...")
            vscan = parse(file_path)
            root = vscan.getroot()
            logger.debug("AppSpiderParser: Root tag: %s", root.tag)

            # Check for AppSpider XML structure - must have VulnSummary tag
            is_valid = "VulnSummary" in str(root.tag)
            logger.info("AppSpiderParser: Validation result: %s", is_valid)
            return is_valid
        except Exception as e:
            logger.error("AppSpiderParser: Validation error: %s", e)
            return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse AppSpider XML file and return standardized findings"""
        logger.info("AppSpiderParser: Starting to parse findings from %s", file_path)

        if file_path is None:
            logger.error("AppSpiderParser: No file path provided")
            return []

        try:
            vscan = parse(file_path)
            root = vscan.getroot()

            if "VulnSummary" not in str(root.tag):
                msg = (
                    "Please ensure that you are uploading AppSpider's VulnerabilitiesSummary.xml file. "
                    "At this time it is the only file that is consumable by SecurityHub."
                )
                logger.error("AppSpiderParser: %s", msg)
                return []

            findings = self._process_findings(root)
            logger.info("AppSpiderParser: Successfully parsed %s findings", len(findings))
            return findings

        except Exception as e:
            logger.error("AppSpiderParser: Failed to parse file: %s", e)
            return []

    def _process_findings(self, root) -> List[StandardizedFinding]:
        """Process XML root and return standardized findings"""
        logger.debug("AppSpiderParser: Processing XML root: %s", root.tag)

        dupes = {}

        for finding in root.iter("Vuln"):
            logger.debug("AppSpiderParser: Processing Vuln element")
            
            try:
                # Extract basic information using correct element names
                attack_score = finding.find("AttackScore")
                severity = self.convert_severity(attack_score.text if attack_score is not None else "0-Safe")
                
                vuln_type = finding.find("VulnType")
                title = vuln_type.text if vuln_type is not None else "Unknown Vulnerability"
                
                description_elem = finding.find("Description")
                description = description_elem.text if description_elem is not None else ""
                
                recommendation_elem = finding.find("Recommendation")
                mitigation = recommendation_elem.text if recommendation_elem is not None else ""
                
                vuln_url_elem = finding.find("VulnUrl")
                vuln_url = vuln_url_elem.text if vuln_url_elem is not None else ""
                
                cwe_elem = finding.find("CweId")
                cwe = int(cwe_elem.text) if cwe_elem is not None and cwe_elem.text else None

                # Create duplicate key
                dupe_key = severity + title

                if dupe_key in dupes:
                    logger.debug("AppSpiderParser: Merging duplicate finding: %s", title)
                    existing_finding = dupes[dupe_key]
                    # Add new attack data
                    self._add_attack_data_to_finding(finding, existing_finding)
                else:
                    logger.debug("AppSpiderParser: Adding new finding: %s", title)
                    new_finding = self._create_standardized_finding(
                        title, description, mitigation, severity, cwe, vuln_url
                    )
                    # Add attack data
                    self._add_attack_data_to_finding(finding, new_finding)
                    dupes[dupe_key] = new_finding
                    
            except Exception as e:
                logger.error("AppSpiderParser: Error processing Vuln element: %s", e)
                continue

        logger.info("AppSpiderParser: Processed %s unique findings", len(dupes))
        return list(dupes.values())

    def _create_standardized_finding(self, title: str, description: str, mitigation: str, 
                                   severity: str, cwe: int, vuln_url: str) -> StandardizedFinding:
        """Create a standardized finding from AppSpider data"""
        
        # Map severity to SeverityLevel enum
        severity_mapping = {
            "Critical": SeverityLevel.CRITICAL,
            "High": SeverityLevel.HIGH,
            "Medium": SeverityLevel.MEDIUM,
            "Low": SeverityLevel.LOW,
            "Info": SeverityLevel.INFO
        }
        standardized_severity = severity_mapping.get(severity, SeverityLevel.MEDIUM)

        # Clean HTML from description and mitigation
        clean_description = html2text.html2text(description) if description else ""
        clean_solution = html2text.html2text(mitigation) if mitigation else ""

        # Convert CWE to list format
        cwe_ids = [f"CWE-{cwe}"] if cwe else []

        # Extract CVEs from description text
        cve_ids = self.extract_cve_ids(clean_description + " " + clean_solution)

        # Create raw data
        raw_data = {
            "vuln_url": vuln_url,
            "original_severity": severity,
            "cwe_id": cwe,
            "cve_ids": cve_ids,
        }

        # Create standardized finding
        finding = StandardizedFinding(
            title=title,
            severity=standardized_severity,
            description=clean_description,
            solution=clean_solution,
            affected_asset=vuln_url,
            cwe_ids=cwe_ids,
            scanner_type="appspider",
            scanner_id=title,  # Use title as scanner ID since no specific ID is provided
            raw_data=raw_data
        )

        return finding

    def _add_attack_data_to_finding(self, finding_element, finding: StandardizedFinding):
        """Add attack request/response data to finding"""
        logger.debug("AppSpiderParser: Adding attack data to finding: %s", finding.title)
        
        for attack in finding_element.iter("AttackRequest"):
            try:
                req_elem = attack.find("Request")
                resp_elem = attack.find("Response")
                
                req = req_elem.text if req_elem is not None else ""
                resp = resp_elem.text if resp_elem is not None else ""

                # Store attack data in raw_data since StandardizedFinding doesn't have request_response_pairs
                if "attack_data" not in finding.raw_data:
                    finding.raw_data["attack_data"] = []
                
                finding.raw_data["attack_data"].append({
                    "request": req,
                    "response": resp
                })
                
                logger.debug("AppSpiderParser: Added attack request/response pair")
            except Exception as e:
                logger.warning("AppSpiderParser: Error processing attack request: %s", e)

    @staticmethod
    def convert_severity(val):
        """Convert AppSpider severity to standardized severity"""
        severity = "Info"
        if val == "0-Safe":
            severity = "Info"
        elif val == "1-Informational":
            severity = "Low"
        elif val == "2-Low":
            severity = "Low"  # Fixed: 2-Low should map to Low, not Medium
        elif val == "3-Medium":
            severity = "High"
        elif val == "4-High":
            severity = "Critical"
        return severity

    def get_scan_types(self):
        return ["AppSpider Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AppSpider Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AppSpider (Rapid7) - Use the VulnerabilitiesSummary.xml file found in the zipped report download."
