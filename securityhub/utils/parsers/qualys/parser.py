"""
Qualys Vulnerability Scanner Parser
Handles Qualys vulnerability scan reports in XML format
"""

import logging
from typing import List, Dict, Any
from ...xml import parse_xml_safely as parse
from ..base import BaseParser
from ..models import StandardizedFinding, SeverityLevel, StandardizedEndpoint, ParserMetadata

logger = logging.getLogger(__name__)


class QualysParser(BaseParser):
    """Parser for Qualys vulnerability scan reports"""
    
    def __init__(self):
        super().__init__()
        self.scanner_type = "qualys"
    
    def get_metadata(self) -> ParserMetadata:
        """Get parser metadata"""
        return ParserMetadata(
            name="Qualys Vulnerability Scanner",
            version="1.0.0",
            description="Parser for Qualys vulnerability scan reports",
            author="SecurityHub Team",
            website="https://www.qualys.com",
            supported_formats=["xml"]
        )
    
    def validate_file(self, file_path: str) -> bool:
        """Validate if file is a valid Qualys report"""
        try:
            root = parse(file_path).getroot()
            # Check for Qualys-specific root elements
            return any(tag in root.tag.lower() for tag in [
                "qualys", "scan", "vulnerability", "report", "knowledgebase"
            ])
        except Exception as e:
            logger.debug("Qualys validation failed: %s", e)
            return False
    
    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse Qualys XML report and return standardized findings"""
        try:
            root = parse(file_path).getroot()
            findings = []
            
            # Handle different Qualys XML structures
            vuln_elements = []
            
            # Try different possible paths for vulnerabilities
            possible_paths = [
                ".//VULN",
                ".//Vulnerability", 
                ".//VULNERABILITY",
                ".//VULN_LIST/VULN",
                ".//SCAN_RESULTS/VULN",
                ".//REPORT/VULN",
                ".//KNOWLEDGE_BASE/VULN"
            ]
            
            for path in possible_paths:
                vuln_elements = root.findall(path)
                if vuln_elements:
                    logger.info("Found %s vulnerabilities using path: %s", len(vuln_elements), path)
                    break
            
            # If no vulnerabilities found, try to find any element with vulnerability-like attributes
            if not vuln_elements:
                for elem in root.iter():
                    if any(attr in elem.tag.lower() for attr in ['vuln', 'vulnerability']):
                        vuln_elements.append(elem)
            
            for vuln in vuln_elements:
                finding = self._create_finding_from_xml(vuln)
                if finding:
                    findings.append(finding)
            
            logger.info("Parsed %s findings from Qualys report", len(findings))
            return findings

        except Exception as e:
            logger.error("Error parsing Qualys file: %s", e)
            return []
    
    def _create_finding_from_xml(self, vuln) -> StandardizedFinding:
        """Create finding from XML vulnerability element"""
        try:
            # Extract basic information
            title = self._get_text(vuln, ["TITLE", "NAME", "VULN_NAME"])
            if not title:
                return None
            
            description = self._get_text(vuln, ["DESCRIPTION", "DETAILS", "SUMMARY"])
            severity = self._get_text(vuln, ["SEVERITY", "RISK", "LEVEL", "THREAT"])
            
            # Get CVSS information
            cvss_score = self._get_cvss_score(vuln)
            cvss_vector = self._get_text(vuln, ["CVSS_VECTOR", "CVSS_VECTOR_STRING"])
            
            # Get affected asset
            affected_asset = self._get_affected_asset(vuln)
            
            # Get solution/remediation
            solution = self._get_text(vuln, ["SOLUTION", "REMEDIATION", "FIX"])
            
            # Get references
            references = self._get_references(vuln)
            
            # Get CWE information
            cwe_ids = self._get_cwe_ids(vuln)

            # Get CVE IDs from <CVE_ID_LIST> and from description text
            cve_ids = self._get_cve_ids(vuln, description)

            # Convert severity
            severity_level = self._convert_severity(severity)

            # Create endpoint if we have host/port information
            endpoint = None
            if affected_asset:
                endpoint = StandardizedEndpoint(
                    url=affected_asset,
                    protocol="http",
                    port=80
                )

            # Create finding
            raw_data = self._extract_raw_data(vuln)
            raw_data["cve_ids"] = cve_ids
            finding = StandardizedFinding(
                title=title,
                description=description,
                severity=severity_level,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                solution=solution,
                references=references,
                cwe_ids=cwe_ids,
                affected_asset=affected_asset,
                scanner_type=self.scanner_type,
                scanner_id=self._get_text(vuln, ["QID", "ID", "VULN_ID"]),
                raw_data=raw_data
            )
            
            return finding
            
        except Exception as e:
            logger.error("Error creating Qualys finding: %s", e)
            return None
    
    def _get_text(self, element, possible_names: List[str]) -> str:
        """Get text from element using multiple possible tag names"""
        for name in possible_names:
            text = element.findtext(name)
            if text:
                return text.strip()
        return ""
    
    def _get_cvss_score(self, vuln) -> float:
        """Extract CVSS score from vulnerability element"""
        cvss_text = self._get_text(vuln, ["CVSS_SCORE", "CVSS", "SCORE"])
        if cvss_text:
            try:
                return float(cvss_text)
            except (ValueError, TypeError):
                pass
        return None
    
    def _get_affected_asset(self, vuln) -> str:
        """Extract affected asset information"""
        # Try different possible asset fields
        asset_fields = ["HOST", "IP", "URL", "LOCATION", "AFFECTED_ASSET"]
        for field in asset_fields:
            asset = self._get_text(vuln, [field])
            if asset:
                return asset
        
        # If no direct asset field, look in parent elements
        parent = vuln.getparent()
        if parent is not None:
            for field in asset_fields:
                asset = self._get_text(parent, [field])
                if asset:
                    return asset
        
        return ""
    
    def _get_references(self, vuln) -> List[str]:
        """Extract references from vulnerability element"""
        references = []
        
        # Look for references element
        refs_elem = vuln.find("REFERENCES") or vuln.find("LINKS") or vuln.find("URLS")
        if refs_elem is not None:
            for ref in refs_elem.findall("REFERENCE") or refs_elem.findall("LINK") or refs_elem.findall("URL"):
                if ref.text:
                    references.append(ref.text.strip())
        
        # Also check for single reference fields
        ref_text = self._get_text(vuln, ["REFERENCE", "LINK", "URL"])
        if ref_text:
            references.append(ref_text)
        
        return references
    
    def _get_cwe_ids(self, vuln) -> List[str]:
        """Extract CWE IDs from vulnerability element"""
        cwe_ids = []
        
        # Look for CWE element
        cwe_elem = vuln.find("CWE") or vuln.find("CWE_ID")
        if cwe_elem is not None:
            cwe_text = cwe_elem.text
            if cwe_text:
                # Handle multiple CWE IDs separated by commas or semicolons
                for cwe_id in cwe_text.replace(';', ',').split(','):
                    cwe_id = cwe_id.strip()
                    if cwe_id and cwe_id.isdigit():
                        cwe_ids.append(f"CWE-{cwe_id}")
        
        return cwe_ids
    
    def _convert_severity(self, severity: str) -> SeverityLevel:
        """Convert Qualys severity to standardized severity"""
        if not severity:
            return SeverityLevel.MEDIUM
        
        severity_lower = severity.lower()
        
        if any(word in severity_lower for word in ["critical", "5", "high"]):
            return SeverityLevel.CRITICAL
        elif any(word in severity_lower for word in ["high", "4"]):
            return SeverityLevel.HIGH
        elif any(word in severity_lower for word in ["medium", "3", "moderate"]):
            return SeverityLevel.MEDIUM
        elif any(word in severity_lower for word in ["low", "2", "info"]):
            return SeverityLevel.LOW
        elif any(word in severity_lower for word in ["info", "1", "information"]):
            return SeverityLevel.INFO
        else:
            return SeverityLevel.MEDIUM
    
    def _get_cve_ids(self, vuln, description: str = "") -> List[str]:
        """Extract CVE IDs from Qualys XML CVE_ID_LIST and description text."""
        cve_ids = []
        # <CVE_ID_LIST><CVE_ID><ID>CVE-XXXX-XXXX</ID></CVE_ID>...</CVE_ID_LIST>
        cve_list_elem = vuln.find("CVE_ID_LIST")
        if cve_list_elem is not None:
            for cve_id_elem in cve_list_elem.findall("CVE_ID"):
                id_elem = cve_id_elem.find("ID")
                if id_elem is not None and id_elem.text:
                    cve_ids.append(id_elem.text.strip())
        # Fallback: regex on description
        if not cve_ids and description:
            cve_ids = self.extract_cve_ids(description)
        return list(dict.fromkeys(c.upper() for c in cve_ids if c))

    def _extract_raw_data(self, vuln) -> Dict[str, Any]:
        """Extract raw data from vulnerability element for debugging"""
        raw_data = {}
        
        # Extract all attributes
        raw_data['attributes'] = dict(vuln.attrib)
        
        # Extract text content from common fields
        common_fields = [
            "TITLE", "DESCRIPTION", "SEVERITY", "CVSS_SCORE", "CVSS_VECTOR",
            "SOLUTION", "QID", "HOST", "IP", "URL", "CWE", "REFERENCES"
        ]
        
        for field in common_fields:
            text = self._get_text(vuln, [field])
            if text:
                raw_data[field.lower()] = text
        
        return raw_data
