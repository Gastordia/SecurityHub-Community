"""
Nuclei parser for SecurityHub
Parses Nuclei JSON scan results
"""

import hashlib
import json
import logging
from typing import List, Dict, Any, Optional

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel, StandardizedEndpoint

logger = logging.getLogger(__name__)


class NucleiParser(BaseParser):
    """Parser for Nuclei JSON scan results"""
    
    def __init__(self):
        super().__init__()
        self.scanner_type = "nuclei"
    
    DEFAULT_SEVERITY = "Low"
    
    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="Nuclei",
            version="1.0.0",
            description="Parser for Nuclei JSON scan results",
            supported_formats=["json"],
            author="SecurityHub Team",
            website="https://github.com/projectdiscovery/nuclei"
        )

    def validate_file(self, file_path: str) -> bool:
        """Validate if file is a valid Nuclei JSON report"""
        if not str(file_path).lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
            
            if not content:
                return False
            
            # Check for Nuclei JSON structure
            if content.startswith('['):
                data = json.loads(content)
                return isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict)
            elif content.startswith('{'):
                # Line-by-line JSON format
                lines = content.split('\n')
                for line in lines:
                    if line.strip():
                        data = json.loads(line)
                        return isinstance(data, dict)
            return False
        except Exception:
            return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse Nuclei JSON file and return standardized findings"""
        try:
            with open(file_path, 'r') as f:
                filecontent = f.read()
            
            if isinstance(filecontent, bytes):
                filecontent = filecontent.decode("utf-8")
            
            data = []
            if filecontent == "" or len(filecontent) == 0:
                return []
            
            if filecontent[0] == "[":
                content = json.loads(filecontent)
                for template in content:
                    data.append(template)
            elif filecontent[0] == "{":
                file = filecontent.split("\n")
                for line in file:
                    if line != "":
                        data.append(json.loads(line))
            
            return self._process_findings(data)
            
        except Exception as e:
            logger.error(f"Failed to parse Nuclei file: {str(e)}")
            return []

    def _process_findings(self, data: List[Dict]) -> List[StandardizedFinding]:
        """Process findings data and return standardized findings"""
        dupes = {}
        
        for item in data:
            logger.debug("Processing item: %s", str(item))
            finding = self._create_standardized_finding(item)
            
            if finding:
                # Use the same duplicate detection logic
                template_id = item.get("templateID", item.get("template-id", ""))
                item_type = item.get("type", "")
                matcher = item.get("matcher-name", item.get("matcher_name", ""))
                host = item.get("host", "")
                
                dupe_key = hashlib.sha256(
                    (template_id + item_type + matcher + host).encode("utf-8"),
                ).hexdigest()
                
                if dupe_key in dupes:
                    logger.debug("dupe_key %s exists.", str(dupe_key))
                    existing_finding = dupes[dupe_key]
                    existing_finding.description += f"\n\n--- Additional Instance ---\n\n{finding.description}"
                else:
                    dupes[dupe_key] = finding
        
        return list(dupes.values())

    def _create_standardized_finding(self, item: Dict) -> Optional[StandardizedFinding]:
        """Create a standardized finding from Nuclei item"""
        try:
            # Extract basic information
            template_id = item.get("templateID", item.get("template-id", ""))
            template_name = item.get("template", "")
            info = item.get("info", {})
            
            # Get severity
            severity = info.get("severity", self.DEFAULT_SEVERITY)
            severity_level = self._convert_severity(severity)
            
            # Get description and references
            description = info.get("description", "")
            references = info.get("reference", [])
            if isinstance(references, str):
                references = [references]
            
            # Get CVE information from multiple sources
            cve_ids = []
            # 1. Explicit cve field
            cve_list = info.get("cve", [])
            if isinstance(cve_list, list):
                cve_ids.extend(cve_list)
            elif isinstance(cve_list, str):
                cve_ids.append(cve_list)
            # 2. classification.cve-id field (newer nuclei templates)
            classification = info.get("classification", {})
            if isinstance(classification, dict):
                cve_class = classification.get("cve-id", classification.get("cve_id", []))
                if isinstance(cve_class, list):
                    cve_ids.extend(cve_class)
                elif isinstance(cve_class, str):
                    cve_ids.append(cve_class)
            # 3. Template ID itself (e.g. CVE-2021-44228)
            import re as _re
            if _re.match(r'^CVE-\d{4}-\d+$', template_id, _re.IGNORECASE):
                cve_ids.append(template_id.upper())
            # 4. Regex extraction from references and description
            ref_text = " ".join(references) if isinstance(references, list) else str(references)
            cve_ids.extend(_re.findall(r'CVE-\d{4}-\d{4,}', ref_text, _re.IGNORECASE))
            cve_ids = list(dict.fromkeys(c.upper() for c in cve_ids if c))
            
            # Get CWE information
            cwe_ids = []
            cwe_list = info.get("cwe", [])
            if isinstance(cwe_list, list):
                cwe_ids.extend([f"CWE-{cwe}" for cwe in cwe_list])
            elif isinstance(cwe_list, str):
                cwe_ids.append(f"CWE-{cwe_list}")
            
            # Get CVSS information
            cvss_score = None
            cvss_vector = None
            cvss_info = info.get("cvss", {})
            if isinstance(cvss_info, dict):
                cvss_score = cvss_info.get("score")
                cvss_vector = cvss_info.get("vector")
            elif isinstance(cvss_info, str):
                # Try to extract score from string
                try:
                    cvss_score = float(cvss_info)
                except ValueError:
                    pass
            
            # Get affected asset
            host = item.get("host", "")
            matched_at = item.get("matched-at", item.get("matchedAt", ""))
            affected_asset = matched_at if matched_at else host
            
            # Get evidence
            evidence = item.get("extracted-results", item.get("extractedResults", []))
            if isinstance(evidence, list):
                evidence = "\n".join(evidence)
            
            # Get tags
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            
            # Create finding
            finding = StandardizedFinding(
                title=template_name,
                description=description,
                severity=severity_level,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                affected_asset=affected_asset,
                evidence=evidence,
                references=references,
                scanner_type="nuclei",
                scanner_id=template_id,
                tags=tags,
                raw_data={
                    "template_id": template_id,
                    "template_name": template_name,
                    "host": host,
                    "matched_at": matched_at,
                    "info": info,
                    "cve_ids": cve_ids,
                }
            )
            
            return finding
            
        except Exception as e:
            logger.error(f"Error creating Nuclei finding: {str(e)}")
            return None

    def _convert_severity(self, severity: str) -> SeverityLevel:
        """Convert Nuclei severity to standardized severity level"""
        severity_lower = str(severity).lower()
        
        if severity_lower in ['critical', 'fatal']:
            return SeverityLevel.CRITICAL
        elif severity_lower in ['high', 'error']:
            return SeverityLevel.HIGH
        elif severity_lower in ['medium', 'warning']:
            return SeverityLevel.MEDIUM
        elif severity_lower in ['low', 'info', 'information']:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.LOW


