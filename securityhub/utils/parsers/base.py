"""
Base parser class for all scanner parsers
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from .models import StandardizedFinding, ParserMetadata

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """Base class for all scanner parsers"""
    
    def __init__(self):
        self.scanner_type = ""
    
    @abstractmethod
    def get_metadata(self) -> ParserMetadata:
        """Get parser metadata"""
        pass
    
    @abstractmethod
    def validate_file(self, file_path: str) -> bool:
        """Validate if file is compatible with this parser"""
        pass
    
    @abstractmethod
    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse file and return standardized findings"""
        pass
    
    def validate_file_exists(self, file_path: str) -> bool:
        """Check if file exists and is readable"""
        try:
            if not os.path.exists(file_path):
                logger.warning("File does not exist: %s", file_path)
                return False

            if not os.path.isfile(file_path):
                logger.warning("Path is not a file: %s", file_path)
                return False

            if not os.access(file_path, os.R_OK):
                logger.warning("File is not readable: %s", file_path)
                return False

            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                logger.warning("File is empty: %s", file_path)
                return False

            if file_size > 100 * 1024 * 1024:  # 100MB limit
                logger.warning("File is too large (%s bytes): %s", file_size, file_path)
                return False

            logger.debug("File validation passed: %s (%s bytes)", file_path, file_size)
            return True

        except Exception as e:
            logger.error("Error validating file %s: %s", file_path, e)
            return False
    
    def validate_file_extension(self, file_path: str, allowed_extensions: List[str]) -> bool:
        """Validate file extension"""
        file_ext = os.path.splitext(file_path.lower())[1]
        logger.debug("BaseParser: Checking file extension '%s' against allowed: %s", file_ext, allowed_extensions)
        if file_ext not in allowed_extensions:
            logger.warning("BaseParser: Unsupported file extension %s for %s", file_ext, self.scanner_type)
            return False
        logger.debug("BaseParser: File extension validation passed")
        return True
    
    def safe_parse_xml(self, file_path: str):
        """Safely parse XML file with error handling"""
        try:
            logger.debug("BaseParser: Parsing XML file: %s", file_path)
            from ..xml import parse_xml_safely
            tree = parse_xml_safely(file_path)
            root = tree.getroot()
            logger.debug("BaseParser: XML root tag: %s", root.tag)
            return root
        except Exception as e:
            logger.error("BaseParser: Error parsing XML file %s: %s", file_path, e)
            return None
    
    def safe_parse_json(self, file_path: str):
        """Safely parse JSON file with error handling"""
        try:
            logger.debug("BaseParser: Parsing JSON file: %s", file_path)
            import json
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            logger.debug("BaseParser: JSON parsed successfully, keys: %s", list(data.keys()) if isinstance(data, dict) else 'not a dict')
            return data
        except Exception as e:
            logger.error("BaseParser: Error parsing JSON file %s: %s", file_path, e)
            return None
    
    def extract_text_safely(self, element, default: str = "") -> str:
        """Safely extract text from XML element"""
        if element is None:
            return default
        text = element.text
        return text.strip() if text else default
    
    def convert_severity_safely(self, severity: str, mapping: Dict[str, str]) -> str:
        """Safely convert severity using mapping"""
        if not severity:
            return "Medium"
        
        severity_lower = severity.lower()
        for key, value in mapping.items():
            if key.lower() in severity_lower:
                return value
        
        return "Medium"
    
    def extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text using regex"""
        import re
        if not text:
            return []
        
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        return re.findall(cve_pattern, text.upper())
    
    def extract_cwe_ids(self, text: str) -> List[str]:
        """Extract CWE IDs from text using regex"""
        import re
        if not text:
            return []
        
        cwe_pattern = r"CWE-(\d+)"
        matches = re.findall(cwe_pattern, text.upper())
        return [f"CWE-{match}" for match in matches]
    
    def clean_html_text(self, html_text: str) -> str:
        """Clean HTML text using html2text"""
        if not html_text:
            return ""
        
        try:
            import html2text
            text_maker = html2text.HTML2Text()
            text_maker.body_width = 0
            return text_maker.handle(html_text).strip()
        except ImportError:
            # Fallback to basic HTML cleaning
            import re
            # Remove HTML tags
            clean_text = re.sub(r'<[^>]+>', '', html_text)
            # Decode HTML entities
            import html
            return html.unescape(clean_text).strip()
    
    def validate_finding_data(self, finding_data: Dict[str, Any]) -> bool:
        """Validate finding data before creating StandardizedFinding"""
        required_fields = ['title', 'severity']
        
        for field in required_fields:
            if field not in finding_data or not finding_data[field]:
                logger.warning("Missing required field '%s' in finding data", field)
                return False
        
        return True
    
    def create_standardized_finding(self, finding_data: Dict[str, Any]) -> Optional[StandardizedFinding]:
        """Create StandardizedFinding with validation"""
        if not self.validate_finding_data(finding_data):
            return None
        
        try:
            finding = StandardizedFinding(**finding_data)
            logger.debug("Created StandardizedFinding: %s", finding.title)
            return finding
        except Exception as e:
            logger.error("Error creating StandardizedFinding: %s", e)
            return None
    
    def extract_standard_metadata_fields(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract standardized metadata fields from raw_data that are common across scanners.
        This ensures consistent extraction of fields like VPR, temporal scores, STIG, exploit frameworks, etc.
        
        Returns a dictionary with standardized field names that can be used by all parsers.
        """
        metadata = {}
        
        # CVSS Temporal Scores - check multiple possible field names
        cvss_v2_temporal = (
            raw_data.get('cvss_v2_temporal') or 
            raw_data.get('cvss_v2_temporal_score') or
            raw_data.get('cvss_temporal_v2') or
            raw_data.get('temporal_score_v2')
        )
        if cvss_v2_temporal:
            try:
                metadata['cvss_v2_temporal'] = float(cvss_v2_temporal)
            except (ValueError, TypeError):
                pass
        
        cvss_v3_temporal = (
            raw_data.get('cvss_v3_temporal') or 
            raw_data.get('cvss_v3_temporal_score') or
            raw_data.get('cvss_temporal_v3') or
            raw_data.get('temporal_score_v3')
        )
        if cvss_v3_temporal:
            try:
                metadata['cvss_v3_temporal'] = float(cvss_v3_temporal)
            except (ValueError, TypeError):
                pass
        
        # VPR Score - check multiple possible field names
        vpr_score = (
            raw_data.get('vpr_score') or 
            raw_data.get('vpr') or
            raw_data.get('tenable_vpr') or
            raw_data.get('vpr_rating')
        )
        if vpr_score:
            try:
                metadata['vpr_score'] = float(vpr_score)
            except (ValueError, TypeError):
                pass
        
        # STIG Severity - check multiple possible field names
        stig_severity = (
            raw_data.get('stig_severity') or 
            raw_data.get('stig') or
            raw_data.get('disa_stig_severity') or
            raw_data.get('stig_rating')
        )
        if stig_severity and str(stig_severity).strip() and str(stig_severity).strip().upper() != 'N/A':
            metadata['stig_severity'] = str(stig_severity).strip()
        
        # Risk Factor - check multiple possible field names
        risk_factor = (
            raw_data.get('risk_factor') or 
            raw_data.get('risk') or
            raw_data.get('risk_level') or
            raw_data.get('risk_rating')
        )
        if risk_factor and str(risk_factor).strip() and str(risk_factor).strip().upper() != 'N/A':
            metadata['risk_factor'] = str(risk_factor).strip()
        
        # Reference IDs - BID, XREF, MSKB
        bid = raw_data.get('bid') or raw_data.get('bugtraq_id') or raw_data.get('bugtraq')
        if bid and str(bid).strip() and str(bid).strip().upper() != 'N/A':
            metadata['bid'] = str(bid).strip()
        
        xref = raw_data.get('xref') or raw_data.get('cross_reference') or raw_data.get('reference_id')
        if xref and str(xref).strip() and str(xref).strip().upper() != 'N/A':
            metadata['xref'] = str(xref).strip()
        
        mskb = raw_data.get('mskb') or raw_data.get('microsoft_kb') or raw_data.get('kb_id')
        if mskb and str(mskb).strip() and str(mskb).strip().upper() != 'N/A':
            metadata['mskb'] = str(mskb).strip()
        
        # Exploit Framework Information
        metasploit = raw_data.get('metasploit') or raw_data.get('metasploit_module') or raw_data.get('msf_module')
        if metasploit and str(metasploit).strip() and str(metasploit).strip().upper() != 'N/A':
            metadata['metasploit'] = str(metasploit).strip()
        
        core_impact = raw_data.get('core_impact') or raw_data.get('coreimpact') or raw_data.get('ci_module')
        if core_impact and str(core_impact).strip() and str(core_impact).strip().upper() != 'N/A':
            metadata['core_impact'] = str(core_impact).strip()
        
        canvas = raw_data.get('canvas') or raw_data.get('canvas_module') or raw_data.get('immunity_canvas')
        if canvas and str(canvas).strip() and str(canvas).strip().upper() != 'N/A':
            metadata['canvas'] = str(canvas).strip()
        
        # EPSS Score - check multiple possible field names
        epss_score = (
            raw_data.get('epss_score') or 
            raw_data.get('epss') or
            raw_data.get('epss_percentile') or
            raw_data.get('exploit_prediction_score')
        )
        if epss_score:
            try:
                epss = float(epss_score)
                # EPSS is typically 0-1, but some sources might report as percentage
                if epss > 1.0:
                    epss = epss / 100.0
                metadata['epss_score'] = epss
            except (ValueError, TypeError):
                pass
        
        # Plugin/Scanner Dates
        plugin_pub_date = raw_data.get('plugin_publication_date') or raw_data.get('publication_date') or raw_data.get('plugin_published')
        if plugin_pub_date and str(plugin_pub_date).strip() and str(plugin_pub_date).strip().upper() != 'N/A':
            metadata['plugin_publication_date'] = str(plugin_pub_date).strip()
        
        plugin_mod_date = raw_data.get('plugin_modification_date') or raw_data.get('modification_date') or raw_data.get('plugin_modified')
        if plugin_mod_date and str(plugin_mod_date).strip() and str(plugin_mod_date).strip().upper() != 'N/A':
            metadata['plugin_modification_date'] = str(plugin_mod_date).strip()
        
        return metadata
    
    def extract_exploit_framework_tags(self, raw_data: Dict[str, Any]) -> List[str]:
        """
        Extract exploit framework tags from raw_data.
        Returns a list of tags like ['metasploit', 'core_impact', 'canvas'] if found.
        """
        tags = []
        
        # Check for Metasploit
        if (raw_data.get('metasploit') or 
            raw_data.get('metasploit_module') or 
            raw_data.get('msf_module')):
            if 'metasploit' not in tags:
                tags.append('metasploit')
        
        # Check for Core Impact
        if (raw_data.get('core_impact') or 
            raw_data.get('coreimpact') or 
            raw_data.get('ci_module')):
            if 'core_impact' not in tags:
                tags.append('core_impact')
        
        # Check for CANVAS
        if (raw_data.get('canvas') or 
            raw_data.get('canvas_module') or 
            raw_data.get('immunity_canvas')):
            if 'canvas' not in tags:
                tags.append('canvas')
        
        return tags