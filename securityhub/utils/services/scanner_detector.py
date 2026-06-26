"""
Scanner Auto-Detection Service
Automatically detects scanner type from uploaded files
"""

import os
import magic
from typing import Optional, Dict, List
from ..parsers.registry import ParserRegistry


class ScannerDetector:
    """Service for automatically detecting scanner type from files"""
    
    def __init__(self):
        """Initialize the scanner detector"""
        self.parser_registry = ParserRegistry()
    
    def detect_scanner(self, file_path: str) -> Optional[str]:
        """
        Detect scanner type from file
        
        Args:
            file_path: Path to the uploaded file
            
        Returns:
            Scanner type string or None if not detected
        """
        if not os.path.exists(file_path):
            return None
        
        # Get file extension
        file_extension = os.path.splitext(file_path)[1].lower()
        
        # Get file mime type
        try:
            mime_type = magic.from_file(file_path, mime=True)
        except Exception:
            mime_type = None
        
        # Try to detect by file extension and content
        detected_scanner = self._detect_by_extension_and_content(file_path, file_extension, mime_type)
        
        if detected_scanner:
            return detected_scanner
        
        # Fallback: try all parsers
        return self._detect_by_parser_validation(file_path)
    
    def _detect_by_extension_and_content(self, file_path: str, extension: str, mime_type: Optional[str]) -> Optional[str]:
        """Detect scanner by file extension and content analysis"""
        
        # Extension-based detection
        extension_mapping = {
            '.xml': ['nmap', 'nessus', 'openvas', 'burp', 'zap', 'acunetix', 'nexpose'],
            '.json': ['nuclei', 'acunetix', 'appspider'],
            '.csv': ['nessus', 'openvas'],
            '.nessus': ['nessus']
        }
        
        candidates = extension_mapping.get(extension, [])
        
        # Content-based detection
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)  # Read first 1KB
                
                # Content signatures
                content_signatures = {
                    'nmap': ['<nmaprun', 'nmap'],
                    'nessus': ['<NessusClientData_v2', 'Nessus'],
                    'openvas': ['<report>', 'OpenVAS'],
                    'burp': ['<issues>', 'Burp'],
                    'zap': ['<OWASPZAPReport', 'ZAP'],
                    'nuclei': ['"templateID"', '"template"'],
                    'acunetix': ['<Scan>', 'Acunetix'],
                    'nexpose': ['<NexposeReport', 'Nexpose'],
                    'appspider': ['AppSpider', 'Rapid7']
                }
                
                for scanner, signatures in content_signatures.items():
                    if any(sig in content for sig in signatures):
                        if scanner in candidates:
                            return scanner
                        candidates.append(scanner)
                        
        except Exception:
            pass
        
        # Try the first candidate that validates
        for scanner in candidates:
            if self.parser_registry.validate_file(scanner, file_path):
                return scanner
        
        return None
    
    def _detect_by_parser_validation(self, file_path: str) -> Optional[str]:
        """Detect scanner by trying all parser validations"""
        for scanner_type in self.parser_registry.list_parsers():
            try:
                if self.parser_registry.validate_file(scanner_type, file_path):
                    return scanner_type
            except Exception:
                continue
        
        return None
    
    def get_supported_scanners(self) -> Dict[str, Dict]:
        """Get all supported scanners with their metadata"""
        scanners = {}
        for scanner_type in self.parser_registry.list_parsers():
            metadata = self.parser_registry.get_metadata(scanner_type)
            if metadata:
                scanners[scanner_type] = {
                    'name': metadata.name,
                    'version': metadata.version,
                    'description': metadata.description,
                    'supported_formats': metadata.supported_formats,
                    'author': metadata.author,
                    'website': metadata.website
                }
        return scanners
    
    def get_scanner_info(self, scanner_type: str) -> Optional[Dict]:
        """Get information about a specific scanner"""
        metadata = self.parser_registry.get_metadata(scanner_type)
        if metadata:
            return {
                'name': metadata.name,
                'version': metadata.version,
                'description': metadata.description,
                'supported_formats': metadata.supported_formats,
                'author': metadata.author,
                'website': metadata.website
            }
        return None
    
    def validate_file_for_scanner(self, file_path: str, scanner_type: str) -> bool:
        """Validate if a file is compatible with a specific scanner"""
        return self.parser_registry.validate_file(scanner_type, file_path)
    
    def get_supported_formats(self, scanner_type: str) -> List[str]:
        """Get supported file formats for a scanner"""
        return self.parser_registry.get_supported_formats(scanner_type)


