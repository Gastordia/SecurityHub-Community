"""
Standardized data models for vulnerability parsing
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class SeverityLevel(Enum):
    """Standardized severity levels across all scanners"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class StandardizedFinding:
    """Standardized vulnerability finding across all scanners"""
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    affected_asset: Optional[str] = None
    evidence: Optional[str] = None
    solution: Optional[str] = None
    references: List[str] = field(default_factory=list)
    scanner_type: str = ""
    scanner_id: str = ""
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Ensure lists are properly initialized"""
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.references is None:
            self.references = []
        if self.tags is None:
            self.tags = []
        if self.raw_data is None:
            self.raw_data = {}


@dataclass
class ParserMetadata:
    """Metadata for parser information"""
    name: str
    version: str
    description: str
    supported_formats: List[str]
    author: str = ""
    website: str = ""
    
    def __post_init__(self):
        """Ensure lists are properly initialized"""
        if self.supported_formats is None:
            self.supported_formats = []


@dataclass
class StandardizedEndpoint:
    """Standardized endpoint information"""
    url: str
    method: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    parameters: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Ensure dicts are properly initialized"""
        if self.parameters is None:
            self.parameters = {}


@dataclass
class ScanMetadata:
    """Metadata about the scan itself"""
    scanner_name: str
    scanner_version: str
    scan_date: Optional[str] = None
    scan_duration: Optional[int] = None
    target_count: Optional[int] = None
    finding_count: Optional[int] = None
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Ensure dicts are properly initialized"""
        if self.raw_metadata is None:
            self.raw_metadata = {}
