"""
MappingDrivenParser — interprets a JSON field-mapping config at runtime.
Enables no-code custom parsers registered via the UI.

Config shape:
{
  "scanner_name": "My Scanner",
  "scanner_description": "...",
  "file_format": "json" | "xml" | "csv",
  "supported_extensions": [".json"],
  "root_path": "vulnerabilities",        # dot-path to the findings array
  "field_mappings": {                    # StandardizedFinding field → dot-path in item
    "title": "name",
    "description": "details.description",
    "severity": "risk_level",
    "affected_asset": "target.host",
    "cvss_score": "cvss.base_score",
    "solution": "remediation",
    "evidence": "proof",
    "references": "refs"                 # list field — joined if string
  },
  "severity_mapping": {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info"
  }
}
"""

import csv
import json
import logging
from typing import Any, Dict, List, Optional

from .base import BaseParser
from .models import ParserMetadata, SeverityLevel, StandardizedFinding

logger = logging.getLogger(__name__)

_SEVERITY_FALLBACKS = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "moderate": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
    "informational": SeverityLevel.INFO,
    "none": SeverityLevel.INFO,
}


def _resolve_path(obj: Any, path: str) -> Any:
    """
    Walk a dot-notation path through nested dicts/lists.

    Supports:
      - Simple keys:          "name"
      - Nested keys:          "details.description"
      - Array navigation:     "vulnerabilities[].name"  (takes first element)
      - Mixed:                "data[].items[].title"
      - Double-dot (wizard):  "vulnerabilities[]..name" is normalised automatically

    Returns None if the path cannot be resolved.
    """
    if not path:
        return None

    # Normalise: collapse consecutive dots and strip leading/trailing dots
    import re
    path = re.sub(r'\.{2,}', '.', path).strip('.')

    # Split on dots but keep [] attached to the preceding key
    # e.g. "vulnerabilities[].details.description" → ["vulnerabilities[]", "details", "description"]
    parts = [p for p in path.split('.') if p]

    for part in parts:
        if obj is None:
            return None

        if part.endswith('[]'):
            # Navigate into the key then unwrap the first array element
            key = part[:-2]
            if key:
                if isinstance(obj, dict):
                    obj = obj.get(key)
                else:
                    return None
            if isinstance(obj, list):
                obj = obj[0] if obj else None
            elif obj is None:
                return None
            # if it wasn't a list (schema mismatch), fall through with current obj
        elif isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list):
            if part.isdigit():
                idx = int(part)
                obj = obj[idx] if idx < len(obj) else None
            else:
                # Implicit first-element unwrap for lists mid-path
                obj = obj[0].get(part) if obj and isinstance(obj[0], dict) else None
        else:
            return None

    return obj


def _resolve_xml_path(element, path: str) -> str:
    """Walk a slash-delimited XPath-like path. Returns text or ''."""
    if not path or element is None:
        return ""
    parts = path.split("/")
    current = element
    for part in parts:
        if current is None:
            return ""
        found = current.find(part)
        if found is None:
            # try as attribute
            return current.get(part, "")
        current = found
    if current is None:
        return ""
    return (current.text or "").strip()


class MappingDrivenParser(BaseParser):
    """Parser that operates from a JSON field-mapping config stored in the DB."""

    def __init__(self, scanner_type: str, config: Dict[str, Any]):
        super().__init__()
        self.scanner_type = scanner_type
        self._config = config
        self._fmt = config.get("file_format", "json").lower()
        self._exts = [e.lower() for e in config.get("supported_extensions", [f".{self._fmt}"])]
        self._root_path = config.get("root_path", "")
        self._field_mappings: Dict[str, str] = config.get("field_mappings", {})
        self._severity_mapping: Dict[str, str] = {
            k.upper(): v for k, v in config.get("severity_mapping", {}).items()
        }

    # ------------------------------------------------------------------
    # BaseParser interface
    # ------------------------------------------------------------------

    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name=self._config.get("scanner_name", self.scanner_type),
            version="1.0.0",
            description=self._config.get("scanner_description", "Custom mapping-driven parser"),
            supported_formats=self._exts,
            author=self._config.get("author", "Custom"),
            website=self._config.get("website", ""),
        )

    def validate_file(self, file_path: str) -> bool:
        if not self.validate_file_exists(file_path):
            return False
        if not self.validate_file_extension(file_path, self._exts):
            return False
        if self._fmt == "json":
            return self.safe_parse_json(file_path) is not None
        if self._fmt == "xml":
            return self.safe_parse_xml(file_path) is not None
        if self._fmt == "csv":
            try:
                with open(file_path, newline="", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    next(reader)
                return True
            except Exception:
                return False
        return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        try:
            if self._fmt == "json":
                return self._parse_json(file_path)
            if self._fmt == "xml":
                return self._parse_xml(file_path)
            if self._fmt == "csv":
                return self._parse_csv(file_path)
        except Exception as e:
            logger.error("MappingDrivenParser(%s) failed: %s", self.scanner_type, e)
        return []

    # ------------------------------------------------------------------
    # Format-specific parsers
    # ------------------------------------------------------------------

    def _parse_json(self, file_path: str) -> List[StandardizedFinding]:
        data = self.safe_parse_json(file_path)
        if data is None:
            return []
        items = self._extract_root(data)
        return [f for f in (self._finding_from_dict(item) for item in items) if f]

    def _parse_xml(self, file_path: str) -> List[StandardizedFinding]:
        root = self.safe_parse_xml(file_path)
        if root is None:
            return []
        # root_path selects items relative to root (XPath find)
        if self._root_path:
            items = root.findall(self._root_path.replace(".", "/"))
        else:
            items = list(root)
        return [f for f in (self._finding_from_xml(el) for el in items) if f]

    def _parse_csv(self, file_path: str) -> List[StandardizedFinding]:
        findings = []
        try:
            with open(file_path, newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    finding = self._finding_from_dict(row)
                    if finding:
                        findings.append(finding)
        except Exception as e:
            logger.error("CSV parse error: %s", e)
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_root(self, data: Any) -> List[Any]:
        if not self._root_path:
            return data if isinstance(data, list) else [data]
        items = _resolve_path(data, self._root_path)
        if items is None:
            return []
        return items if isinstance(items, list) else [items]

    def _finding_from_dict(self, item: Dict[str, Any]) -> Optional[StandardizedFinding]:
        fm = self._field_mappings
        title = str(_resolve_path(item, fm.get("title", "title")) or "").strip()
        if not title:
            return None
        description = str(_resolve_path(item, fm.get("description", "description")) or "")
        severity = self._map_severity(str(_resolve_path(item, fm.get("severity", "severity")) or ""))
        affected_asset = str(_resolve_path(item, fm.get("affected_asset", "")) or "").strip() or None
        solution = str(_resolve_path(item, fm.get("solution", "")) or "").strip() or None
        evidence = str(_resolve_path(item, fm.get("evidence", "")) or "").strip() or None

        raw_cvss = _resolve_path(item, fm.get("cvss_score", ""))
        cvss_score: Optional[float] = None
        try:
            if raw_cvss is not None:
                cvss_score = float(raw_cvss)
        except (TypeError, ValueError):
            pass

        refs_raw = _resolve_path(item, fm.get("references", ""))
        references: List[str] = []
        if isinstance(refs_raw, list):
            references = [str(r) for r in refs_raw]
        elif refs_raw:
            references = [str(refs_raw)]

        cve_ids = self.extract_cve_ids(description + " " + title)
        cwe_ids = self.extract_cwe_ids(description + " " + title)

        return StandardizedFinding(
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            affected_asset=affected_asset,
            solution=solution,
            evidence=evidence,
            references=references,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            scanner_type=self.scanner_type,
            scanner_id=str(_resolve_path(item, fm.get("scanner_id", "id")) or ""),
            raw_data=item if isinstance(item, dict) else {},
        )

    def _finding_from_xml(self, element) -> Optional[StandardizedFinding]:
        fm = self._field_mappings
        title = _resolve_xml_path(element, fm.get("title", "title"))
        if not title:
            return None
        description = _resolve_xml_path(element, fm.get("description", "description"))
        severity = self._map_severity(_resolve_xml_path(element, fm.get("severity", "severity")))
        affected_asset = _resolve_xml_path(element, fm.get("affected_asset", "")) or None
        solution = _resolve_xml_path(element, fm.get("solution", "")) or None
        evidence = _resolve_xml_path(element, fm.get("evidence", "")) or None

        raw_cvss = _resolve_xml_path(element, fm.get("cvss_score", ""))
        cvss_score: Optional[float] = None
        try:
            if raw_cvss:
                cvss_score = float(raw_cvss)
        except (TypeError, ValueError):
            pass

        cve_ids = self.extract_cve_ids(description + " " + title)
        cwe_ids = self.extract_cwe_ids(description + " " + title)

        return StandardizedFinding(
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            affected_asset=affected_asset,
            solution=solution,
            evidence=evidence,
            references=[],
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            scanner_type=self.scanner_type,
            scanner_id="",
            raw_data={},
        )

    def _map_severity(self, raw: str) -> SeverityLevel:
        key = raw.strip().upper()
        # Try user-defined mapping first
        if key in self._severity_mapping:
            mapped = self._severity_mapping[key].lower()
            for sv in SeverityLevel:
                if sv.value.lower() == mapped:
                    return sv
        # Fallback to generic keywords
        for kw, sv in _SEVERITY_FALLBACKS.items():
            if kw in raw.lower():
                return sv
        return SeverityLevel.MEDIUM
