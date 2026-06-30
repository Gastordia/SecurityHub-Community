"""
OWASP ZAP parser for SecurityHub
Parses OWASP ZAP XML scan results
"""

import logging
import re
from typing import List, Dict, Any, Optional
from ...xml import parse_xml_safely as parse

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel, StandardizedEndpoint

logger = logging.getLogger(__name__)

# ZAP risk codes: 0=Info, 1=Low, 2=Medium, 3=High
# ZAP has no Critical level — High is the maximum
_RISK_TO_SEVERITY = {
    "0": SeverityLevel.INFO,
    "1": SeverityLevel.LOW,
    "2": SeverityLevel.MEDIUM,
    "3": SeverityLevel.HIGH,
}

# ZAP confidence codes: 0=False Positive, 1=Low, 2=Medium, 3=High, 4=Confirmed
# Map to a 0-1 float
_CONFIDENCE_MAP = {
    "0": 0.0,
    "1": 0.25,
    "2": 0.50,
    "3": 0.75,
    "4": 1.0,
}


class ZAPParser(BaseParser):
    """Parser for OWASP ZAP XML scan results"""

    def __init__(self):
        super().__init__()
        self.scanner_type = "zap"

    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="OWASP ZAP",
            version="2.0.0",
            description="Parser for OWASP ZAP XML scan results",
            supported_formats=["xml"],
            author="SecurityHub Team",
            website="https://www.zaproxy.org/"
        )

    def validate_file(self, file_path: str) -> bool:
        if not str(file_path).lower().endswith('.xml'):
            return False
        try:
            root = parse(file_path).getroot()
            is_zap = (
                root.tag == "OWASPZAPReport"
                or root.tag == "report"
                or any(child.tag == "site" for child in root)
                or "zap" in root.tag.lower()
                or "zaproxy" in root.tag.lower()
            )
            if is_zap or root.tag in ("report", "xml"):
                xml_content = root.tag + " ".join(e.tag for e in root.iter())
                zap_indicators = ["alertitem", "site", "alerts", "instances", "OWASPZAPReport", "zaproxy"]
                if any(i in xml_content.lower() for i in zap_indicators):
                    return True
            return False
        except Exception:
            return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        try:
            tree = parse(file_path)
            return self._parse_items(tree)
        except Exception as e:
            logger.error("Failed to parse ZAP file: %s", e)
            return []

    def _parse_items(self, tree) -> List[StandardizedFinding]:
        items: List[StandardizedFinding] = []
        dupes: Dict[str, StandardizedFinding] = {}

        for node in tree.findall("site"):
            for item in node.findall("alerts/alertitem"):
                finding = self._parse_alert(item)
                if finding:
                    dupe_key = f"zap:{finding.scanner_id}"
                    if dupe_key not in dupes:
                        dupes[dupe_key] = finding
                        items.append(finding)
                    else:
                        dupes[dupe_key].description += (
                            f"\n\n--- Additional Instance ---\n\n{finding.description}"
                        )

        return items

    def _parse_alert(self, item) -> Optional[StandardizedFinding]:
        try:
            alert_text = self._text(item, "alert") or self._text(item, "name") or "Unknown Alert"
            plugin_id = self._text(item, "pluginid") or "0"
            risk_code = self._text(item, "riskcode") or "1"
            severity_level = _RISK_TO_SEVERITY.get(risk_code, SeverityLevel.MEDIUM)

            # Confidence — prefer the dedicated confidencecode element, fall back to confidence
            confidence_code = (
                self._text(item, "confidencecode")
                or self._text(item, "confidence")
            )
            scanner_confidence = _CONFIDENCE_MAP.get(confidence_code or "", None)

            description = self._clean_html(self._text(item, "desc") or "")
            solution = self._clean_html(self._text(item, "solution") or "")
            other_info = self._clean_html(self._text(item, "otherinfo") or "")

            if other_info:
                description = f"{description}\n\nAdditional Info: {other_info}".strip()

            # References — split on newlines/spaces
            references: List[str] = []
            ref_raw = self._clean_html(self._text(item, "reference") or "")
            if ref_raw:
                for ref in re.split(r'[\n\r]+', ref_raw):
                    ref = ref.strip()
                    if ref:
                        references.append(ref)

            # CWE
            cwe_ids: List[str] = []
            cwe_text = self._text(item, "cweid") or ""
            if cwe_text and cwe_text.isdigit():
                cwe_ids = [f"CWE-{cwe_text}"]

            # WASC ID
            wasc_id = self._text(item, "wascid") or ""

            # CVE IDs from description / other-info / references
            search_text = " ".join(filter(None, [description, other_info, ref_raw]))
            cve_ids = list(dict.fromkeys(self.extract_cve_ids(search_text)))

            # Instances — collect all affected URIs with method/param/evidence
            instances: List[Dict[str, str]] = []
            affected_urls: List[str] = []
            for inst in item.findall("instances/instance"):
                uri = self._text(inst, "uri") or ""
                method = self._text(inst, "method") or ""
                param = self._text(inst, "param") or ""
                attack = self._text(inst, "attack") or ""
                evidence = self._clean_html(self._text(inst, "evidence") or "")
                inst_other = self._clean_html(self._text(inst, "otherinfo") or "")
                if uri:
                    affected_urls.append(uri)
                instances.append({
                    "uri": uri,
                    "method": method,
                    "param": param,
                    "attack": attack,
                    "evidence": evidence,
                    "otherinfo": inst_other,
                })

            # Derive primary affected asset from first instance URL
            primary_url = affected_urls[0] if affected_urls else ""

            # Build evidence string from first instance if available
            evidence_str = None
            if instances:
                first = instances[0]
                parts = []
                if first.get("evidence"):
                    parts.append(f"Evidence: {first['evidence']}")
                if first.get("param"):
                    parts.append(f"Parameter: {first['param']}")
                if first.get("attack"):
                    parts.append(f"Attack: {first['attack']}")
                if parts:
                    evidence_str = "\n".join(parts)

            # Affected endpoints list
            affected_endpoints = [
                {"url": u, "protocol": u.split("://")[0] if "://" in u else "http"}
                for u in affected_urls
            ]

            finding = StandardizedFinding(
                title=alert_text,
                description=description,
                severity=severity_level,
                evidence=evidence_str,
                solution=solution,
                references=references,
                cwe_ids=cwe_ids,
                affected_asset=primary_url,
                scanner_type="zap",
                scanner_id=plugin_id,
                raw_data={
                    "risk_code": risk_code,
                    "confidence_code": confidence_code,
                    "confidence_score": scanner_confidence,
                    "affected_assets": affected_urls,
                    "affected_endpoints": affected_endpoints,
                    "plugin_id": plugin_id,
                    "wasc_id": wasc_id,
                    "cve_ids": cve_ids,
                    "instances": instances,
                    "otherinfo": other_info,
                },
            )
            return finding

        except Exception as e:
            logger.error("Error creating ZAP finding: %s", e)
            return None

    def _text(self, element, tag: str) -> Optional[str]:
        child = element.find(tag)
        if child is None or not child.text:
            return None
        return child.text.strip() or None

    def _clean_html(self, html_text: str) -> str:
        if not html_text:
            return ""
        clean = re.sub(r'<[^>]+>', '', html_text)
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean
