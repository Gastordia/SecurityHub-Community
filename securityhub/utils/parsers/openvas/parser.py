"""
OpenVAS / Greenbone parser for SecurityHub
Parses OpenVAS scan results in CSV or XML format
"""

import csv
import logging
import re
from typing import List, Dict, Any, Optional
from ...xml import parse_xml_safely as parse

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel, StandardizedEndpoint

logger = logging.getLogger(__name__)


class OpenVASParser(BaseParser):
    """Parser for OpenVAS / Greenbone scan results"""

    def __init__(self):
        super().__init__()
        self.scanner_type = "openvas"

    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="OpenVAS",
            version="2.0.0",
            description="Parser for Greenbone OpenVAS scan results in CSV or XML format",
            supported_formats=["csv", "xml"],
            author="SecurityHub Team",
            website="https://www.openvas.org/"
        )

    def validate_file(self, file_path: str) -> bool:
        file_path_str = str(file_path).lower()
        if file_path_str.endswith('.csv'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                return any(h in first_line for h in ['nvt name', 'severity', 'summary', 'ip'])
            except Exception:
                return False
        elif file_path_str.endswith('.xml'):
            try:
                root = parse(file_path).getroot()
                return "report" in root.tag
            except Exception:
                return False
        return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        if str(file_path).lower().endswith('.xml'):
            return self._parse_xml_findings(file_path)
        elif str(file_path).lower().endswith('.csv'):
            return self._parse_csv_findings(file_path)
        logger.error("Filename extension not recognized. Use .xml or .csv")
        return []

    # ── XML ──────────────────────────────────────────────────────────────────

    def _parse_xml_findings(self, file_path: str) -> List[StandardizedFinding]:
        try:
            root = parse(file_path).getroot()
            if "report" not in root.tag:
                logger.error("Not a valid OpenVAS XML file.")
                return []

            findings = []
            dupes: Dict[str, StandardizedFinding] = {}

            for result in root.findall(".//result"):
                finding = self._parse_xml_result(result)
                if finding:
                    dupe_key = f"openvas:{finding.scanner_id}:{finding.affected_asset}"
                    if dupe_key not in dupes:
                        dupes[dupe_key] = finding
                        findings.append(finding)
                    else:
                        existing = dupes[dupe_key]
                        existing.description += f"\n\n--- Additional Instance ---\n\n{finding.description}"

            return findings
        except Exception as e:
            logger.error("Failed to parse OpenVAS XML file: %s", e)
            return []

    def _parse_xml_result(self, result) -> Optional[StandardizedFinding]:
        try:
            # ── NVT info ─────────────────────────────────────────────────────
            nvt = result.find("nvt")
            nvt_oid = nvt.attrib.get("oid", "0") if nvt is not None else "0"
            nvt_name = self._text(nvt, "name") if nvt is not None else "Unknown"
            nvt_family = self._text(nvt, "family") if nvt is not None else ""

            # ── Host / port ───────────────────────────────────────────────────
            host_elem = result.find("host")
            host_ip = host_elem.text.strip() if host_elem is not None and host_elem.text else "Unknown"
            hostname_elem = host_elem.find("hostname") if host_elem is not None else None
            hostname = hostname_elem.text.strip() if hostname_elem is not None and hostname_elem.text else None
            affected_asset = hostname or host_ip

            raw_port = self._text(result, "port") or ""
            port, protocol = self._split_port(raw_port)

            # ── Severity / threat ─────────────────────────────────────────────
            severity_text = self._text(result, "severity") or "0"
            threat_text = self._text(result, "threat") or ""
            severity_level = self._convert_severity(severity_text, threat_text)

            # ── CVSS ──────────────────────────────────────────────────────────
            cvss_score = None
            raw_cvss = self._text(nvt, "cvss_base") if nvt is not None else None
            if raw_cvss:
                try:
                    cvss_score = float(raw_cvss)
                except ValueError:
                    pass

            cvss_vector = self._text(nvt, "cvss_base_vector") if nvt is not None else None

            # Tags string may contain cvss_base_vector and other metadata
            nvt_tags = self._text(nvt, "tags") if nvt is not None else ""
            tag_dict = self._parse_nvt_tags(nvt_tags)

            if not cvss_vector:
                cvss_vector = tag_dict.get("cvss_base_vector")

            solution_type = tag_dict.get("solution_type", "")
            summary = tag_dict.get("summary", "")
            insight = tag_dict.get("insight", "")

            # ── CVE / CWE ─────────────────────────────────────────────────────
            cve_ids = self._extract_cve_list(nvt)
            cwe_ids = self._extract_cwe_list(nvt, tag_dict)

            # ── References ────────────────────────────────────────────────────
            references = self._extract_references(nvt)

            # ── Description / solution ────────────────────────────────────────
            description_raw = self._text(result, "description") or summary or ""
            if insight and insight not in description_raw:
                description_raw = f"{description_raw}\n\nInsight: {insight}".strip()

            solution_raw = self._text(result, "solution") or tag_dict.get("solution", "")
            if solution_type and solution_type.strip().upper() not in ("N/A", "NONE", ""):
                solution_raw = f"[{solution_type}] {solution_raw}".strip() if solution_raw else solution_type

            # ── QoD (quality of detection → confidence) ───────────────────────
            qod_elem = result.find("qod")
            qod_value = None
            qod_type = ""
            if qod_elem is not None:
                qod_val_text = self._text(qod_elem, "value")
                if qod_val_text:
                    try:
                        qod_value = int(qod_val_text) / 100.0
                    except ValueError:
                        pass
                qod_type = self._text(qod_elem, "type") or ""

            # ── Endpoint ──────────────────────────────────────────────────────
            endpoint_url = self._build_url(affected_asset, port, protocol)

            finding = StandardizedFinding(
                title=nvt_name,
                description=description_raw,
                severity=severity_level,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                solution=solution_raw,
                references=references,
                affected_asset=affected_asset,
                scanner_type="openvas",
                scanner_id=nvt_oid,
                raw_data={
                    "nvt_oid": nvt_oid,
                    "nvt_family": nvt_family,
                    "port": port,
                    "protocol": protocol,
                    "host": host_ip,
                    "hostname": hostname,
                    "affected_endpoints": [{"url": endpoint_url, "protocol": protocol, "port": port}],
                    "cve_ids": cve_ids,
                    "solution_type": solution_type,
                    "qod_value": qod_value,
                    "qod_type": qod_type,
                    "confidence_score": qod_value,
                    "threat": threat_text,
                },
            )
            return finding

        except Exception as e:
            logger.error("Error parsing OpenVAS XML result: %s", e)
            return None

    # ── CSV ───────────────────────────────────────────────────────────────────

    def _parse_csv_findings(self, file_path: str) -> List[StandardizedFinding]:
        try:
            findings = []
            dupes: Dict[str, StandardizedFinding] = {}

            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    finding = self._parse_csv_row(row)
                    if finding:
                        dupe_key = f"openvas:{finding.scanner_id}:{finding.affected_asset}"
                        if dupe_key not in dupes:
                            dupes[dupe_key] = finding
                            findings.append(finding)
                        else:
                            dupes[dupe_key].description += (
                                f"\n\n--- Additional Instance ---\n\n{finding.description}"
                            )

            return findings
        except Exception as e:
            raise ValueError(f"Failed to parse OpenVAS CSV file: {e}")

    def _parse_csv_row(self, row: Dict[str, str]) -> Optional[StandardizedFinding]:
        try:
            nvt_name = row.get('nvt name', row.get('Name', 'Unknown'))
            nvt_oid = row.get('nvt oid', row.get('OID', '0'))
            severity_raw = row.get('severity', row.get('CVSS', '0'))
            threat_raw = row.get('threat', row.get('risk', ''))
            host = row.get('ip', row.get('host', 'Unknown'))
            raw_port = row.get('port', '')
            port, protocol = self._split_port(raw_port)

            hostname = row.get('hostname', row.get('dns name', ''))
            affected_asset = hostname.strip() if hostname and hostname.strip() else host

            description = row.get('description', row.get('summary', ''))
            solution = row.get('solution', '')

            cve_text = row.get('cve', row.get('CVEs', ''))
            cve_ids = [c.strip() for c in cve_text.split(',') if c.strip()] if cve_text else []

            cvss_score = None
            if severity_raw:
                try:
                    cvss_score = float(severity_raw)
                except ValueError:
                    pass

            cvss_vector = row.get('cvss vector', row.get('cvss_vector', '')) or None

            # CWE from dedicated column or extract from description
            cwe_raw = row.get('cwe', '')
            cwe_ids = self.extract_cwe_ids(cwe_raw) if cwe_raw else self.extract_cwe_ids(description)

            references = []
            refs_raw = row.get('xrefs', row.get('references', ''))
            if refs_raw:
                for ref in re.split(r'[,\n]', refs_raw):
                    ref = ref.strip()
                    if ref and ref.upper() != 'N/A':
                        references.append(ref)

            severity_level = self._convert_severity(str(cvss_score or 0), threat_raw)

            endpoint_url = self._build_url(affected_asset, port, protocol)

            return StandardizedFinding(
                title=nvt_name,
                description=description,
                severity=severity_level,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                solution=solution,
                references=references,
                affected_asset=affected_asset,
                scanner_type="openvas",
                scanner_id=nvt_oid,
                raw_data={
                    "nvt_oid": nvt_oid,
                    "port": port,
                    "protocol": protocol,
                    "host": host,
                    "hostname": hostname,
                    "affected_endpoints": [{"url": endpoint_url, "protocol": protocol, "port": port}],
                    "cve_ids": cve_ids,
                    "row_data": row,
                },
            )
        except Exception as e:
            logger.error("Error parsing OpenVAS CSV row: %s", e)
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _text(self, element, tag: str) -> Optional[str]:
        if element is None:
            return None
        child = element.find(tag)
        if child is None or not child.text:
            return None
        return child.text.strip() or None

    def _split_port(self, raw: str):
        """Parse '443/tcp' or '80' into (port_str, protocol_str)."""
        if not raw or raw in ("general/tcp", "general/udp", "general"):
            return None, "tcp"
        if "/" in raw:
            parts = raw.split("/", 1)
            port_part = parts[0].strip()
            proto_part = parts[1].strip().lower()
            port = port_part if port_part.isdigit() and port_part != "0" else None
            return port, proto_part
        return (raw.strip() if raw.strip().isdigit() else None), "tcp"

    def _build_url(self, host: str, port: Optional[str], protocol: Optional[str]) -> str:
        proto = protocol or "tcp"
        if proto in ("http", "https", "ftp", "ssh"):
            url = f"{proto}://{host}"
        else:
            url = f"tcp://{host}"
        if port and port != "0":
            url += f":{port}"
        return url

    def _parse_nvt_tags(self, tags_str: Optional[str]) -> Dict[str, str]:
        """Parse OpenVAS pipe-delimited tags string into a dict."""
        result: Dict[str, str] = {}
        if not tags_str:
            return result
        for pair in tags_str.split("|"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                result[k.strip()] = v.strip()
        return result

    def _extract_cve_list(self, nvt) -> List[str]:
        if nvt is None:
            return []
        cve_elem = nvt.find("cve")
        if cve_elem is None or not cve_elem.text:
            return []
        return [c.strip() for c in cve_elem.text.split(',') if c.strip() and c.strip().upper() != 'NOCVE']

    def _extract_cwe_list(self, nvt, tag_dict: Dict[str, str]) -> List[str]:
        cwe_ids: List[str] = []
        # From dedicated element
        if nvt is not None:
            cwe_elem = nvt.find("cwe")
            if cwe_elem is not None and cwe_elem.text:
                cwe_ids.extend(self.extract_cwe_ids(cwe_elem.text))
        # From tags dict
        cwe_tag = tag_dict.get("cwe", "")
        if cwe_tag:
            cwe_ids.extend(self.extract_cwe_ids(cwe_tag))
        return list(dict.fromkeys(cwe_ids))

    def _extract_references(self, nvt) -> List[str]:
        if nvt is None:
            return []
        references: List[str] = []

        xref_elem = nvt.find("xref")
        if xref_elem is not None and xref_elem.text:
            for ref in re.split(r'[,\n]', xref_elem.text):
                ref = ref.strip()
                if ref and ref.upper() not in ('N/A', 'NOXREF'):
                    references.append(ref)

        for cert_ref in nvt.findall(".//cert_ref"):
            cert_type = cert_ref.attrib.get("type", "")
            cert_id = cert_ref.attrib.get("id", "")
            if cert_id:
                label = f"{cert_type}: {cert_id}" if cert_type else cert_id
                references.append(label)

        return list(dict.fromkeys(references))

    def _convert_severity(self, severity: str, threat: str = "") -> SeverityLevel:
        # Text-based threat field takes precedence when numeric score is ambiguous
        threat_lower = threat.strip().lower()
        if threat_lower in ("critical",):
            return SeverityLevel.CRITICAL
        if threat_lower in ("high",):
            return SeverityLevel.HIGH
        if threat_lower in ("medium", "moderate"):
            return SeverityLevel.MEDIUM
        if threat_lower in ("low",):
            return SeverityLevel.LOW
        if threat_lower in ("log", "debug", "false positive"):
            return SeverityLevel.INFO

        # Numeric CVSS fallback
        try:
            val = float(severity)
            if val >= 9.0:
                return SeverityLevel.CRITICAL
            if val >= 7.0:
                return SeverityLevel.HIGH
            if val >= 4.0:
                return SeverityLevel.MEDIUM
            if val >= 1.0:
                return SeverityLevel.LOW
            return SeverityLevel.INFO
        except (ValueError, TypeError):
            return SeverityLevel.INFO
