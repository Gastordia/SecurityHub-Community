"""
Trivy / Grype / Snyk container and SCA vulnerability parser for SecurityHub.

Supports:
  - Trivy JSON output  (trivy image/fs/repo --format json)
  - Grype JSON output  (grype --output json)
  - Snyk JSON output   (snyk test --json)

These tools all scan container images and file-system dependencies for known CVEs,
outputting package name + installed version + fixed version alongside CVSS data.
"""

import json
import logging
from typing import List, Dict, Any, Optional

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical":  SeverityLevel.CRITICAL,
    "high":      SeverityLevel.HIGH,
    "medium":    SeverityLevel.MEDIUM,
    "moderate":  SeverityLevel.MEDIUM,
    "low":       SeverityLevel.LOW,
    "negligible":SeverityLevel.INFO,
    "unknown":   SeverityLevel.INFO,
    "info":      SeverityLevel.INFO,
}


class TrivyParser(BaseParser):
    """Parser for Trivy, Grype, and Snyk JSON output"""

    def __init__(self):
        super().__init__()
        self.scanner_type = "trivy"

    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="Trivy / Grype / Snyk",
            version="1.0.0",
            description="Parser for container and SCA vulnerability JSON output (Trivy, Grype, Snyk)",
            supported_formats=["json"],
            author="SecurityHub Team",
            website="https://github.com/aquasecurity/trivy",
        )

    def validate_file(self, file_path: str) -> bool:
        if not str(file_path).lower().endswith(".json"):
            return False
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return (
                self._is_trivy(data)
                or self._is_grype(data)
                or self._is_snyk(data)
            )
        except Exception:
            return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"TrivyParser: failed to load file: {e}")
            return []

        if self._is_trivy(data):
            return self._parse_trivy(data)
        if self._is_grype(data):
            return self._parse_grype(data)
        if self._is_snyk(data):
            return self._parse_snyk(data)

        logger.error("TrivyParser: unrecognised JSON structure")
        return []

    # ── Format detection ──────────────────────────────────────────────────────

    def _is_trivy(self, data: Dict) -> bool:
        return isinstance(data, dict) and "Results" in data and "SchemaVersion" in data

    def _is_grype(self, data: Dict) -> bool:
        return isinstance(data, dict) and "matches" in data and "source" in data

    def _is_snyk(self, data: Dict) -> bool:
        return isinstance(data, dict) and "vulnerabilities" in data and "projectName" in data

    # ── Trivy ─────────────────────────────────────────────────────────────────

    def _parse_trivy(self, data: Dict) -> List[StandardizedFinding]:
        findings: List[StandardizedFinding] = []
        dupes: Dict[str, StandardizedFinding] = {}

        artifact_name = data.get("ArtifactName", "Unknown")
        artifact_type = data.get("ArtifactType", "")

        for result in data.get("Results", []):
            target = result.get("Target", artifact_name)
            result_type = result.get("Type", "")

            for vuln in result.get("Vulnerabilities") or []:
                finding = self._trivy_vuln_to_finding(vuln, target, result_type, artifact_name, artifact_type)
                if finding:
                    key = f"trivy:{finding.scanner_id}:{target}"
                    if key not in dupes:
                        dupes[key] = finding
                        findings.append(finding)

        logger.info(f"TrivyParser: parsed {len(findings)} Trivy findings")
        return findings

    def _trivy_vuln_to_finding(
        self, vuln: Dict, target: str, result_type: str,
        artifact_name: str, artifact_type: str
    ) -> Optional[StandardizedFinding]:
        try:
            vuln_id = vuln.get("VulnerabilityID", "")
            pkg_name = vuln.get("PkgName", "")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion", "")
            severity_raw = (vuln.get("Severity") or "unknown").lower()
            severity = _SEVERITY_MAP.get(severity_raw, SeverityLevel.INFO)

            title = f"{vuln_id} in {pkg_name} {installed_version}" if pkg_name else vuln_id

            description = vuln.get("Description") or vuln.get("Title") or ""
            if vuln.get("Title") and vuln.get("Description"):
                description = f"{vuln['Title']}\n\n{vuln['Description']}"

            solution = ""
            if fixed_version:
                solution = f"Upgrade {pkg_name} from {installed_version} to {fixed_version}."
            elif vuln.get("Status"):
                solution = vuln["Status"]

            # CVSS
            cvss_score = None
            cvss_vector = None
            for cvss_source in (vuln.get("CVSS") or {}).values():
                if isinstance(cvss_source, dict):
                    v3 = cvss_source.get("V3Score") or cvss_source.get("V3")
                    v3_vec = cvss_source.get("V3Vector")
                    v2 = cvss_source.get("V2Score") or cvss_source.get("V2")
                    if v3 is not None:
                        try:
                            cvss_score = float(v3)
                            if v3_vec:
                                cvss_vector = v3_vec
                            break
                        except (ValueError, TypeError):
                            pass
                    if v2 is not None and cvss_score is None:
                        try:
                            cvss_score = float(v2)
                        except (ValueError, TypeError):
                            pass

            cve_ids = [vuln_id] if vuln_id.startswith("CVE-") else []
            cwe_ids = self.extract_cwe_ids(" ".join(vuln.get("CweIDs") or []))

            references = list(vuln.get("References") or [])

            pkg_path = vuln.get("PkgPath") or vuln.get("PkgIdentifier", {}).get("PURL", "")

            finding = StandardizedFinding(
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                solution=solution,
                references=references,
                affected_asset=target,
                scanner_type="trivy",
                scanner_id=vuln_id,
                tags=[result_type] if result_type else [],
                raw_data={
                    "cve_ids": cve_ids,
                    "package_name": pkg_name,
                    "package_version": installed_version,
                    "fixed_version": fixed_version,
                    "pkg_path": pkg_path,
                    "artifact_name": artifact_name,
                    "artifact_type": artifact_type,
                    "result_type": result_type,
                    "severity_source": vuln.get("SeveritySource", ""),
                    "published_date": vuln.get("PublishedDate", ""),
                    "last_modified_date": vuln.get("LastModifiedDate", ""),
                    "data_source": vuln.get("DataSource", {}).get("Name", ""),
                    "affected_endpoints": [{"url": target, "type": "package"}],
                },
            )
            return finding

        except Exception as e:
            logger.error(f"TrivyParser: error parsing trivy vuln: {e}")
            return None

    # ── Grype ─────────────────────────────────────────────────────────────────

    def _parse_grype(self, data: Dict) -> List[StandardizedFinding]:
        findings: List[StandardizedFinding] = []
        dupes: Dict[str, StandardizedFinding] = {}

        source = data.get("source", {})
        target = source.get("target", {})
        image_name = target.get("userInput") or target.get("imageID", "Unknown")

        for match in data.get("matches", []):
            finding = self._grype_match_to_finding(match, image_name)
            if finding:
                key = f"grype:{finding.scanner_id}:{finding.affected_asset}"
                if key not in dupes:
                    dupes[key] = finding
                    findings.append(finding)

        logger.info(f"TrivyParser (Grype): parsed {len(findings)} findings")
        return findings

    def _grype_match_to_finding(self, match: Dict, image_name: str) -> Optional[StandardizedFinding]:
        try:
            vuln = match.get("vulnerability", {})
            vuln_id = vuln.get("id", "")
            severity_raw = (vuln.get("severity") or "unknown").lower()
            severity = _SEVERITY_MAP.get(severity_raw, SeverityLevel.INFO)

            artifact = match.get("artifact", {})
            pkg_name = artifact.get("name", "")
            installed_version = artifact.get("version", "")
            pkg_type = artifact.get("type", "")

            fixed_versions = [
                f.get("version", "") for f in vuln.get("fix", {}).get("versions", [])
            ]
            fixed_version = ", ".join(v for v in fixed_versions if v)

            title = f"{vuln_id} in {pkg_name} {installed_version}" if pkg_name else vuln_id
            description = vuln.get("description") or ""

            solution = ""
            if fixed_version:
                solution = f"Upgrade {pkg_name} from {installed_version} to {fixed_version}."

            cvss_score = None
            cvss_vector = None
            for cvss in vuln.get("cvss", []):
                metrics = cvss.get("metrics", {})
                base = metrics.get("baseScore")
                vec = cvss.get("vector", "")
                if base is not None:
                    try:
                        cvss_score = float(base)
                        if vec:
                            cvss_vector = vec
                        break
                    except (ValueError, TypeError):
                        pass

            cve_ids = [vuln_id] if vuln_id.startswith("CVE-") else []
            related = [r.get("id", "") for r in vuln.get("relatedVulnerabilities", [])]
            cve_ids.extend(v for v in related if v.startswith("CVE-"))

            references = list(vuln.get("urls") or [])

            location = artifact.get("locations", [{}])[0]
            pkg_path = location.get("path", "")

            return StandardizedFinding(
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                solution=solution,
                references=references,
                affected_asset=image_name,
                scanner_type="grype",
                scanner_id=vuln_id,
                tags=[pkg_type] if pkg_type else [],
                raw_data={
                    "cve_ids": list(dict.fromkeys(cve_ids)),
                    "package_name": pkg_name,
                    "package_version": installed_version,
                    "fixed_version": fixed_version,
                    "pkg_path": pkg_path,
                    "pkg_type": pkg_type,
                    "artifact_name": image_name,
                    "affected_endpoints": [{"url": image_name, "type": "package"}],
                },
            )

        except Exception as e:
            logger.error(f"TrivyParser (Grype): error parsing match: {e}")
            return None

    # ── Snyk ──────────────────────────────────────────────────────────────────

    def _parse_snyk(self, data: Dict) -> List[StandardizedFinding]:
        findings: List[StandardizedFinding] = []
        dupes: Dict[str, StandardizedFinding] = {}

        project_name = data.get("projectName", data.get("displayTargetFile", "Unknown"))

        for vuln in data.get("vulnerabilities", []):
            finding = self._snyk_vuln_to_finding(vuln, project_name)
            if finding:
                key = f"snyk:{finding.scanner_id}:{finding.affected_asset}"
                if key not in dupes:
                    dupes[key] = finding
                    findings.append(finding)

        logger.info(f"TrivyParser (Snyk): parsed {len(findings)} findings")
        return findings

    def _snyk_vuln_to_finding(self, vuln: Dict, project_name: str) -> Optional[StandardizedFinding]:
        try:
            vuln_id = vuln.get("id", "")
            title = vuln.get("title", vuln_id)
            severity_raw = (vuln.get("severity") or "unknown").lower()
            severity = _SEVERITY_MAP.get(severity_raw, SeverityLevel.INFO)

            pkg_name = vuln.get("packageName", vuln.get("moduleName", ""))
            installed_version = vuln.get("version", "")
            upgrades = vuln.get("upgradePath", [])
            fixed_version = str(upgrades[-1]) if upgrades else ""

            description = vuln.get("description") or ""
            solution = ""
            if fixed_version and fixed_version.lower() not in ("true", "false", ""):
                solution = f"Upgrade {pkg_name} to {fixed_version}."
            elif vuln.get("fixedIn"):
                solution = f"Fixed in: {', '.join(str(v) for v in vuln['fixedIn'])}."

            cvss_score = vuln.get("cvssScore")
            if cvss_score is not None:
                try:
                    cvss_score = float(cvss_score)
                except (ValueError, TypeError):
                    cvss_score = None
            cvss_vector = vuln.get("CVSSv3") or vuln.get("cvssV3Vector") or None

            identifiers = vuln.get("identifiers", {})
            cve_ids = identifiers.get("CVE", [])
            cwe_ids_raw = identifiers.get("CWE", [])
            cwe_ids = [c if c.upper().startswith("CWE-") else f"CWE-{c}" for c in cwe_ids_raw]

            references = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

            return StandardizedFinding(
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                solution=solution,
                references=references,
                affected_asset=project_name,
                scanner_type="snyk",
                scanner_id=vuln_id,
                tags=list(vuln.get("functions", [])),
                raw_data={
                    "cve_ids": cve_ids,
                    "package_name": pkg_name,
                    "package_version": installed_version,
                    "fixed_version": fixed_version,
                    "pkg_type": vuln.get("language", ""),
                    "artifact_name": project_name,
                    "exploit_maturity": vuln.get("exploit", ""),
                    "affected_endpoints": [{"url": project_name, "type": "package"}],
                },
            )

        except Exception as e:
            logger.error(f"TrivyParser (Snyk): error parsing vuln: {e}")
            return None
