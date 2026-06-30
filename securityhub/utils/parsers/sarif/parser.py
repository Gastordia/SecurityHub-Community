"""
SARIF (Static Analysis Results Interchange Format) parser for SecurityHub.

Supports SARIF 2.1.0 output from:
  GitHub Advanced Security, CodeQL, Semgrep, Bandit, ESLint security,
  Checkov, Trivy SARIF mode, Snyk Code, and any other SARIF-compliant tool.
"""

import json
import logging
import re
from typing import List, Dict, Any, Optional

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel

logger = logging.getLogger(__name__)

# SARIF level → severity
_LEVEL_MAP = {
    "error":   SeverityLevel.HIGH,
    "warning": SeverityLevel.MEDIUM,
    "note":    SeverityLevel.LOW,
    "none":    SeverityLevel.INFO,
}

# Some tools embed their own severity in properties.severity
_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high":     SeverityLevel.HIGH,
    "medium":   SeverityLevel.MEDIUM,
    "moderate": SeverityLevel.MEDIUM,
    "low":      SeverityLevel.LOW,
    "info":     SeverityLevel.INFO,
    "note":     SeverityLevel.INFO,
    "warning":  SeverityLevel.MEDIUM,
    "error":    SeverityLevel.HIGH,
}


class SARIFParser(BaseParser):
    """Parser for SARIF 2.1.0 static analysis output"""

    def __init__(self):
        super().__init__()
        self.scanner_type = "sarif"

    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="SARIF",
            version="1.0.0",
            description=(
                "Parser for SARIF 2.1.0 output (GitHub Advanced Security, CodeQL, "
                "Semgrep, Bandit, ESLint, Checkov, Snyk Code, etc.)"
            ),
            supported_formats=["json", "sarif"],
            author="SecurityHub Team",
            website="https://sarifweb.azurewebsites.net/",
        )

    def validate_file(self, file_path: str) -> bool:
        path_lower = str(file_path).lower()
        if not (path_lower.endswith(".json") or path_lower.endswith(".sarif")):
            return False
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return (
                isinstance(data, dict)
                and data.get("version", "").startswith("2.")
                and "runs" in data
            )
        except Exception:
            return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                sarif = json.load(f)
        except Exception as e:
            logger.error("SARIFParser: failed to load file: %s", e)
            return []

        findings: List[StandardizedFinding] = []
        dupes: Dict[str, StandardizedFinding] = {}

        for run in sarif.get("runs", []):
            tool_name = self._tool_name(run)
            rules = self._index_rules(run)

            for result in run.get("results", []):
                finding = self._parse_result(result, rules, tool_name)
                if finding:
                    key = f"sarif:{finding.scanner_id}:{finding.affected_asset}"
                    if key not in dupes:
                        dupes[key] = finding
                        findings.append(finding)
                    else:
                        dupes[key].description += (
                            f"\n\n--- Additional Location ---\n\n{finding.description}"
                        )

        logger.info("SARIFParser: parsed %s findings", len(findings))
        return findings

    # ── Internal ──────────────────────────────────────────────────────────────

    def _tool_name(self, run: Dict) -> str:
        try:
            return run["tool"]["driver"]["name"]
        except (KeyError, TypeError):
            return "Unknown SAST Tool"

    def _index_rules(self, run: Dict) -> Dict[str, Dict]:
        """Build a rule-id → rule-object index from tool.driver.rules."""
        rules: Dict[str, Dict] = {}
        try:
            for rule in run["tool"]["driver"].get("rules", []):
                rid = rule.get("id", "")
                if rid:
                    rules[rid] = rule
        except (KeyError, TypeError):
            pass
        return rules

    def _parse_result(
        self, result: Dict, rules: Dict[str, Dict], tool_name: str
    ) -> Optional[StandardizedFinding]:
        try:
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            # ── Title ─────────────────────────────────────────────────────────
            title = (
                self._msg_text(result.get("message"))
                or self._rule_name(rule)
                or rule_id
                or "Unknown Finding"
            )
            # Prefer rule short description as title when the message is long
            rule_short = self._rule_name(rule)
            if rule_short and len(title) > 120:
                title = rule_short

            # ── Description ───────────────────────────────────────────────────
            full_desc = self._rule_full_desc(rule) or self._msg_text(result.get("message")) or ""
            help_text = self._rule_help(rule)
            if help_text and help_text not in full_desc:
                full_desc = f"{full_desc}\n\n{help_text}".strip()

            # ── Severity ──────────────────────────────────────────────────────
            severity = self._parse_severity(result, rule)

            # ── Location (affected asset / evidence) ──────────────────────────
            locations = result.get("locations", [])
            primary_location = locations[0] if locations else {}
            artifact_uri, region = self._extract_location(primary_location)

            evidence = self._build_evidence(primary_location, region)

            # Collect all affected URIs as endpoints
            affected_endpoints = []
            for loc in locations:
                uri, _ = self._extract_location(loc)
                if uri:
                    affected_endpoints.append({"url": uri, "type": "source_file"})

            # ── CVSS / CWE / CVE ─────────────────────────────────────────────
            props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
            cvss_score, cvss_vector = self._extract_cvss(props)
            cwe_ids = self._extract_cwe(rule, props)
            cve_ids = self._extract_cve(props, full_desc)

            # ── References ────────────────────────────────────────────────────
            references = self._extract_references(rule)

            # ── Tags ──────────────────────────────────────────────────────────
            tags = list(props.get("tags", []) or [])
            if tool_name and tool_name.lower() not in [t.lower() for t in tags]:
                tags.insert(0, tool_name.lower().replace(" ", "-"))

            # ── Solution ──────────────────────────────────────────────────────
            solution = self._rule_help(rule) or ""

            finding = StandardizedFinding(
                title=title,
                description=full_desc,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_ids=cwe_ids,
                evidence=evidence,
                solution=solution,
                references=references,
                affected_asset=artifact_uri or "",
                scanner_type="sarif",
                scanner_id=rule_id or title,
                tags=tags,
                raw_data={
                    "rule_id": rule_id,
                    "tool_name": tool_name,
                    "affected_endpoints": affected_endpoints,
                    "cve_ids": cve_ids,
                    "region": region,
                    "level": result.get("level", ""),
                    "fingerprints": result.get("fingerprints", {}),
                    "properties": props,
                },
            )
            return finding

        except Exception as e:
            logger.error("SARIFParser: error parsing result: %s", e)
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _msg_text(self, msg: Optional[Dict]) -> str:
        if not msg:
            return ""
        return (msg.get("text") or msg.get("markdown") or "").strip()

    def _rule_name(self, rule: Dict) -> str:
        name_obj = rule.get("shortDescription") or rule.get("name") or {}
        if isinstance(name_obj, dict):
            return (name_obj.get("text") or "").strip()
        return str(name_obj).strip()

    def _rule_full_desc(self, rule: Dict) -> str:
        desc = rule.get("fullDescription") or rule.get("shortDescription") or {}
        if isinstance(desc, dict):
            return (desc.get("text") or desc.get("markdown") or "").strip()
        return ""

    def _rule_help(self, rule: Dict) -> str:
        help_obj = rule.get("help") or {}
        if isinstance(help_obj, dict):
            return (help_obj.get("text") or help_obj.get("markdown") or "").strip()
        return ""

    def _parse_severity(self, result: Dict, rule: Dict) -> SeverityLevel:
        # 1. Tool-level severity in rule properties
        for obj in (result.get("properties") or {}, rule.get("properties") or {}):
            for key in ("security-severity", "severity", "risk", "level"):
                val = obj.get(key)
                if val:
                    # security-severity is often a CVSS-like float string
                    try:
                        score = float(val)
                        return self._cvss_to_severity(score)
                    except (ValueError, TypeError):
                        mapped = _SEVERITY_MAP.get(str(val).lower())
                        if mapped:
                            return mapped

        # 2. SARIF result level
        level = (result.get("level") or "warning").lower()
        return _LEVEL_MAP.get(level, SeverityLevel.MEDIUM)

    def _cvss_to_severity(self, score: float) -> SeverityLevel:
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        if score >= 7.0:
            return SeverityLevel.HIGH
        if score >= 4.0:
            return SeverityLevel.MEDIUM
        if score > 0.0:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    def _extract_location(self, location: Dict):
        """Return (uri, region_dict) from a SARIF location object."""
        try:
            ploc = location.get("physicalLocation", {})
            uri = (ploc.get("artifactLocation") or {}).get("uri", "")
            region = ploc.get("region", {})
            return uri, region
        except Exception:
            return "", {}

    def _build_evidence(self, location: Dict, region: Dict) -> str:
        parts = []
        uri, _ = self._extract_location(location)
        if uri:
            start_line = region.get("startLine", "")
            end_line = region.get("endLine", "")
            col = region.get("startColumn", "")
            loc_str = uri
            if start_line:
                loc_str += f":{start_line}"
                if col:
                    loc_str += f":{col}"
                if end_line and end_line != start_line:
                    loc_str += f"-{end_line}"
            parts.append(f"Location: {loc_str}")

        snippet = (region.get("snippet") or {}).get("text", "")
        if snippet:
            parts.append(f"Snippet:\n```\n{snippet.strip()}\n```")

        # Logical location (function/class name)
        for ll in location.get("logicalLocations", []):
            fqn = ll.get("fullyQualifiedName") or ll.get("name", "")
            kind = ll.get("kind", "")
            if fqn:
                label = f"{kind}: {fqn}" if kind else fqn
                parts.append(f"In: {label}")
                break

        return "\n".join(parts)

    def _extract_cvss(self, props: Dict):
        cvss_score = None
        cvss_vector = None
        for key in ("cvssScore", "cvss_score", "security-severity", "CVSS"):
            val = props.get(key)
            if val is not None:
                try:
                    cvss_score = float(val)
                    break
                except (ValueError, TypeError):
                    pass
        for key in ("cvssVector", "cvss_vector", "cvss-vector"):
            val = props.get(key)
            if val:
                cvss_vector = str(val)
                break
        return cvss_score, cvss_vector

    def _extract_cwe(self, rule: Dict, props: Dict) -> List[str]:
        cwe_ids: List[str] = []
        # From rule properties tags like "CWE-79"
        for source in (props, rule.get("properties") or {}):
            for tag in source.get("tags", []) or []:
                if re.match(r"CWE-\d+", str(tag), re.IGNORECASE):
                    cwe_ids.append(tag.upper())
            for key in ("cwe", "cweId", "cwe_id", "CWE"):
                val = source.get(key)
                if val:
                    cwe_ids.extend(self.extract_cwe_ids(str(val)))
        return list(dict.fromkeys(cwe_ids))

    def _extract_cve(self, props: Dict, text: str) -> List[str]:
        cve_ids: List[str] = []
        for key in ("cve", "cveId", "cve_id", "CVE"):
            val = props.get(key)
            if val:
                cve_ids.extend(self.extract_cve_ids(str(val)))
        cve_ids.extend(self.extract_cve_ids(text))
        return list(dict.fromkeys(cve_ids))

    def _extract_references(self, rule: Dict) -> List[str]:
        refs: List[str] = []
        for rel in rule.get("helpUri", []) if isinstance(rule.get("helpUri"), list) else ([rule.get("helpUri")] if rule.get("helpUri") else []):
            refs.append(str(rel))
        for rel in rule.get("relationships", []) or []:
            url = (rel.get("target") or {}).get("id", "")
            if url and url.startswith("http"):
                refs.append(url)
        return list(dict.fromkeys(refs))
