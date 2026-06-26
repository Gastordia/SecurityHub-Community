"""
Nexpose parser for SecurityHub
Parses Nexpose XML 2.0 scan results
Comprehensive implementation based on Nexpose reference parsers
"""

import logging
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from ...xml import parse_xml_safely as parse
from hyperlink._url import SCHEME_PORT_MAP
import html2text

from ..base import BaseParser
from ..models import StandardizedFinding, ParserMetadata, SeverityLevel, StandardizedEndpoint

logger = logging.getLogger(__name__)

USE_FIRST_SEEN = False  # Set to True if you want to use the first seen date logic

class NexposeParser(BaseParser):
    """Comprehensive parser for Nexpose XML 2.0 scan results"""
    
    def __init__(self):
        super().__init__()
        self.scanner_type = "nexpose"
    
    def get_metadata(self) -> ParserMetadata:
        return ParserMetadata(
            name="Nexpose",
            version="2.0.0",
            description="Comprehensive parser for Nexpose XML 2.0 scan results",
            supported_formats=["xml"],
            author="SecurityHub Team",
            website="https://www.rapid7.com/products/nexpose/"
        )

    def validate_file(self, file_path: str) -> bool:
        """Validate if file is a valid Nexpose XML report"""
        logger.debug(f"🔍 NexposeParser: Validating file: {file_path}")
        
        if not str(file_path).lower().endswith('.xml'):
            logger.debug(f"🔍 NexposeParser: Invalid file extension")
            return False
        
        try:
            tree = parse(file_path)
            root = tree.getroot()
            logger.debug(f"🔍 NexposeParser: Root tag: {root.tag}")
            
            # Check for Nexpose XML structure
            is_valid = (root.tag == "NexposeReport" or 
                       any(child.tag in ["VulnerabilityDefinitions", "nodes"] for child in root))
            logger.debug(f"🔍 NexposeParser: Validation result: {is_valid}")
            return is_valid
        except Exception as e:
            logger.error(f"💥 NexposeParser: Validation error: {str(e)}")
            return False

    def parse_findings(self, file_path: str) -> List[StandardizedFinding]:
        """Parse Nexpose XML file and return standardized findings"""
        logger.info(f"🔍 NexposeParser: Starting to parse findings from {file_path}")
        
        try:
            tree = parse(file_path)
            vuln_definitions = self._get_vuln_definitions(tree)
            findings = self._get_standardized_items(tree, vuln_definitions)
            logger.info(f"✅ NexposeParser: Successfully parsed {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"💥 NexposeParser: Failed to parse Nexpose file: {str(e)}")
            return []

    def _get_vuln_definitions(self, tree) -> Dict[str, Dict]:
        """Get comprehensive vulnerability definitions from XML"""
        vulns = {}
        url_index = 0
        
        for vulnsDef in tree.findall("VulnerabilityDefinitions"):
            for vulnDef in vulnsDef.findall("vulnerability"):
                vid = vulnDef.get("id").lower()
                severity_chk = int(vulnDef.get("severity", 0))
                
                # Convert severity
                if severity_chk >= 9:
                    sev = "Critical"
                elif severity_chk >= 7:
                    sev = "High"
                elif severity_chk >= 4:
                    sev = "Medium"
                elif 0 < severity_chk < 4:
                    sev = "Low"
                else:
                    sev = "Info"
                
                vuln = {
                    "desc": "",
                    "name": vulnDef.get("title"),
                    "vector": vulnDef.get("cvssVector"),  # this is CVSS v2
                    "refs": {},
                    "resolution": "",
                    "severity": sev,
                    "tags": [],
                }
                
                for item in list(vulnDef):
                    if item.tag == "description":
                        for htmlType in list(item):
                            vuln["desc"] += self._parse_html_type(htmlType)

                    elif item.tag == "exploits":
                        for exploit in list(item):
                            vuln["refs"][exploit.get("title")] = (
                                str(exploit.get("title")).strip()
                                + " "
                                + str(exploit.get("link")).strip()
                            )

                    elif item.tag == "references":
                        for ref in list(item):
                            if "URL" in ref.get("source"):
                                vuln["refs"][
                                    ref.get("source") + str(url_index)
                                ] = str(ref.text).strip()
                                url_index += 1
                            else:
                                vuln["refs"][ref.get("source")] = str(
                                    ref.text,
                                ).strip()

                    elif item.tag == "solution":
                        for htmlType in list(item):
                            vuln["resolution"] += self._parse_html_type(htmlType)

                    elif item.tag == "tags":
                        for tag in list(item):
                            vuln["tags"].append(tag.text.lower())

                vulns[vid] = vuln
        
        logger.debug(f"🔍 NexposeParser: Found {len(vulns)} vulnerability definitions")
        return vulns

    def _parse_html_type(self, node):
        """
        Parse XML element of type HtmlType

        @return ret A string containing the parsed element
        """
        ret = ""
        tag = node.tag.lower()

        if tag == "containerblockelement":
            if len(list(node)) > 0:
                for child in list(node):
                    ret += self._parse_html_type(child)
            else:
                if node.text:
                    ret += "<div>" + str(node.text).strip()
                if node.tail:
                    ret += str(node.tail).strip() + "</div>"
                else:
                    ret += "</div>"
        if tag == "listitem":
            if len(list(node)) > 0:
                for child in list(node):
                    ret += self._parse_html_type(child)
            else:
                if node.text:
                    ret += "<li>" + str(node.text).strip() + "</li>"
        if tag == "orderedlist":
            i = 1
            for item in list(node):
                ret += (
                    "<ol>"
                    + str(i)
                    + " "
                    + self._parse_html_type(item)
                    + "</ol>"
                )
                i += 1
        if tag == "paragraph":
            if len(list(node)) > 0:
                for child in list(node):
                    ret += self._parse_html_type(child)
            else:
                if node.text:
                    ret += "<p>" + node.text.strip()
                if node.tail:
                    ret += str(node.tail).strip() + "</p>"
                else:
                    ret += "</p>"
        if tag == "unorderedlist":
            for item in list(node):
                unorderedlist = self._parse_html_type(item)
                if unorderedlist not in ret:
                    ret += "* " + unorderedlist
        if tag == "urllink":
            if node.text:
                ret += str(node.text).strip() + " "
            last = ""

            for attr in node.attrib:
                if last != "":
                    if node.get(attr) != node.get(last):
                        ret += str(node.get(attr)) + " "
                last = attr

        return ret

    def _parse_tests_type(self, node, vulns_definitions):
        """
        Parse XML element of type TestsType

        @return vulns A list of vulnerabilities according to vulns_definitions
        """
        vulns = []

        for tests in node.findall("tests"):
            for test in tests.findall("test"):
                if test.get("id") in vulns_definitions and (
                    test.get("status")
                    in [
                        "vulnerable-exploited",
                        "vulnerable-version",
                        "vulnerable-potential",
                    ]
                ):
                    vuln = vulns_definitions[test.get("id").lower()].copy()
                    for desc in list(test):
                        if "pluginOutput" in vuln:
                            vuln[
                                "pluginOutput"
                            ] += "\n\n" + self._parse_html_type(desc)
                        else:
                            vuln["pluginOutput"] = self._parse_html_type(desc)
                    
                    if USE_FIRST_SEEN and (date := test.get("vulnerable-since")):
                        date = datetime.fromisoformat(date)
                        # It would be nice to be able to define it per Endpoint_Status but for now, we use the oldest known information
                        if not vuln.get("vulnerableSince") or (date < vuln["vulnerableSince"]):
                            vuln["vulnerableSince"] = date
                        else:
                            vuln["vulnerableSince"] = None
                    else:
                        vuln["vulnerableSince"] = None
                    vulns.append(vuln)

        return vulns

    def _get_standardized_items(self, tree, vulns) -> List[StandardizedFinding]:
        """Get standardized findings from Nexpose XML"""
        hosts = []
        
        for nodes in tree.findall("nodes"):
            for node in nodes.findall("node"):
                host = {}
                host["name"] = node.get("address")
                host["hostnames"] = set()
                host["os"] = ""
                host["services"] = []
                host["vulns"] = self._parse_tests_type(node, vulns)

                # Add host up finding
                host["vulns"].append(
                    {
                        "name": "Host Up",
                        "desc": "Host is up because it replied on ICMP request or some TCP/UDP port is up",
                        "severity": "Info",
                    },
                )

                for names in node.findall("names"):
                    for name in names.findall("name"):
                        host["hostnames"].add(name.text)

                for endpoints in node.findall("endpoints"):
                    for endpoint in endpoints.findall("endpoint"):
                        svc = {
                            "protocol": endpoint.get("protocol"),
                            "port": int(endpoint.get("port")),
                            "status": endpoint.get("status"),
                        }
                        for services in endpoint.findall("services"):
                            for service in services.findall("service"):
                                svc["name"] = service.get("name", "").lower()
                                svc["vulns"] = self._parse_tests_type(service, vulns)

                                for configs in service.findall("configurations"):
                                    for config in configs.findall("config"):
                                        if "banner" in config.get("name"):
                                            svc["version"] = config.get("name")

                                # Add open port finding
                                svc["vulns"].append(
                                    {
                                        "name": "Open port {}/{}".format(
                                            svc["protocol"].upper(),
                                            svc["port"],
                                        ),
                                        "desc": '{}/{} port is open with "{}" service'.format(
                                            svc["protocol"],
                                            svc["port"],
                                            service.get("name"),
                                        ),
                                        "severity": "Info",
                                        "tags": [
                                            re.sub(
                                                r"[^A-Za-z0-9]+",
                                                "-",
                                                service.get("name").lower(),
                                            ).rstrip("-"),
                                        ]
                                        if service.get("name") != "<unknown>"
                                        else [],
                                    },
                                )

                        host["services"].append(svc)

                hosts.append(host)

        dupes = {}
        findings = []

        for host in hosts:
            # Manage findings by node only
            for vuln in host["vulns"]:
                dupe_key = vuln["severity"] + vuln["name"]

                find = self._find_standardized_finding(dupe_key, dupes, vuln)

                endpoint = StandardizedEndpoint(url=f"http://{host['name']}")
                find.raw_data.setdefault("affected_endpoints", []).append({
                    "url": f"http://{host['name']}",
                    "host": host['name']
                })
                find.tags.extend(vuln.get("tags", []))

            # Manage findings by service
            for service in host["services"]:
                for vuln in service["vulns"]:
                    dupe_key = vuln["severity"] + vuln["name"]

                    find = self._find_standardized_finding(dupe_key, dupes, vuln)

                    # Build URL for service endpoint
                    protocol = service["name"] if service["name"] in SCHEME_PORT_MAP else service["protocol"]
                    port = service["port"]
                    url = f"{protocol}://{host['name']}:{port}"
                    
                    endpoint = StandardizedEndpoint(url=url)
                    find.raw_data.setdefault("affected_endpoints", []).append({
                        "url": url,
                        "host": host['name'],
                        "port": port,
                        "protocol": protocol
                    })
                    find.tags.extend(vuln.get("tags", []))

        return list(dupes.values())

    def _find_standardized_finding(self, dupe_key, dupes, vuln) -> StandardizedFinding:
        """Create or update standardized finding"""
        if dupe_key in dupes:
            find = dupes[dupe_key]
            dupe_text = html2text.html2text(vuln.get("pluginOutput", ""))
            if dupe_text not in find.description:
                find.description += "\n\n" + dupe_text
        else:
            find = self._create_standardized_finding(vuln)
            dupes[dupe_key] = find
        return find

    def _create_standardized_finding(self, vuln) -> StandardizedFinding:
        """Create a standardized finding from Nexpose vulnerability data"""
        
        # Map severity to SeverityLevel enum
        severity_mapping = {
            "Critical": SeverityLevel.CRITICAL,
            "High": SeverityLevel.HIGH,
            "Medium": SeverityLevel.MEDIUM,
            "Low": SeverityLevel.LOW,
            "Info": SeverityLevel.INFO
        }
        standardized_severity = severity_mapping.get(vuln["severity"], SeverityLevel.MEDIUM)

        # Build references
        references = []
        for ref in vuln.get("refs", {}):
            if ref.startswith("BID"):
                references.append(f"https://www.securityfocus.com/bid/{vuln['refs'][ref]}")
            elif ref.startswith("CA"):
                references.append(f"https://www.cert.org/advisories/{vuln['refs'][ref]}.html")
            elif ref.startswith("CERT-VN"):
                references.append(f"https://www.kb.cert.org/vuls/id/{vuln['refs'][ref]}.html")
            elif ref.startswith("CVE"):
                references.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln['refs'][ref]}")
            elif ref.startswith("DEBIAN"):
                references.append(f"https://security-tracker.debian.org/tracker/{vuln['refs'][ref]}")
            elif ref.startswith("XF"):
                references.append(f"https://exchange.xforce.ibmcloud.com/vulnerabilities/{vuln['refs'][ref]}")
            elif ref.startswith("URL"):
                references.append(vuln['refs'][ref])
            else:
                references.append(f"{ref}: {vuln['refs'][ref]}")

        # Extract CVE IDs (separate from CWE)
        cve_ids = []
        if "CVE" in vuln.get("refs", {}):
            raw_cve = vuln["refs"]["CVE"]
            if isinstance(raw_cve, list):
                cve_ids.extend(raw_cve)
            elif raw_cve:
                cve_ids.append(str(raw_cve))

        # Extract CWE IDs from dedicated field, not from refs
        cwe_ids = []
        for ref_key in vuln.get("refs", {}):
            if ref_key.upper().startswith("CWE"):
                raw_cwe = vuln["refs"][ref_key]
                if isinstance(raw_cwe, list):
                    cwe_ids.extend([f"CWE-{c}" if not str(c).upper().startswith("CWE") else str(c) for c in raw_cwe])
                elif raw_cwe:
                    cwe_str = str(raw_cwe)
                    cwe_ids.append(f"CWE-{cwe_str}" if not cwe_str.upper().startswith("CWE") else cwe_str)

        # Create standardized finding
        finding = StandardizedFinding(
            title=vuln["name"],
            severity=standardized_severity,
            description=html2text.html2text(vuln["desc"].strip())
            + "\n\n"
            + html2text.html2text(vuln.get("pluginOutput", "").strip()),
            solution=html2text.html2text(vuln.get("resolution")) if vuln.get("resolution") else None,
            evidence=vuln.get("vector") or None,
            references=references,
            cwe_ids=cwe_ids,
            cvss_vector=vuln.get("vector"),
            scanner_type="nexpose",
            scanner_id=vuln["name"],
            tags=vuln.get("tags", []),
            raw_data={
                "false_p": False,
                "duplicate": False,
                "out_of_scope": False,
                "dynamic_finding": True,
                "affected_endpoints": [],
                "discovered_date": vuln.get("vulnerableSince"),
                "cve_ids": cve_ids,
            }
        )

        return finding

    def get_scan_types(self):
        return ["Nexpose Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Use the full XML export template from Nexpose."
