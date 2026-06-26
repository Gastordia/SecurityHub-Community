from utils.parsers.nessus.parser import NessusParser
import tempfile


def test_nessus_parser_extracts_host_metadata_from_plugin_output():
    parser = NessusParser()
    output = """
    Following OS Fingerprints were found

    Remote operating system : AIX 6.1
    Confidence level : 56
    Method : MLSinFP
    Type : unknown
    Fingerprint : unknown

    Remote operating system : Microsoft Windows
    Confidence level : 70
    Method : HTTP
    Type : general-purpose
    Fingerprint : HTTP:Server: Microsoft-HTTPAPI/2.0

    Following fingerprints could not be used to determine OS :
    SSLcert:!:i/CN:localhosts/CN:localhost
    i/CN:QNAP NASi/O:QNAP Systems, Inc.i/OU:QTS
    """

    metadata = parser._extract_host_metadata(
        plugin_id="11936",
        title="OS Identification",
        plugin_output=output,
        ip="192.168.1.240",
        fqdn="nas.example.local",
        port="443",
    )

    assert metadata["operating_system"] == "Microsoft Windows"
    assert metadata["os_detection_confidence"] == 70
    assert metadata["os_detection_method"] == "HTTP"
    assert len(metadata["os_fingerprints"]) == 2
    assert "QNAP NAS" in metadata["certificate_names"]
    assert metadata["hostnames"] == ["QNAP NAS", "nas.example.local"]


def test_nessus_parser_extracts_kerberos_metadata():
    parser = NessusParser()
    output = """
    Nessus gathered the following information :

      Server time  : 2026-04-22 15:14:01 UTC
      Realm        : MAYDANE.REIM
    """

    metadata = parser._extract_host_metadata(
        plugin_id="1",
        title="Kerberos Information Disclosure",
        plugin_output=output,
        ip="192.168.1.5",
    )

    assert metadata["kerberos_realm"] == "MAYDANE.REIM"
    assert metadata["kerberos_server_time"] == "2026-04-22 15:14:01 UTC"


def test_nessus_parser_preserves_xml_host_and_plugin_metadata():
    parser = NessusParser()
    xml_content = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Example">
    <ReportHost name="192.168.1.240">
      <HostProperties>
        <tag name="host-ip">192.168.1.240</tag>
        <tag name="netbios-name">MAYDANE-REIM</tag>
        <tag name="operating-system">QNAP QTS</tag>
        <tag name="operating-system-conf">95</tag>
        <tag name="operating-system-method">WebUI</tag>
        <tag name="system-type">embedded</tag>
        <tag name="Credentialed_Scan">false</tag>
        <tag name="policy-used">Advanced Scan</tag>
        <tag name="patch-summary-total-cves">0</tag>
        <tag name="traceroute-hop-0">192.168.1.240</tag>
        <tag name="cpe-0">cpe:/a:qnap:qts -&gt; QNAP QTS</tag>
      </HostProperties>
      <ReportItem
        port="443"
        svc_name="www"
        protocol="tcp"
        severity="2"
        pluginID="99999"
        pluginName="Sample Plugin"
        pluginFamily="General"
      >
        <description>Detailed plugin description</description>
        <synopsis>Short synopsis</synopsis>
        <plugin_output>Example output</plugin_output>
        <plugin_publication_date>2025/01/01</plugin_publication_date>
        <plugin_modification_date>2025/02/02</plugin_modification_date>
        <plugin_type>remote</plugin_type>
        <risk_factor>Medium</risk_factor>
        <script_version>1.2.3</script_version>
        <cve>CVE-2025-1111</cve>
        <cpe>cpe:/a:qnap:qts:5.1</cpe>
        <epss_score>0.4567</epss_score>
        <exploit_available>true</exploit_available>
        <exploited_by_nessus>true</exploited_by_nessus>
        <cisa-known-exploited>true</cisa-known-exploited>
        <in_the_news>true</in_the_news>
        <asset_inventory>QNAP QTS</asset_inventory>
        <asset_inventory_category>software</asset_inventory_category>
        <os_identification>QNAP QTS via WebUI</os_identification>
        <cvss3_base_score>8.8</cvss3_base_score>
        <cvss3_vector>AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss3_vector>
        <cvss_score_source>CVSS v3</cvss_score_source>
        <cvss_score_rationale>Provided by plugin</cvss_score_rationale>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

    with tempfile.NamedTemporaryFile(suffix=".nessus", mode="w", encoding="utf-8", delete=False) as temp_file:
        temp_file.write(xml_content)
        temp_path = temp_file.name

    findings = parser.parse_findings(temp_path)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.raw_data["plugin_family"] == "General"
    assert finding.raw_data["plugin_type"] == "remote"
    assert finding.raw_data["script_version"] == "1.2.3"
    assert finding.raw_data["epss_score"] == 0.4567
    assert finding.raw_data["exploit_available"] is True
    assert finding.raw_data["exploited_by_nessus"] is True
    assert finding.raw_data["cisa_known_exploited"] is True
    assert finding.raw_data["in_the_news"] is True
    assert finding.raw_data["asset_inventory"] == "QNAP QTS"
    assert finding.raw_data["asset_inventory_category"] == "software"
    assert finding.raw_data["os_identification"] == "QNAP QTS via WebUI"
    assert finding.raw_data["component_cpe"] == "cpe:/a:qnap:qts:5.1"
    assert finding.raw_data["component_name"] == "qts"
    assert finding.raw_data["component_version"] == "5.1"
    assert finding.raw_data["operating_system"] == "QNAP QTS"
    assert finding.raw_data["device_type"] == "embedded"
    assert finding.raw_data["credentialed_scan"] is False
    assert finding.raw_data["scan_policy"] == "Advanced Scan"
    assert finding.raw_data["netbios_name"] == "MAYDANE-REIM"
    assert finding.raw_data["host_cpe_list"] == ["cpe:/a:qnap:qts"]
    assert finding.raw_data["traceroute"] == ["192.168.1.240"]
    assert set(finding.tags) == {"exploit-available", "exploited-by-nessus", "cisa-kev", "in-the-news"}
