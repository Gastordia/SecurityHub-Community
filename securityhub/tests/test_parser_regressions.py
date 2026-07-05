import tempfile
from pathlib import Path
from unittest import TestCase

from utils.parsers.burp.parser import BurpParser
from utils.parsers.nexpose.parser import NexposeParser
from utils.parsers.nuclei.parser import NucleiParser


class ParserRegressionTests(TestCase):
    def test_nuclei_uses_info_name_as_title(self):
        content = (
            '{"templateID":"synthetic-nuclei","info":{"name":"Synthetic Nuclei Title",'
            '"severity":"high","description":"desc"},"matched-at":"https://example.test"}'
        )
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", encoding="utf-8", delete=False) as f:
            f.write(content)
            path = f.name

        findings = NucleiParser().parse_findings(path)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Synthetic Nuclei Title")

    def test_burp_falls_back_to_type_when_name_missing(self):
        xml = """<?xml version="1.0"?>
<issues>
  <issue url="http://example.test/login">
    <serialNumber>1</serialNumber>
    <type>Synthetic Burp Type</type>
    <severity>High</severity>
    <location>Parameter: username</location>
    <path>/login</path>
  </issue>
</issues>
"""
        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", encoding="utf-8", delete=False) as f:
            f.write(xml)
            path = f.name

        findings = BurpParser().parse_findings(path)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Synthetic Burp Type")
        self.assertEqual(findings[0].affected_asset, "http://example.test/login")

    def test_nexpose_filters_inventory_noise(self):
        xml = """<?xml version="1.0"?>
<NexposeReport>
  <VulnerabilityDefinitions>
    <vulnerability id="real-vuln" title="Synthetic Nexpose Title" severity="7">
      <description><paragraph>Real vulnerability</paragraph></description>
    </vulnerability>
    <vulnerability id="noise-host" title="Host Up" severity="0">
      <description><paragraph>Inventory noise</paragraph></description>
    </vulnerability>
  </VulnerabilityDefinitions>
  <nodes>
    <node address="192.0.2.55">
      <tests>
        <test id="real-vuln" status="vulnerable-version" />
        <test id="noise-host" status="vulnerable-version" />
      </tests>
      <endpoints>
        <endpoint protocol="tcp" port="443" status="open">
          <services>
            <service name="https">
              <tests />
            </service>
          </services>
        </endpoint>
      </endpoints>
    </node>
  </nodes>
</NexposeReport>
"""
        report = Path(tempfile.mkdtemp()) / "nexpose.xml"
        report.write_text(xml, encoding="utf-8")

        findings = NexposeParser().parse_findings(str(report))
        titles = [finding.title for finding in findings]

        self.assertIn("Synthetic Nexpose Title", titles)
        self.assertNotIn("Host Up", titles)
        self.assertFalse(any(title.startswith("Open port ") for title in titles))
