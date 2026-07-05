from pathlib import Path

from utils.parsers.nmap.parser import NmapParser


def test_nmap_host_description_is_not_duplicated(tmp_path):
    xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1762473600">
  <host>
    <status state="up"/>
    <address addr="10.110.101.240" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.9p1 Ubuntu 10" extrainfo="Ubuntu Linux; protocol 2.0"/>
        <script id="ssh-hostkey" output="rsa key here"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <script id="fingerprint-strings" output="HTTP/1.1 200 OK"/>
      </port>
      <port protocol="tcp" portid="8000">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    report = tmp_path / "nmap.xml"
    report.write_text(xml)

    findings = NmapParser().parse_findings(str(report))

    assert len(findings) == 1
    description = findings[0].description
    assert description.count("Host") == 1
    assert "Open Ports" in description
    assert "22/tcp" in description
    assert "80/tcp" in description
    assert "8000/tcp" in description
    assert description.count("IP Address: 10.110.101.240") == 1
    assert "Script ID: ssh-hostkey" in description
    assert "Script ID: fingerprint-strings" in description
    # No leftover Markdown syntax — the app has no Markdown renderer anywhere
    assert "###" not in description
    assert "**" not in description
