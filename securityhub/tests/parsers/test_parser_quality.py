#!/usr/bin/env python3
"""
Quality test for SecurityHub parsers
Tests the specific improvements we made to filter out low-quality findings
"""

import os
import tempfile
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.parsers.nexpose.parser import NexposeParser
from utils.parsers.burp.parser import BurpParser
from utils.parsers.appspider.parser import AppSpiderParser
from utils.parsers.models import SeverityLevel


def test_nexpose_quality_filtering():
    """Test that Nexpose parser filters out low-quality findings"""
    print("🧪 Testing Nexpose Quality Filtering...")
    
    parser = NexposeParser()
    
    # Create XML with both real vulnerabilities and low-quality findings
    xml_content = """<?xml version="1.0"?>
    <NexposeReport>
        <VulnerabilityDefinitions>
            <VulnerabilityDefinition id="real-vuln-1">
                <title>SQL Injection in Login Form</title>
                <description>SQL injection vulnerability found in login form</description>
                <severity>High</severity>
                <cvssScore>8.5</cvssScore>
            </VulnerabilityDefinition>
            <VulnerabilityDefinition id="real-vuln-2">
                <title>Cross-Site Scripting (XSS)</title>
                <description>Reflected XSS vulnerability in search parameter</description>
                <severity>Medium</severity>
                <cvssScore>6.1</cvssScore>
            </VulnerabilityDefinition>
            <VulnerabilityDefinition id="low-quality-1">
                <title>Host Up</title>
                <description>Host is up because it replied on ICMP request</description>
                <severity>Info</severity>
            </VulnerabilityDefinition>
            <VulnerabilityDefinition id="low-quality-2">
                <title>Service: http</title>
                <description>HTTP service is running on port 80</description>
                <severity>Info</severity>
            </VulnerabilityDefinition>
            <VulnerabilityDefinition id="low-quality-3">
                <title>Port Open</title>
                <description>TCP port 22 is open</description>
                <severity>Info</severity>
            </VulnerabilityDefinition>
        </VulnerabilityDefinitions>
        <nodes>
            <node address="192.168.1.1">
                <tests>
                    <test id="real-vuln-1"/>
                    <test id="real-vuln-2"/>
                    <test id="low-quality-1"/>
                    <test id="low-quality-2"/>
                    <test id="low-quality-3"/>
                </tests>
            </node>
        </nodes>
    </NexposeReport>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        temp_file = f.name
    
    try:
        findings = parser.parse_findings(temp_file)
        
        print(f"  📊 Found {len(findings)} findings")
        
        # Should only have the real vulnerabilities
        expected_titles = [
            "SQL Injection in Login Form",
            "Cross-Site Scripting (XSS)"
        ]
        
        actual_titles = [f.title for f in findings]
        
        for title in expected_titles:
            if title in actual_titles:
                print(f"  ✅ Found real vulnerability: {title}")
            else:
                print(f"  ❌ Missing real vulnerability: {title}")
        
        # Should NOT have low-quality findings
        low_quality_titles = ["Host Up", "Service: http", "Port Open"]
        for title in low_quality_titles:
            if title in actual_titles:
                print(f"  ❌ Found low-quality finding (should be filtered): {title}")
            else:
                print(f"  ✅ Correctly filtered out: {title}")
        
        # Check severities
        severities = [f.severity for f in findings]
        if SeverityLevel.HIGH in severities:
            print(f"  ✅ Found High severity findings")
        if SeverityLevel.MEDIUM in severities:
            print(f"  ✅ Found Medium severity findings")
        
        return len(findings) == 2 and all(title in actual_titles for title in expected_titles)
        
    finally:
        os.unlink(temp_file)


def test_burp_title_improvements():
    """Test that Burp parser creates proper titles instead of numeric IDs"""
    print("\n🧪 Testing Burp Title Improvements...")
    
    parser = BurpParser()
    
    # Create XML with various vulnerability types
    xml_content = """<?xml version="1.0"?>
    <issues>
        <issue url="http://example.com/login">
            <serialNumber>12345</serialNumber>
            <type>SQL injection</type>
            <severity>High</severity>
            <description>SQL injection vulnerability found in login form</description>
            <location>Parameter: username</location>
            <path>/login</path>
        </issue>
        <issue url="http://example.com/search">
            <serialNumber>67890</serialNumber>
            <type>Cross-site scripting</type>
            <severity>Medium</severity>
            <description>XSS vulnerability found in search form</description>
            <location>Parameter: q</location>
            <path>/search</path>
        </issue>
        <issue url="http://example.com/admin">
            <serialNumber>11111</serialNumber>
            <type>Information disclosure</type>
            <severity>Low</severity>
            <description>Sensitive information exposed in error messages</description>
            <location>Response headers</location>
        </issue>
    </issues>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        temp_file = f.name
    
    try:
        findings = parser.parse_findings(temp_file)
        
        print(f"  📊 Found {len(findings)} findings")
        
        # Add debugging for the first finding
        if findings:
            first_finding = findings[0]
            print(f"  🔍 Debug - First finding raw_data:")
            print(f"    vuln_type: {first_finding.raw_data.get('vuln_type', 'N/A')}")
            print(f"    parameter: {first_finding.raw_data.get('parameter', 'N/A')}")
            print(f"    path: {first_finding.raw_data.get('path', 'N/A')}")
            print(f"    location: {first_finding.raw_data.get('location', 'N/A')}")
        
        # Show actual titles for debugging
        print("  🔍 Actual titles generated:")
        for i, finding in enumerate(findings):
            print(f"    {i+1}. {finding.title}")
        
        # Check for proper titles instead of numeric IDs
        titles = [f.title for f in findings]
        
        expected_titles = [
            "SQL injection in Parameter: username",
            "Cross-site scripting in Parameter: q",
            "Information disclosure in Response headers"
        ]
        
        print("  🔍 Expected titles:")
        for title in expected_titles:
            print(f"    - {title}")
        
        for title in expected_titles:
            if title in titles:
                print(f"  ✅ Found proper title: {title}")
            else:
                print(f"  ❌ Missing proper title: {title}")
        
        # Should NOT have numeric IDs as titles
        numeric_titles = ["12345", "67890", "11111"]
        for title in numeric_titles:
            if title in titles:
                print(f"  ❌ Found numeric title (should be improved): {title}")
            else:
                print(f"  ✅ Correctly improved numeric title: {title}")
        
        # Check severities
        severities = [f.severity for f in findings]
        if SeverityLevel.HIGH in severities:
            print(f"  ✅ Found High severity findings")
        if SeverityLevel.MEDIUM in severities:
            print(f"  ✅ Found Medium severity findings")
        if SeverityLevel.LOW in severities:
            print(f"  ✅ Found Low severity findings")
        
        return len(findings) == 3 and all(title in titles for title in expected_titles)
        
    finally:
        os.unlink(temp_file)


def test_appspider_robustness():
    """Test that AppSpider parser handles different formats robustly"""
    print("\n🧪 Testing AppSpider Robustness...")
    
    parser = AppSpiderParser()
    
    # Test JSON format
    json_content = {
        "Vulnerabilities": [
            {
                "Name": "SQL Injection",
                "Description": "SQL injection vulnerability found",
                "Severity": "High",
                "URL": "http://example.com/test",
                "CVSS": "8.5",
                "Solution": "Use parameterized queries"
            }
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        import json
        json.dump(json_content, f)
        temp_file = f.name
    
    try:
        findings = parser.parse_findings(temp_file)
        
        print(f"  📊 Found {len(findings)} findings from JSON")
        
        if len(findings) > 0:
            finding = findings[0]
            print(f"  ✅ Title: {finding.title}")
            print(f"  ✅ Severity: {finding.severity}")
            print(f"  ✅ CVSS Score: {finding.cvss_score}")
            print(f"  ✅ Solution: {finding.solution}")
            
            return True
        else:
            print(f"  ❌ No findings parsed from JSON")
            return False
            
    finally:
        os.unlink(temp_file)


def run_quality_tests():
    """Run all quality tests"""
    print("🔍 SecurityHub Parser Quality Tests")
    print("=" * 50)
    
    tests = [
        ("Nexpose Quality Filtering", test_nexpose_quality_filtering),
        ("Burp Title Improvements", test_burp_title_improvements),
        ("AppSpider Robustness", test_appspider_robustness)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        try:
            if test_func():
                print(f"  ✅ {test_name} PASSED")
                passed += 1
            else:
                print(f"  ❌ {test_name} FAILED")
        except Exception as e:
            print(f"  ❌ {test_name} ERROR: {str(e)}")
    
    print("\n" + "=" * 50)
    print(f"📊 Quality Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All quality tests passed! Parsers are working correctly.")
        return True
    else:
        print("⚠️ Some quality tests failed. Check the output above.")
        return False


if __name__ == '__main__':
    success = run_quality_tests()
    exit(0 if success else 1)
