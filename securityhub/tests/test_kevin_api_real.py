#!/usr/bin/env python3
"""
Real KEVin API Testing Script
Tests the actual KEVin API endpoints with real data
"""

import requests
import json
import time
from datetime import datetime, timedelta

class KEVinAPITester:
    """Test KEVin API with real data"""
    
    def __init__(self):
        self.base_url = "https://kevin.gtfkd.com"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityHub-KEVin-API-Tester/1.0'
        })
    
    def test_api_endpoint(self, endpoint, description):
        """Test a specific API endpoint"""
        print(f"\n🔍 Testing: {description}")
        print(f"   Endpoint: {endpoint}")
        
        try:
            start_time = time.time()
            response = self.session.get(endpoint, timeout=15)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            print(f"   Status: {response.status_code}")
            print(f"   Response Time: {response_time:.2f}ms")
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Success: {len(data) if isinstance(data, list) else 'Data received'}")
                return True, data
            else:
                print(f"   ❌ Failed: HTTP {response.status_code}")
                return False, None
                
        except requests.exceptions.Timeout:
            print(f"   ⏰ Timeout after 15 seconds")
            return False, None
        except requests.exceptions.ConnectionError:
            print(f"   🔌 Connection Error")
            return False, None
        except Exception as e:
            print(f"   💥 Error: {str(e)}")
            return False, None
    
    def test_kev_endpoints(self):
        """Test KEV (Known Exploited Vulnerabilities) endpoints"""
        print("\n" + "="*80)
        print("TESTING KEV ENDPOINTS")
        print("="*80)
        
        # Test 1: Get recent KEVs
        endpoint = f"{self.base_url}/kev/recent?days=7"
        success, data = self.test_api_endpoint(endpoint, "Recent KEVs (last 7 days)")
        
        if success and data:
            if isinstance(data, list) and len(data) > 0:
                latest_kev = data[0]
                print(f"   📅 Latest KEV: {latest_kev.get('cveID', 'N/A')} - {latest_kev.get('dateAdded', 'N/A')}")
                print(f"   📊 Total recent KEVs: {len(data)}")
            else:
                print(f"   📊 Data format: {type(data)}")
        
        # Test 2: Get KEV metrics
        endpoint = f"{self.base_url}/get_metrics"
        success, data = self.test_api_endpoint(endpoint, "KEV Metrics")
        
        if success and data:
            print(f"   📈 Total CVEs: {data.get('cves_count', 'N/A')}")
            print(f"   🎯 Total KEVs: {data.get('kevs_count', 'N/A')}")
        
        # Test 3: Search KEVs by vendor
        endpoint = f"{self.base_url}/kev?search=Microsoft&page=1&per_page=5"
        success, data = self.test_api_endpoint(endpoint, "Search Microsoft KEVs")
        
        if success and data:
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"   🔍 Found {len(vulns)} Microsoft vulnerabilities")
                for i, vuln in enumerate(vulns[:3]):  # Show first 3
                    print(f"      {i+1}. {vuln.get('cveID', 'N/A')}: {vuln.get('vendor', 'N/A')}")
            else:
                print(f"   📊 Data structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        
        # Test 4: Check specific CVE in KEV
        test_cve = "CVE-2023-22527"  # A known CVE
        endpoint = f"{self.base_url}/kev/exists?cve={test_cve}"
        success, data = self.test_api_endpoint(endpoint, f"Check if {test_cve} exists in KEV")
        
        if success and data:
            exists = data.get('exists', False)
            print(f"   🎯 {test_cve} in KEV: {'✅ YES' if exists else '❌ NO'}")
        
        # Test 5: Get detailed KEV information
        endpoint = f"{self.base_url}/kev/{test_cve}"
        success, data = self.test_api_endpoint(endpoint, f"Get detailed KEV info for {test_cve}")
        
        if success and data:
            print(f"   📋 Vendor: {data.get('vendor', 'N/A')}")
            print(f"   🏷️  Product: {data.get('product', 'N/A')}")
            print(f"   📅 Date Added: {data.get('dateAdded', 'N/A')}")
            print(f"   ⚠️  Required Action: {data.get('requiredAction', 'N/A')}")
    
    def test_vuln_endpoints(self):
        """Test vulnerability endpoints"""
        print("\n" + "="*80)
        print("TESTING VULNERABILITY ENDPOINTS")
        print("="*80)
        
        test_cve = "CVE-2023-22527"
        
        # Test 1: Get comprehensive vulnerability data
        endpoint = f"{self.base_url}/vuln/{test_cve}"
        success, data = self.test_api_endpoint(endpoint, f"Get comprehensive data for {test_cve}")
        
        if success and data:
            print(f"   📊 Data sources available:")
            if 'cisaData' in data:
                print(f"      ✅ CISA Data")
            if 'nvdData' in data:
                print(f"      ✅ NVD Data")
            if 'mitreData' in data:
                print(f"      ✅ MITRE Data")
            if 'cveID' in data:
                print(f"      ✅ CVE ID: {data['cveID']}")
        
        # Test 2: Get NVD data only
        endpoint = f"{self.base_url}/vuln/{test_cve}/nvd"
        success, data = self.test_api_endpoint(endpoint, f"Get NVD data for {test_cve}")
        
        if success and data:
            print(f"   📊 NVD data received: {len(data) if isinstance(data, dict) else 'Data available'}")
        
        # Test 3: Get MITRE data only
        endpoint = f"{self.base_url}/vuln/{test_cve}/mitre"
        success, data = self.test_api_endpoint(endpoint, f"Get MITRE data for {test_cve}")
        
        if success and data:
            print(f"   📊 MITRE data received: {len(data) if isinstance(data, dict) else 'Data available'}")
    
    def test_recent_endpoints(self):
        """Test recent vulnerability endpoints"""
        print("\n" + "="*80)
        print("TESTING RECENT VULNERABILITY ENDPOINTS")
        print("="*80)
        
        # Test 1: Get recently published vulnerabilities
        endpoint = f"{self.base_url}/vuln/published?days=7&page=1&per_page=10"
        success, data = self.test_api_endpoint(endpoint, "Recently published vulnerabilities (last 7 days)")
        
        if success and data:
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"   📅 Found {len(vulns)} recently published vulnerabilities")
                if vulns:
                    latest = vulns[0]
                    print(f"   🆕 Latest: {latest.get('cveID', 'N/A')} - {latest.get('publishedDate', 'N/A')}")
            else:
                print(f"   📊 Data structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        
        # Test 2: Get recently modified vulnerabilities
        endpoint = f"{self.base_url}/vuln/modified?days=7&page=1&per_page=10"
        success, data = self.test_api_endpoint(endpoint, "Recently modified vulnerabilities (last 7 days)")
        
        if success and data:
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"   📝 Found {len(vulns)} recently modified vulnerabilities")
            else:
                print(f"   📊 Data structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
    
    def test_advanced_search(self):
        """Test advanced search capabilities"""
        print("\n" + "="*80)
        print("TESTING ADVANCED SEARCH CAPABILITIES")
        print("="*80)
        
        # Test 1: Search by actor
        endpoint = f"{self.base_url}/kev?actor=Lazarus%20Group&page=1&per_page=5"
        success, data = self.test_api_endpoint(endpoint, "Search KEVs by actor (Lazarus Group)")
        
        if success and data:
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"   🕵️  Found {len(vulns)} vulnerabilities related to Lazarus Group")
                for i, vuln in enumerate(vulns[:3]):
                    print(f"      {i+1}. {vuln.get('cveID', 'N/A')}: {vuln.get('vendor', 'N/A')}")
            else:
                print(f"   📊 Data structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        
        # Test 2: Filter by ransomware
        endpoint = f"{self.base_url}/kev?filter=ransomware&page=1&per_page=5"
        success, data = self.test_api_endpoint(endpoint, "Filter KEVs by ransomware usage")
        
        if success and data:
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"   🦠 Found {len(vulns)} ransomware-related vulnerabilities")
            else:
                print(f"   📊 Data structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        
        # Test 3: Sort by severity
        endpoint = f"{self.base_url}/kev?sort=severity&order=desc&page=1&per_page=5"
        success, data = self.test_api_endpoint(endpoint, "Sort KEVs by severity (highest first)")
        
        if success and data:
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"   🔴 Found {len(vulns)} highest severity vulnerabilities")
                if vulns:
                    highest = vulns[0]
                    print(f"   🚨 Highest severity: {highest.get('cveID', 'N/A')}")
            else:
                print(f"   📊 Data structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
    
    def test_pagination(self):
        """Test pagination functionality"""
        print("\n" + "="*80)
        print("TESTING PAGINATION FUNCTIONALITY")
        print("="*80)
        
        # Test 1: First page
        endpoint = f"{self.base_url}/kev?page=1&per_page=3"
        success, data = self.test_api_endpoint(endpoint, "First page (3 items per page)")
        
        if success and data:
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"   📄 Page 1: {len(vulns)} items")
                if vulns:
                    print(f"      Items: {', '.join([v.get('cveID', 'N/A') for v in vulns])}")
        
        # Test 2: Second page
        endpoint = f"{self.base_url}/kev?page=2&per_page=3"
        success, data = self.test_api_endpoint(endpoint, "Second page (3 items per page)")
        
        if success and data:
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"   📄 Page 2: {len(vulns)} items")
                if vulns:
                    print(f"      Items: {', '.join([v.get('cveID', 'N/A') for v in vulns])}")
    
    def run_all_tests(self):
        """Run all KEVin API tests"""
        print("🚀 Starting KEVin API Real Data Testing")
        print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🌐 Base URL: {self.base_url}")
        
        # Run all test categories
        self.test_kev_endpoints()
        self.test_vuln_endpoints()
        self.test_recent_endpoints()
        self.test_advanced_search()
        self.test_pagination()
        
        print("\n" + "="*80)
        print("🎉 KEVin API Testing Complete!")
        print(f"⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)


def main():
    """Main function to run KEVin API tests"""
    tester = KEVinAPITester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()


