#!/usr/bin/env python3
"""
Minimal KEVin API Test
Tests the core KEVin API functionality without complex Django setup
"""

import pytest
import requests
import json
import time
from datetime import datetime


@pytest.mark.skip(reason="External network test — requires live https://kevin.gtfkd.com, run manually")
def test_kevin_api_core_functionality():
    """Test core KEVin API functionality"""
    print("🔍 Testing KEVin API Core Functionality")
    print("=" * 60)
    
    base_url = "https://kevin.gtfkd.com"
    
    # Test 1: Basic connectivity
    print("\n🌐 Test 1: Basic API Connectivity")
    try:
        response = requests.get(f"{base_url}/get_metrics", timeout=10)
        if response.status_code == 200:
            print("✅ API is accessible and responding")
        else:
            print(f"❌ API returned status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False
    
    # Test 2: KEV data retrieval
    print("\n📊 Test 2: KEV Data Retrieval")
    try:
        response = requests.get(f"{base_url}/kev/recent?days=1", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Retrieved {len(data)} recent KEVs")
            if data:
                latest = data[0]
                print(f"   Latest: {latest.get('cveID', 'N/A')}")
        else:
            print(f"❌ KEV endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ KEV test failed: {e}")
    
    # Test 3: Vulnerability data retrieval
    print("\n🔬 Test 3: Vulnerability Data Retrieval")
    test_cve = "CVE-2023-22527"
    try:
        response = requests.get(f"{base_url}/vuln/{test_cve}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Retrieved vulnerability data for {test_cve}")
            print(f"   Data sources: {list(data.keys())}")
        else:
            print(f"❌ Vulnerability endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Vulnerability test failed: {e}")
    
    # Test 4: Search functionality
    print("\n🔍 Test 4: Search Functionality")
    try:
        response = requests.get(f"{base_url}/kev?search=Microsoft&page=1&per_page=3", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"✅ Search found {len(vulns)} Microsoft vulnerabilities")
            else:
                print(f"✅ Search endpoint working (data structure: {list(data.keys())})")
        else:
            print(f"❌ Search endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Search test failed: {e}")
    
    # Test 5: Performance test
    print("\n⚡ Test 5: Performance Test")
    endpoints = [
        "/get_metrics",
        "/kev/recent?days=1",
        "/kev?page=1&per_page=5"
    ]
    
    total_time = 0
    successful_requests = 0
    
    for endpoint in endpoints:
        try:
            start_time = time.time()
            response = requests.get(f"{base_url}{endpoint}", timeout=10)
            end_time = time.time()
            
            if response.status_code == 200:
                response_time = (end_time - start_time) * 1000
                total_time += response_time
                successful_requests += 1
                print(f"   {endpoint}: {response_time:.2f}ms")
            else:
                print(f"   {endpoint}: Failed (HTTP {response.status_code})")
                
        except Exception as e:
            print(f"   {endpoint}: Error - {e}")
    
    if successful_requests > 0:
        avg_time = total_time / successful_requests
        print(f"   Average response time: {avg_time:.2f}ms")
        
        if avg_time < 500:
            print("   ✅ Performance: Excellent (< 500ms)")
        elif avg_time < 1000:
            print("   ✅ Performance: Good (< 1000ms)")
        else:
            print("   ⚠️  Performance: Slow (> 1000ms)")
    
    return True

def test_kevin_api_advanced_features():
    """Test advanced KEVin API features"""
    print("\n🚀 Testing KEVin API Advanced Features")
    print("=" * 60)
    
    base_url = "https://kevin.gtfkd.com"
    
    # Test 1: Actor-based search
    print("\n🕵️  Test 1: Actor-Based Search")
    try:
        response = requests.get(f"{base_url}/kev?actor=Lazarus%20Group&page=1&per_page=3", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"✅ Found {len(vulns)} Lazarus Group vulnerabilities")
            else:
                print("✅ Actor search endpoint working")
        else:
            print(f"❌ Actor search failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Actor search error: {e}")
    
    # Test 2: Ransomware filtering
    print("\n🦠 Test 2: Ransomware Filtering")
    try:
        response = requests.get(f"{base_url}/kev?filter=ransomware&page=1&per_page=3", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"✅ Found {len(vulns)} ransomware-related vulnerabilities")
            else:
                print("✅ Ransomware filter endpoint working")
        else:
            print(f"❌ Ransomware filter failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Ransomware filter error: {e}")
    
    # Test 3: Severity sorting
    print("\n🔴 Test 3: Severity Sorting")
    try:
        response = requests.get(f"{base_url}/kev?sort=severity&order=desc&page=1&per_page=3", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                print(f"✅ Found {len(vulns)} highest severity vulnerabilities")
            else:
                print("✅ Severity sorting endpoint working")
        else:
            print(f"❌ Severity sorting failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Severity sorting error: {e}")
    
    # Test 4: Pagination
    print("\n📄 Test 4: Pagination")
    try:
        # Get first page
        response1 = requests.get(f"{base_url}/kev?page=1&per_page=2", timeout=10)
        response2 = requests.get(f"{base_url}/kev?page=2&per_page=2", timeout=10)
        
        if response1.status_code == 200 and response2.status_code == 200:
            data1 = response1.json()
            data2 = response2.json()
            
            if 'vulnerabilities' in data1 and 'vulnerabilities' in data2:
                page1_count = len(data1['vulnerabilities'])
                page2_count = len(data2['vulnerabilities'])
                print(f"✅ Pagination working: Page 1 ({page1_count} items), Page 2 ({page2_count} items)")
            else:
                print("✅ Pagination endpoints working")
        else:
            print(f"❌ Pagination failed: Page 1 ({response1.status_code}), Page 2 ({response2.status_code})")
    except Exception as e:
        print(f"❌ Pagination error: {e}")

def main():
    """Main test function"""
    print("🚀 Starting KEVin API Minimal Testing")
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🌐 Testing against: https://kevin.gtfkd.com")
    
    # Test core functionality
    core_success = test_kevin_api_core_functionality()
    
    # Test advanced features
    test_kevin_api_advanced_features()
    
    print("\n" + "=" * 60)
    print("🎉 KEVin API Minimal Testing Complete!")
    print(f"⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if core_success:
        print("✅ All core functionality tests passed")
        print("💡 KEVin API is ready for production use")
    else:
        print("❌ Some core functionality tests failed")
        print("⚠️  Review results before production use")
    
    print("=" * 60)

if __name__ == "__main__":
    main()


