"""
Test runner for migrated services
Runs all unit tests and integration tests for the migrated functionality
"""

import unittest
import sys
import os
from datetime import datetime

# Add the project root to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Configure Django settings before importing any Django modules
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securityhub.settings')

import django
from django.conf import settings

# Configure Django
if not settings.configured:
    django.setup()

# Import test modules
from test_parser_service_migrated import TestParserServiceMigrated
from test_asset_intelligence_service_migrated import TestAssetIntelligenceServiceMigrated
from test_intelligence_engine_migrated import TestIntelligenceEngineMigrated
from test_service_integration_migrated import TestServiceIntegrationMigrated


class TestRunner:
    """Test runner for migrated services"""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = None
        self.end_time = None
    
    def run_all_tests(self):
        """Run all migrated service tests"""
        print("🧪 Starting Migrated Services Test Suite")
        print("=" * 60)
        
        self.start_time = datetime.now()
        
        # Test suites to run
        test_suites = [
            ('ParserService Migrated', TestParserServiceMigrated),
            ('AssetIntelligenceService Migrated', TestAssetIntelligenceServiceMigrated),
            ('IntelligenceEngine Migrated', TestIntelligenceEngineMigrated),
            ('Service Integration Migrated', TestServiceIntegrationMigrated)
        ]
        
        total_tests = 0
        total_failures = 0
        total_errors = 0
        
        for suite_name, test_class in test_suites:
            print(f"\n🔍 Running {suite_name} Tests...")
            print("-" * 40)
            
            # Create test suite
            suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
            
            # Run tests
            runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
            result = runner.run(suite)
            
            # Record results
            self.test_results[suite_name] = {
                'tests_run': result.testsRun,
                'failures': len(result.failures),
                'errors': len(result.errors),
                'success': result.wasSuccessful()
            }
            
            total_tests += result.testsRun
            total_failures += len(result.failures)
            total_errors += len(result.errors)
            
            # Print results for this suite
            if result.wasSuccessful():
                print(f"✅ {suite_name}: {result.testsRun} tests passed")
            else:
                print(f"❌ {suite_name}: {result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors")
        
        self.end_time = datetime.now()
        
        # Print overall results
        self.print_summary(total_tests, total_failures, total_errors)
        
        return total_failures == 0 and total_errors == 0
    
    def print_summary(self, total_tests, total_failures, total_errors):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 MIGRATED SERVICES TEST SUMMARY")
        print("=" * 60)
        
        duration = (self.end_time - self.start_time).total_seconds()
        
        print(f"⏱️  Total Duration: {duration:.2f} seconds")
        print(f"🧪 Total Tests: {total_tests}")
        print(f"✅ Passed: {total_tests - total_failures - total_errors}")
        print(f"❌ Failed: {total_failures}")
        print(f"💥 Errors: {total_errors}")
        
        if total_failures == 0 and total_errors == 0:
            print("\n🎉 ALL TESTS PASSED! Migrated services are working correctly.")
        else:
            print(f"\n⚠️  {total_failures + total_errors} tests failed. Please review the issues above.")
        
        print("\n📋 Detailed Results by Service:")
        print("-" * 40)
        
        for suite_name, results in self.test_results.items():
            status = "✅ PASS" if results['success'] else "❌ FAIL"
            print(f"{status} {suite_name}: {results['tests_run']} tests")
            if not results['success']:
                print(f"    - Failures: {results['failures']}")
                print(f"    - Errors: {results['errors']}")
    
    def run_specific_tests(self, test_names):
        """Run specific test methods"""
        print(f"🔍 Running specific tests: {', '.join(test_names)}")
        print("=" * 60)
        
        # This would require more complex test discovery
        # For now, just run all tests
        return self.run_all_tests()


def main():
    """Main test runner"""
    runner = TestRunner()
    
    # Check if specific tests were requested
    if len(sys.argv) > 1:
        test_names = sys.argv[1:]
        success = runner.run_specific_tests(test_names)
    else:
        success = runner.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
