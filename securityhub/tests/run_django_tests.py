"""
Django test runner for migrated services
Properly configures Django settings and runs full test suite
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

# Now import Django test modules
from django.test import TestCase
from django.test.utils import get_runner


class DjangoTestRunner:
    """Django test runner for migrated services"""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = None
        self.end_time = None
    
    def run_all_tests(self):
        """Run all Django tests"""
        print("🧪 Starting Django Migrated Services Test Suite")
        print("=" * 60)
        
        self.start_time = datetime.now()
        
        # Test suites to run
        test_suites = [
            'test_parser_service_migrated',
            'test_asset_intelligence_service_migrated',
            'test_intelligence_engine_migrated',
            'test_service_integration_migrated'
        ]
        
        total_tests = 0
        total_failures = 0
        total_errors = 0
        
        for suite_name in test_suites:
            print(f"\n🔍 Running {suite_name}...")
            print("-" * 40)
            
            try:
                # Import and run the test module
                test_module = __import__(suite_name, fromlist=[''])
                
                # Create test suite
                loader = unittest.TestLoader()
                suite = loader.loadTestsFromModule(test_module)
                
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
                    
            except Exception as e:
                print(f"❌ {suite_name}: ERROR - {e}")
                self.test_results[suite_name] = {
                    'tests_run': 0,
                    'failures': 0,
                    'errors': 1,
                    'success': False
                }
                total_errors += 1
        
        self.end_time = datetime.now()
        
        # Print overall results
        self.print_summary(total_tests, total_failures, total_errors)
        
        return total_failures == 0 and total_errors == 0
    
    def print_summary(self, total_tests, total_failures, total_errors):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 DJANGO MIGRATED SERVICES TEST SUMMARY")
        print("=" * 60)
        
        duration = (self.end_time - self.start_time).total_seconds()
        
        print(f"⏱️  Total Duration: {duration:.2f} seconds")
        print(f"🧪 Total Tests: {total_tests}")
        print(f"✅ Passed: {total_tests - total_failures - total_errors}")
        print(f"❌ Failed: {total_failures}")
        print(f"💥 Errors: {total_errors}")
        
        if total_failures == 0 and total_errors == 0:
            print("\n🎉 ALL DJANGO TESTS PASSED! Migrated services are working correctly.")
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


def main():
    """Main test runner"""
    runner = DjangoTestRunner()
    success = runner.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()






