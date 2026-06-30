#!/usr/bin/env python3
"""
Test runner script for SecurityHub tests
"""
import os
import sys
import django
from django.conf import settings
from django.test.utils import get_runner

def run_tests():
    """Run all tests with proper configuration"""
    
    # Get the project root (parent of securityhub directory)
    current_dir = os.path.dirname(os.path.abspath(__file__))  # securityhub/tests/
    project_root = os.path.dirname(current_dir)  # securityhub/
    root_dir = os.path.dirname(project_root)  # /home/root/
    
    # Add both the project root and the root directory to Python path
    sys.path.insert(0, project_root)
    sys.path.insert(0, root_dir)
    
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securityhub.settings_test')
    
    # Configure Django
    django.setup()
    
    # Get test runner
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    
    # Run tests
    failures = test_runner.run_tests([
        'tests.test_vulnerability_enhancements',
        'tests.test_project_enhancements', 
        'tests.test_api_integration',
        'vulnerability.tests',
        'project.tests'
    ])
    
    return failures

if __name__ == '__main__':
    failures = run_tests()
    sys.exit(bool(failures))
