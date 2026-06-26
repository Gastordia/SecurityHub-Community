#!/usr/bin/env python3
"""
Test script for the parser service
"""

import os
import sys
import django

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securityhub.settings')
django.setup()

from utils.services.parser_service import ParserService

def test_parser_service():
    """Test the parser service functionality"""
    print("Testing Parser Service...")
    
    # Initialize the service
    service = ParserService()
    
    # Test getting supported scanners
    print("\n1. Testing supported scanners...")
    scanners = service.get_supported_scanners()
    print(f"Found {len(scanners)} supported scanners:")
    for scanner in scanners:
        print(f"  - {scanner['name']} ({scanner['type']}) - {', '.join(scanner['supported_formats'])}")
    
    print("\n✅ Parser service test completed successfully!")

if __name__ == "__main__":
    test_parser_service()
