#!/bin/bash

# Quick Verification Script for Intelligence Dashboard Implementation
# This script checks if all required files exist

echo "🔍 Verifying Intelligence Dashboard Implementation..."
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track results
PASSED=0
FAILED=0

# Function to check file
check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✅${NC} $1"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}❌${NC} $1 (MISSING)"
        ((FAILED++))
        return 1
    fi
}

# Function to check directory
check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✅${NC} $1/"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}❌${NC} $1/ (MISSING)"
        ((FAILED++))
        return 1
    fi
}

echo "📁 Checking Core Files..."
echo ""

# Core files
check_file "src/services/intelligence-api.ts"
check_file "src/hooks/useIntelligenceDashboard.ts"
check_file "src/pages/intelligence-dashboard-new.tsx"

echo ""
echo "📁 Checking Intelligence Components..."
echo ""

# Intelligence components directory
check_dir "src/components/intelligence"

# Phase 1.1: Intelligence Dashboard Foundation
echo ""
echo "Phase 1.1: Intelligence Dashboard Foundation"
check_file "src/components/intelligence/dashboard-layout.tsx"
check_file "src/components/intelligence/dashboard-nav.tsx"
check_file "src/components/intelligence/fusion-metrics-cards.tsx"

# Phase 1.2: Asset Intelligence Dashboard
echo ""
echo "Phase 1.2: Asset Intelligence Dashboard"
check_file "src/components/intelligence/asset-intelligence-dashboard.tsx"
check_file "src/components/intelligence/asset-intelligence-card.tsx"
check_file "src/components/intelligence/asset-risk-matrix.tsx"

# Phase 1.3: Threat Intelligence Dashboard
echo ""
echo "Phase 1.3: Threat Intelligence Dashboard"
check_file "src/components/intelligence/threat-intelligence-dashboard.tsx"
check_file "src/components/intelligence/threat-list.tsx"
check_file "src/components/intelligence/threat-detail-modal.tsx"
check_file "src/components/intelligence/ioc-management.tsx"

# Phase 2.1: Correlation Dashboard
echo ""
echo "Phase 2.1: Correlation Dashboard"
check_file "src/components/intelligence/correlation-dashboard.tsx"
check_file "src/components/intelligence/correlation-analysis.tsx"
check_file "src/components/intelligence/correlation-results.tsx"

echo ""
echo "📊 Summary:"
echo -e "${GREEN}✅ Passed: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}❌ Failed: $FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}🎉 All files verified!${NC}"
    exit 0
fi

