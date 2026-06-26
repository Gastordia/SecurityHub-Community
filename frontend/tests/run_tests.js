#!/usr/bin/env node
/**
 * Test runner script for frontend tests
 */
const { execSync } = require('child_process');
const path = require('path');

// Test configuration
const testConfig = {
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.js'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/index.tsx',
    '!src/serviceWorker.ts',
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70,
    },
  },
};

// Test files to run
const testFiles = [
  'test_advanced_vulnerability_search.test.tsx',
  'test_vulnerability_database_manager.test.tsx',
  'test_scanner_integration.test.tsx',
  'test_vulnerability_dashboard.test.tsx',
];

function runTests() {
  console.log('🧪 Running APTRS Frontend Tests...\n');
  
  try {
    // Run Jest tests
    const jestCommand = `npx jest --config=${JSON.stringify(testConfig)} --testPathPattern="(${testFiles.join('|')})" --verbose`;
    
    console.log('Running Jest tests...');
    execSync(jestCommand, { 
      stdio: 'inherit',
      cwd: path.resolve(__dirname, '..')
    });
    
    console.log('\n✅ All frontend tests passed!');
    return 0;
    
  } catch (error) {
    console.error('\n❌ Some frontend tests failed!');
    console.error('Error:', error.message);
    return 1;
  }
}

// Run tests if this script is executed directly
if (require.main === module) {
  const exitCode = runTests();
  process.exit(exitCode);
}

module.exports = { runTests, testConfig };
