#!/bin/bash
# Script to update embedded JSON data in api-data.js

cd "$(dirname "$0")/.."

if [ ! -f "api-reference.json" ]; then
    echo "Error: api-reference.json not found in parent directory"
    exit 1
fi

python3 << 'PYTHON'
import json

# Read the JSON file
with open('api-reference.json', 'r') as f:
    data = json.load(f)

# Create a JavaScript file that embeds the JSON
js_content = f"// Embedded API Reference Data\n// Auto-generated from api-reference.json\n// Do not edit manually - run update-data.sh to regenerate\n\nwindow.API_REFERENCE_DATA = {json.dumps(data, indent=2)};\n"

# Write to frontend directory
with open('frontend/api-data.js', 'w') as f:
    f.write(js_content)

print("✅ Updated api-data.js with latest JSON data")
print(f"   Size: {len(js_content)} bytes")
PYTHON










