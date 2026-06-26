#!/usr/bin/env python3
"""
Parse the markdown documentation and generate data.js file
"""
import re
import json
import sys
from pathlib import Path

def parse_markdown_file(md_path):
    """Parse the markdown documentation file"""
    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    endpoints = []
    current_category = None
    current_endpoint = None
    
    lines = content.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        # Check for category headers (## 1. Core Vulnerability DB Endpoints)
        category_match = re.match(r'^## (\d+)\.\s+(.+)$', line)
        if category_match:
            category_num = category_match.group(1)
            category_name = category_match.group(2)
            current_category = {
                'num': category_num,
                'name': category_name,
                'key': get_category_key(category_name)
            }
            i += 1
            continue
        
        # Check for endpoint headers (### 1.1 `Vulndbfilter` (ViewSet))
        endpoint_match = re.match(r'^### (\d+\.\d+)\s+`(.+?)`\s*\((.+?)\)', line)
        if endpoint_match:
            if current_endpoint:
                endpoints.append(current_endpoint)
            
            endpoint_num = endpoint_match.group(1)
            endpoint_name = endpoint_match.group(2)
            endpoint_type = endpoint_match.group(3)
            
            current_endpoint = {
                'id': f"{current_category['key']}_{endpoint_num.replace('.', '_')}",
                'number': endpoint_num,
                'name': endpoint_name,
                'type': endpoint_type,
                'category': current_category['key'],
                'path': '',
                'method': '',
                'capability': '',
                'description': '',
                'howItWorks': [],
                'dependencies': [],
                'status': '',
                'issues': []
            }
            i += 1
            continue
        
        # Parse endpoint details
        if current_endpoint:
            # Endpoint path
            if line.startswith('**Endpoint**:'):
                match = re.search(r'`([A-Z]+)\s+(.+)`', line)
                if match:
                    current_endpoint['method'] = match.group(1)
                    current_endpoint['path'] = match.group(2)
            
            # Capability
            elif line.startswith('**Capability**:'):
                current_endpoint['capability'] = line.replace('**Capability**:', '').strip()
            
            # Method
            elif line.startswith('**Method**:'):
                current_endpoint['type'] = line.replace('**Method**:', '').strip()
            
            # What it does
            elif line.startswith('**What it does:**'):
                i += 1
                description_lines = []
                while i < len(lines) and not lines[i].strip().startswith('**'):
                    if lines[i].strip() and not lines[i].strip().startswith('-'):
                        description_lines.append(lines[i].strip())
                    elif lines[i].strip().startswith('-'):
                        description_lines.append(lines[i].strip()[2:])
                    i += 1
                current_endpoint['description'] = ' '.join(description_lines)
                continue
            
            # How it works
            elif line.startswith('**How it works:**'):
                i += 1
                steps = []
                while i < len(lines) and not lines[i].strip().startswith('**'):
                    step_match = re.match(r'^(\d+)\.\s+(.+)$', lines[i].strip())
                    if step_match:
                        steps.append(step_match.group(2))
                    i += 1
                current_endpoint['howItWorks'] = steps
                continue
            
            # Dependencies
            elif line.startswith('**Dependencies:**'):
                i += 1
                deps = []
                while i < len(lines) and not lines[i].strip().startswith('**'):
                    dep_match = re.match(r'^- (.+?):\s*(.+)$', lines[i].strip())
                    if dep_match:
                        dep_type = dep_match.group(1).lower()
                        dep_name = dep_match.group(2).strip()
                        deps.append({
                            'type': dep_type,
                            'name': dep_name
                        })
                    i += 1
                current_endpoint['dependencies'] = deps
                continue
            
            # Functionality Status
            elif line.startswith('**Functionality Status:**'):
                i += 1
                status_lines = []
                issues = []
                while i < len(lines) and not lines[i].strip().startswith('---') and not lines[i].strip().startswith('##'):
                    status_line = lines[i].strip()
                    if status_line:
                        if status_line.startswith('- ✅'):
                            status_lines.append(status_line[2:].strip())
                        elif status_line.startswith('- ⚠️'):
                            issue_text = status_line[2:].strip()
                            if '**ISSUE**' in issue_text or '**LIMITATION**' in issue_text or '**DEPENDENCY**' in issue_text:
                                issue_type = 'ISSUE' if '**ISSUE**' in issue_text else 'LIMITATION' if '**LIMITATION**' in issue_text else 'DEPENDENCY'
                                issue_msg = re.sub(r'\*\*.*?\*\*:', '', issue_text).strip()
                                issues.append({
                                    'type': issue_type,
                                    'message': issue_msg
                                })
                            status_lines.append(issue_text)
                        elif status_line.startswith('- ❌'):
                            status_lines.append(status_line[2:].strip())
                    i += 1
                current_endpoint['status'] = ' '.join(status_lines)
                current_endpoint['issues'] = issues
                continue
        
        i += 1
    
    # Add last endpoint
    if current_endpoint:
        endpoints.append(current_endpoint)
    
    return endpoints

def get_category_key(category_name):
    """Convert category name to key"""
    mapping = {
        'Core Vulnerability DB Endpoints': 'core',
        'Upload & Parser Endpoints': 'upload',
        'Asset Intelligence Endpoints': 'asset',
        'Threat Intelligence Endpoints': 'threat',
        'Correlation Engine Endpoints': 'correlation',
        'Dynamic Profiling Endpoints': 'profiling',
        'Intelligence Fusion Endpoints': 'fusion',
        'Enhanced Intelligence Endpoints': 'intelligence'
    }
    return mapping.get(category_name, 'other')

def generate_data_js(endpoints):
    """Generate the data.js file"""
    js_content = f"// Auto-generated endpoint data\n"
    js_content += f"const ENDPOINT_DATA = {json.dumps(endpoints, indent=2)};\n"
    return js_content

def main():
    # Get the markdown file path
    md_file = Path(__file__).parent.parent / 'vuln_endpoints_doc.md'
    
    if not md_file.exists():
        print(f"Error: {md_file} not found")
        sys.exit(1)
    
    print(f"Parsing {md_file}...")
    endpoints = parse_markdown_file(md_file)
    
    print(f"Found {len(endpoints)} endpoints")
    
    # Generate data.js
    js_content = generate_data_js(endpoints)
    js_file = Path(__file__).parent / 'data.js'
    
    with open(js_file, 'w', encoding='utf-8') as f:
        f.write(js_content)
    
    print(f"Generated {js_file}")

if __name__ == '__main__':
    main()

