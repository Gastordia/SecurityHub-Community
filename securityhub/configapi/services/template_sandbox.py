"""
Template Preview Sandbox - Generates fake data for template preview.
Provides isolated preview environment with fake projects, vulnerabilities, charts.
"""
import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta
import random

logger = logging.getLogger(__name__)


class SandboxDataGenerator:
    """
    Generates fake data for template preview.
    Provides standard datasets per report type.
    """
    
    def generate_fake_project(self, report_type: str = 'Audit') -> Dict[str, Any]:
        """
        Generate fake project data.
        
        Args:
            report_type: Type of report (Audit, Re-Audit)
        
        Returns:
            Dictionary with fake project data
        """
        project_names = [
            'Acme Corporation Security Assessment',
            'Global Tech Penetration Test',
            'Financial Services Audit',
            'Healthcare System Review',
            'E-commerce Platform Assessment'
        ]
        
        return {
            'id': random.randint(1000, 9999),
            'name': random.choice(project_names),
            'description': 'This is a sample security assessment project for template preview.',
            'start_date': (datetime.now() - timedelta(days=30)).isoformat(),
            'end_date': datetime.now().isoformat(),
            'status': 'Completed',
            'manager': {
                'name': 'John Security',
                'email': 'john.security@example.com',
            },
            'organization': {
                'name': 'Sample Organization',
                'domain': 'example.com'
            }
        }
    
    def generate_fake_vulnerabilities(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        Generate fake vulnerability data.
        
        Args:
            count: Number of vulnerabilities to generate
        
        Returns:
            List of vulnerability dictionaries
        """
        severities = ['Critical', 'High', 'Medium', 'Low', 'Informational']
        titles = [
            'SQL Injection Vulnerability',
            'Cross-Site Scripting (XSS)',
            'Insecure Direct Object Reference',
            'Security Misconfiguration',
            'Sensitive Data Exposure',
            'Missing Function Level Access Control',
            'Cross-Site Request Forgery (CSRF)',
            'Using Components with Known Vulnerabilities',
            'Unvalidated Redirects and Forwards',
            'Weak Authentication'
        ]
        
        descriptions = [
            'The application is vulnerable to SQL injection attacks.',
            'User input is not properly sanitized before rendering.',
            'Direct object references are not properly protected.',
            'Security settings are not properly configured.',
            'Sensitive data is exposed in transit or at rest.',
            'Access controls are not enforced at the function level.',
            'The application does not properly validate CSRF tokens.',
            'Outdated components with known vulnerabilities are in use.',
            'Redirects and forwards are not properly validated.',
            'Authentication mechanisms are weak or improperly implemented.'
        ]
        
        vulnerabilities = []
        for i in range(count):
            severity = random.choice(severities)
            title_idx = i % len(titles)
            
            vuln = {
                'id': i + 1,
                'title': titles[title_idx],
                'description': descriptions[title_idx],
                'severity': severity,
                'cvssscore': self._get_cvss_for_severity(severity),
                'status': 'Vulnerable',
                'discovered_date': (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat(),
                'category': random.choice(['Web Application', 'Network', 'Infrastructure', 'Mobile']),
                'affected_systems': [f'system-{j}' for j in range(random.randint(1, 3))],
                'remediation': f'Apply security patch and implement proper input validation for {titles[title_idx]}.'
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_cvss_for_severity(self, severity: str) -> float:
        """Get CVSS score for severity level."""
        scores = {
            'Critical': random.uniform(9.0, 10.0),
            'High': random.uniform(7.0, 8.9),
            'Medium': random.uniform(4.0, 6.9),
            'Low': random.uniform(0.1, 3.9),
            'Informational': 0.0
        }
        return round(scores.get(severity, 5.0), 1)
    
    def generate_fake_instances(self, vuln_count: int = 10) -> List[Dict[str, Any]]:
        """
        Generate fake vulnerable instance data.
        
        Args:
            vuln_count: Number of vulnerabilities to generate instances for
        
        Returns:
            List of instance dictionaries
        """
        instances = []
        for i in range(vuln_count):
            instance = {
                'id': i + 1,
                'vulnerability_id': i + 1,
                'url': f'https://example.com/vulnerable-endpoint-{i}',
                'parameter': random.choice(['id', 'username', 'email', 'token']),
                'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                'evidence': f'Sample evidence for vulnerability {i + 1}',
                'discovered_at': (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat()
            }
            instances.append(instance)
        
        return instances
    
    def generate_fake_charts(self) -> Dict[str, Any]:
        """
        Generate fake chart data for template preview.
        
        Returns:
            Dictionary with chart data structures
        """
        from datetime import datetime, timedelta
        import random
        
        # Severity distribution
        severity_counts = {
            'Critical': random.randint(1, 5),
            'High': random.randint(5, 15),
            'Medium': random.randint(10, 25),
            'Low': random.randint(15, 30),
            'Info': random.randint(5, 15)
        }
        
        # Timeline data
        timeline = []
        current_date = datetime.now() - timedelta(days=30)
        for _ in range(30):
            timeline.append({
                'date': current_date.strftime('%Y-%m-%d'),
                'count': random.randint(0, 10)
            })
            current_date += timedelta(days=1)
        
        # Top categories
        categories = ['SQL Injection', 'XSS', 'CSRF', 'Authentication Bypass', 'Privilege Escalation']
        category_counts = {cat: random.randint(5, 20) for cat in categories}
        
        return {
            'severity_distribution': {
                'labels': list(severity_counts.keys()),
                'data': list(severity_counts.values())
            },
            'vulnerability_timeline': timeline,
            'top_categories': category_counts
        }
    
    def generate_complete_context(self, report_type: str = 'Audit') -> Dict[str, Any]:
        """
        Generate complete standardized fake context for template preview.
        Provides consistent data structure across all preview sessions.
        
        Args:
            report_type: Type of report
        
        Returns:
            Complete context dictionary matching real report structure
        """
        # Standardized: Always generate exactly 10 findings
        vulnerabilities = self.generate_fake_vulnerabilities(10)
        instances = self.generate_fake_instances(10)
        charts = self.generate_fake_charts()
        project = self.generate_fake_project(report_type)
        
        # Count by severity (standardized distribution)
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Standardized timeline data (30 days)
        timeline_data = []
        from datetime import datetime, timedelta
        current_date = datetime.now() - timedelta(days=30)
        for i in range(30):
            timeline_data.append({
                'date': current_date.strftime('%Y-%m-%d'),
                'new_findings': random.randint(0, 3),
                'closed_findings': random.randint(0, 2),
                'total_open': random.randint(5, 15)
            })
            current_date += timedelta(days=1)
        
        # Standardized categories
        categories = [
            {'name': 'SQL Injection', 'count': severity_counts.get('Critical', 0) + 1},
            {'name': 'Cross-Site Scripting (XSS)', 'count': severity_counts.get('High', 0) + 1},
            {'name': 'Authentication Bypass', 'count': severity_counts.get('High', 0)},
            {'name': 'Insecure Direct Object Reference', 'count': severity_counts.get('Medium', 0) + 1},
            {'name': 'Security Misconfiguration', 'count': severity_counts.get('Medium', 0)},
            {'name': 'Sensitive Data Exposure', 'count': severity_counts.get('Low', 0) + 1},
            {'name': 'Missing Access Control', 'count': severity_counts.get('Low', 0)},
            {'name': 'CSRF', 'count': severity_counts.get('Informational', 0) + 1}
        ]
        
        # Reusable severity distribution (standardized)
        severity_distribution = {
            'labels': ['Critical', 'High', 'Medium', 'Low', 'Informational'],
            'data': [
                severity_counts.get('Critical', 0),
                severity_counts.get('High', 0),
                severity_counts.get('Medium', 0),
                severity_counts.get('Low', 0),
                severity_counts.get('Informational', 0)
            ],
            'colors': ['#FF491C', '#F66E09', '#FBBC02', '#20B803', '#3399FF']
        }
        
        context = {
            'project': project,
            'findings': vulnerabilities,  # Standardized name
            'vuln': vulnerabilities,  # Legacy support
            'instances': instances,
            'totalvulnerability': len(vulnerabilities),
            'total_findings': len(vulnerabilities),  # Standardized name
            'critical': severity_counts.get('Critical', 0),
            'high': severity_counts.get('High', 0),
            'medium': severity_counts.get('Medium', 0),
            'low': severity_counts.get('Low', 0),
            'info': severity_counts.get('Informational', 0),
            'informational': severity_counts.get('Informational', 0),  # Standardized name
            'standard': 'NIST',
            'Report_type': report_type,
            'report_type': report_type,  # Standardized name
            'mycomany': 'Security Assessment Company',
            'company': 'Security Assessment Company',  # Standardized name
            'projectscope': [
                {'name': 'Web Application', 'description': 'Main web application'},
                {'name': 'API Endpoints', 'description': 'REST API services'},
                {'name': 'Database', 'description': 'Database systems'}
            ],
            'scope': [  # Standardized name
                'Web Application',
                'API Endpoints',
                'Database Systems'
            ],
            'totalretest': [],
            'projectmanagers': [
                {'name': 'John Security', 'email': 'john@example.com'},
                {'name': 'Jane Analyst', 'email': 'jane@example.com'}
            ],
            'customeruser': [],
            'charts': charts,
            'pie_chart': charts.get('pie_chart', ''),  # Legacy support
            # Standardized chart data
            'severity_distribution': severity_distribution,
            'vulnerability_timeline': timeline_data,
            'top_categories': categories,
            'report_date': datetime.now().strftime('%Y-%m-%d'),
            'generated_at': datetime.now().isoformat()
        }
        
        return context

