"""
Django management command to create default report templates.

Usage:
    python manage.py create_default_templates
    python manage.py create_default_templates --user-id 1
    python manage.py create_default_templates --overwrite
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from configapi.models import ReportTemplate, TemplateVersion
from django.utils import timezone

User = get_user_model()


class Command(BaseCommand):
    help = 'Create default report templates'

    def add_arguments(self, parser):
        parser.add_argument(
            '--user-id',
            type=int,
            help='User ID to set as created_by (default: first superuser)',
        )
        parser.add_argument(
            '--overwrite',
            action='store_true',
            help='Overwrite existing templates with same name',
        )

    def handle(self, *args, **options):
        user_id = options.get('user_id')
        overwrite = options.get('overwrite', False)

        if user_id:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'User with ID {user_id} not found'))
                return
        else:
            user = User.objects.filter(is_superuser=True).first()
            if not user:
                user = User.objects.filter(is_active=True).first()
                if not user:
                    self.stdout.write(self.style.ERROR('No users found. Please create a user first.'))
                    return

        self.stdout.write(self.style.SUCCESS(f'Creating default templates (created_by: {user.email})'))

        templates_data = [
            {
                'name': 'Executive Summary - HTML',
                'description': 'Professional executive summary template for HTML/PDF reports',
                'format': 'html',
                'category': 'executive',
                'content': '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{ mission.name }} - Executive Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary-box { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .metric { display: inline-block; margin: 10px 20px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
    </style>
</head>
<body>
    <h1>{{ mission.name }} - Executive Summary</h1>
    
    <div class="summary-box">
        <h2>Mission Overview</h2>
        <p><strong>Company:</strong> {{ mission.company }}</p>
        <p><strong>Entity:</strong> {{ mission.filial }}</p>
        <p><strong>Year:</strong> {{ mission.year }}</p>
        <p><strong>Status:</strong> {{ mission.status }}</p>
    </div>

    <h2>Key Metrics</h2>
    <div class="metric">
        <div class="metric-value">{{ total_findings }}</div>
        <div>Total Findings</div>
    </div>
    <div class="metric">
        <div class="metric-value">{{ total_scans }}</div>
        <div>Scans Performed</div>
    </div>

    <h2>Scope</h2>
    <ul>
        {% for item in scope %}
        <li>{{ item }}</li>
        {% endfor %}
    </ul>

    <h2>Scanners Used</h2>
    <ul>
        {% for scanner in scanners_used %}
        <li>{{ scanner }}</li>
        {% endfor %}
    </ul>

    <h2>Report Generated</h2>
    <p>Generated on: {{ generated_at }}</p>
</body>
</html>''',
                'variables_schema': {
                    'mission': {
                        'name': 'string',
                        'company': 'string',
                        'filial': 'string',
                        'year': 'number',
                        'status': 'string'
                    },
                    'total_findings': 'number',
                    'total_scans': 'number',
                    'scope': 'array',
                    'scanners_used': 'array',
                    'generated_at': 'string'
                },
                'is_public': True,
                'is_system_template': True
            },
            {
                'name': 'Technical Report - HTML',
                'description': 'Detailed technical report template with findings breakdown',
                'format': 'html',
                'category': 'technical',
                'content': '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{ mission.name }} - Technical Report</title>
    <style>
        body { font-family: 'Courier New', monospace; margin: 40px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; margin-top: 30px; }
        .finding { margin: 20px 0; padding: 15px; border-left: 4px solid #e74c3c; background: #f8f9fa; }
        .finding-title { font-weight: bold; font-size: 1.2em; }
        .finding-details { margin-top: 10px; }
        .severity-critical { border-left-color: #e74c3c; }
        .severity-high { border-left-color: #f39c12; }
        .severity-medium { border-left-color: #f1c40f; }
        .severity-low { border-left-color: #3498db; }
        code { background: #ecf0f1; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>{{ mission.name }} - Technical Security Report</h1>
    
    <h2>Mission Information</h2>
    <p><strong>Company:</strong> {{ mission.company }}</p>
    <p><strong>Entity:</strong> {{ mission.filial }}</p>
    <p><strong>Year:</strong> {{ mission.year }}</p>
    
    <h2>Scan Summary</h2>
    <p>Total Scans: {{ total_scans }}</p>
    <p>Scanners Used: {{ scanners_used|join:', ' }}</p>
    
    <h2>Findings</h2>
    {% if findings %}
        {% for finding in findings %}
        <div class="finding severity-{{ finding.severity|lower }}">
            <div class="finding-title">{{ finding.title }}</div>
            <div class="finding-details">
                <p><strong>Severity:</strong> {{ finding.severity }}</p>
                <p><strong>Description:</strong> {{ finding.description }}</p>
                {% if finding.recommendation %}
                <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    {% else %}
        <p>No findings reported.</p>
    {% endif %}
    
    <h2>Report Metadata</h2>
    <p>Generated: {{ generated_at }}</p>
</body>
</html>''',
                'variables_schema': {
                    'mission': 'object',
                    'findings': 'array',
                    'total_scans': 'number',
                    'scanners_used': 'array',
                    'generated_at': 'string'
                },
                'is_public': True,
                'is_system_template': True
            },
            {
                'name': 'Compliance Report - HTML',
                'description': 'Compliance-focused report template',
                'format': 'html',
                'category': 'compliance',
                'content': '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{ mission.name }} - Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #27ae60; }
        .compliance-item { margin: 15px 0; padding: 15px; background: #d5f4e6; border-radius: 5px; }
        .compliant { background: #d5f4e6; }
        .non-compliant { background: #fadbd8; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border: 1px solid #ddd; }
        th { background-color: #27ae60; color: white; }
    </style>
</head>
<body>
    <h1>{{ mission.name }} - Compliance Assessment Report</h1>
    
    <h2>Organization Information</h2>
    <p><strong>Company:</strong> {{ mission.company }}</p>
    <p><strong>Entity:</strong> {{ mission.filial }}</p>
    <p><strong>Assessment Year:</strong> {{ mission.year }}</p>
    
    <h2>Compliance Status</h2>
    <div class="compliance-item">
        <h3>Security Standards Compliance</h3>
        <p>This report documents compliance with security standards and best practices.</p>
    </div>
    
    <h2>Assessment Scope</h2>
    <ul>
        {% for item in scope %}
        <li>{{ item }}</li>
        {% endfor %}
    </ul>
    
    <h2>Report Date</h2>
    <p>{{ generated_at }}</p>
</body>
</html>''',
                'variables_schema': {
                    'mission': 'object',
                    'scope': 'array',
                    'generated_at': 'string'
                },
                'is_public': True,
                'is_system_template': True
            },
            {
                'name': 'Simple CSV Export',
                'description': 'Basic CSV template for data export',
                'format': 'csv',
                'category': 'custom',
                'content': '''Mission,Company,Entity,Year,Status,Total Findings,Total Scans
{{ mission.name }},{{ mission.company }},{{ mission.filial }},{{ mission.year }},{{ mission.status }},{{ total_findings }},{{ total_scans }}''',
                'variables_schema': {
                    'mission': 'object',
                    'total_findings': 'number',
                    'total_scans': 'number'
                },
                'is_public': True,
                'is_system_template': True
            }
        ]

        created_count = 0
        updated_count = 0

        for template_data in templates_data:
            name = template_data['name']
            
            existing = ReportTemplate.objects.filter(name=name).first()

            if existing and not overwrite:
                self.stdout.write(self.style.WARNING(f'Template "{name}" already exists. Skipping. Use --overwrite to replace.'))
                continue

            if existing and overwrite:
                # Update existing template
                for key, value in template_data.items():
                    if key not in ['name']:  # Don't update name
                        setattr(existing, key, value)
                existing.created_by = user
                existing.save()
                
                # Create new version
                TemplateVersion.objects.create(
                    template=existing,
                    version_number=existing.current_version + 1,
                    content=existing.content,
                    variables_schema=existing.variables_schema or {},
                    settings=existing.settings or {},
                    change_summary='Updated by create_default_templates command',
                    created_by=user
                )
                existing.current_version += 1
                existing.save()
                
                updated_count += 1
                self.stdout.write(self.style.SUCCESS(f'Updated template: {name}'))
            else:
                # Create new template
                template = ReportTemplate.objects.create(
                    name=name,
                    description=template_data['description'],
                    format=template_data['format'],
                    category=template_data['category'],
                    content=template_data['content'],
                    variables_schema=template_data.get('variables_schema', {}),
                    settings=template_data.get('settings', {}),
                    created_by=user,
                    is_public=template_data.get('is_public', False),
                    is_system_template=template_data.get('is_system_template', False),
                    is_active=True
                )
                
                # Create initial version
                TemplateVersion.objects.create(
                    template=template,
                    version_number=1,
                    content=template.content,
                    variables_schema=template.variables_schema or {},
                    settings=template.settings or {},
                    change_summary='Initial version - Default template',
                    created_by=user
                )
                
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f'Created template: {name}'))

        self.stdout.write(self.style.SUCCESS(
            f'\nCompleted! Created {created_count} templates, updated {updated_count} templates.'
        ))



