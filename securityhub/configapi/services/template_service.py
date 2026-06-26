"""
Unified template service for rendering, validation, and preview.
Central service for all template operations.
"""
import logging
from typing import Dict, Any, Optional
from django.core.cache import cache
from django.utils import timezone
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import TemplateSyntaxError
from .template_validator import TemplateValidator, ValidationResult
from ..models import ReportTemplate
import hashlib
import json

logger = logging.getLogger(__name__)


class TemplateServiceError(Exception):
    """Base exception for template service errors"""
    pass


class TemplateNotFoundError(TemplateServiceError):
    """Template not found"""
    pass


class TemplateRenderError(TemplateServiceError):
    """Error rendering template"""
    pass


class TemplateService:
    """
    Unified service for template operations.
    Handles rendering, validation, preview, and caching.
    """
    
    def __init__(self, enable_cache: bool = True, cache_timeout: int = 3600):
        """
        Initialize template service.
        
        Args:
            enable_cache: Enable template caching
            cache_timeout: Cache timeout in seconds (default 1 hour)
        """
        self.enable_cache = enable_cache
        self.cache_timeout = cache_timeout
        self.validator = TemplateValidator()
        
        # Create Jinja2 environment with security settings
        self.jinja_env = SandboxedEnvironment(
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
    
    def render_template(
        self,
        template_id: int,
        context: Dict[str, Any],
        format: Optional[str] = None,
        validate: bool = True,
        track_usage: bool = True,
        user=None,
        project=None
    ) -> str:
        """
        Render a template with the given context.
        
        Args:
            template_id: ID of the template to render
            context: Context data for template rendering
            format: Optional format override (uses template format if not provided)
            validate: Whether to validate template before rendering
            track_usage: Whether to track template usage
            user: User object for usage tracking
            project: Project object for usage tracking
        
        Returns:
            Rendered template content as string
        
        Raises:
            TemplateNotFoundError: If template not found
            TemplateRenderError: If rendering fails
        """
        try:
            # Get template
            try:
                template = ReportTemplate.objects.get(id=template_id, is_active=True)
            except ReportTemplate.DoesNotExist:
                raise TemplateNotFoundError(f"Template with id {template_id} not found or not active")
            
            # Use template format if not overridden
            if format is None:
                format = template.format
            
            # Validate template if requested
            if validate:
                validation = self.validator.validate_template_object(template)
                if not validation.is_valid:
                    error_messages = [e.message for e in validation.errors]
                    raise TemplateRenderError(
                        f"Template validation failed: {'; '.join(error_messages)}"
                    )
            
            # Check cache
            cache_key = self._get_cache_key(template_id, context, format)
            if self.enable_cache:
                cached_result = cache.get(cache_key)
                if cached_result:
                    logger.debug(f"Cache hit for template {template_id}")
                    return cached_result
            
            # Render template
            try:
                jinja_template = self.jinja_env.from_string(template.content)
                rendered_content = jinja_template.render(**context)
            except TemplateSyntaxError as e:
                raise TemplateRenderError(f"Template syntax error: {str(e)} (line {e.lineno})")
            except Exception as e:
                logger.error(f"Error rendering template {template_id}: {str(e)}", exc_info=True)
                raise TemplateRenderError(f"Error rendering template: {str(e)}")
            
            # Cache result
            if self.enable_cache:
                cache.set(cache_key, rendered_content, self.cache_timeout)
                logger.debug(f"Cached rendered template {template_id}")
            
            # Track usage
            if track_usage:
                self._track_usage(template, format, user, project)
            
            return rendered_content
            
        except (TemplateNotFoundError, TemplateRenderError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error in render_template: {str(e)}", exc_info=True)
            raise TemplateRenderError(f"Unexpected error: {str(e)}")
    
    def validate_template(self, template_id: int) -> ValidationResult:
        """
        Validate a template.
        
        Args:
            template_id: ID of the template to validate
        
        Returns:
            ValidationResult with errors and warnings
        
        Raises:
            TemplateNotFoundError: If template not found
        """
        try:
            template = ReportTemplate.objects.get(id=template_id)
            return self.validator.validate_template_object(template)
        except ReportTemplate.DoesNotExist:
            raise TemplateNotFoundError(f"Template with id {template_id} not found")
    
    def validate_template_content(
        self,
        content: str,
        variables_schema: Dict[str, Any] = None,
        format: str = 'html'
    ) -> ValidationResult:
        """
        Validate template content directly (without database lookup).
        
        Args:
            content: Template content to validate
            variables_schema: Optional variable schema
            format: Template format
        
        Returns:
            ValidationResult
        """
        return self.validator.validate(content, variables_schema, format)
    
    def preview_template(
        self,
        template_id: int,
        sample_data: Optional[Dict[str, Any]] = None,
        project_id: Optional[int] = None
    ) -> str:
        """
        Preview a template with sample or real data.

        Args:
            template_id: ID of the template to preview
            sample_data: Optional sample data to use
            project_id: Optional project ID to load real data

        Returns:
            Rendered preview content

        Raises:
            TemplateNotFoundError: If template not found
            TemplateRenderError: If rendering fails
        """
        try:
            template = ReportTemplate.objects.get(id=template_id, is_active=True)

            # Generate or load context data
            if sample_data:
                context = sample_data
            elif project_id:
                # Load real project data
                context = self._prepare_project_context(project_id)
            else:
                # Generate sample data based on template schema
                context = self._generate_sample_data(template)
            
            # Render without caching and without tracking usage
            return self.render_template(
                template_id=template_id,
                context=context,
                validate=True,
                track_usage=False
            )
            
        except ReportTemplate.DoesNotExist:
            raise TemplateNotFoundError(f"Template with id {template_id} not found")
        except Exception as e:
            logger.error(f"Error previewing template {template_id}: {str(e)}", exc_info=True)
            raise TemplateRenderError(f"Error previewing template: {str(e)}")
    
    def _prepare_project_context(self, project_id: int) -> Dict[str, Any]:
        """
        Prepare context data from a project.
        This should match the data structure used in project/report.py
        """
        from project.models import Project, Vulnerability, VulnerableInstance, ProjectScope
        from accounts.models import CustomUser
        import pygal
        from pygal.style import Style
        
        try:
            project = Project.objects.get(id=project_id)
            
            # Get vulnerabilities
            vuln = Vulnerability.objects.filter(project=project).order_by('-cvssscore')
            instances = VulnerableInstance.objects.filter(project=project)
            
            # Count by severity
            critical = vuln.filter(vulnerabilityseverity='Critical', status='Vulnerable').count()
            high = vuln.filter(vulnerabilityseverity='High', status='Vulnerable').count()
            medium = vuln.filter(vulnerabilityseverity='Medium', status='Vulnerable').count()
            low = vuln.filter(vulnerabilityseverity='Low', status='Vulnerable').count()
            info = vuln.filter(
                status='Vulnerable',
                vulnerabilityseverity__in=['Informational', 'None']
            ).count()
            
            # Create pie chart
            custom_style = Style(
                colors=("#FF491C", "#F66E09", "#FBBC02", "#20B803", "#3399FF"),
                background='transparent',
                plot_background='transparent',
                legend_font_size=0,
                legend_box_size=0,
                value_font_size=40
            )
            pie_chart = pygal.Pie(style=custom_style)
            pie_chart.legend_box_size = 0
            pie_chart.add('Critical', critical)
            pie_chart.add('High', high)
            pie_chart.add('Medium', medium)
            pie_chart.add('Low', low)
            pie_chart.add('Informational', info)
            
            # Get other data
            totalvulnerability = vuln.count()
            mycompany = None
            projectscope = ProjectScope.objects.filter(project=project)
            totalretest = []

            from project.services.project_contacts import get_project_manager_queryset
            projectmanagers = get_project_manager_queryset(project)
            customeruser = CustomUser.objects.none()
            
            # Build context (matching project/report.py structure)
            context = {
                'projectscope': projectscope,
                'totalvulnerability': totalvulnerability,
                'standard': 'NIST',  # Default, should be passed
                'Report_type': 'Audit',  # Default, should be passed
                'mycomany': mycompany,
                'totalretest': totalretest,
                'vuln': vuln,
                'project': project,
                'ciritcal': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'info': info,
                'instances': instances,
                'projectmanagers': projectmanagers,
                'customeruser': customeruser,
                'pie_chart': pie_chart.render(is_unicode=True)
            }
            
            return context
            
        except Exception as e:
            logger.error(f"Error preparing project context: {str(e)}", exc_info=True)
            # Return minimal context on error
            return self._generate_sample_data(None)
    
    def _generate_sample_data(self, template: Optional[ReportTemplate] = None) -> Dict[str, Any]:
        """
        Generate sample data for template preview.
        Uses variables_schema if available, otherwise uses defaults.
        """
        if template and template.variables_schema:
            sample_data = {}
            for var_name, var_spec in template.variables_schema.items():
                if isinstance(var_spec, dict):
                    var_type = var_spec.get('type', 'string')
                    default = var_spec.get('default', None)
                    
                    if default is not None:
                        sample_data[var_name] = default
                    elif var_type == 'number':
                        sample_data[var_name] = 0
                    elif var_type == 'boolean':
                        sample_data[var_name] = False
                    elif var_type == 'array':
                        sample_data[var_name] = []
                    elif var_type == 'object':
                        sample_data[var_name] = {}
                    else:
                        sample_data[var_name] = f'Sample {var_name}'
                else:
                    sample_data[var_name] = f'Sample {var_name}'
            
            return sample_data
        
        # Default sample data
        return {
            'project': {
                'name': 'Sample Security Assessment',
                'id': 1,
                'description': 'This is a sample project for template preview'
            },
            'totalvulnerability': 42,
            'ciritcal': 5,
            'high': 12,
            'medium': 15,
            'low': 8,
            'info': 2,
            'standard': 'NIST',
            'Report_type': 'Audit',
            'mycomany': 'Security Company',
            'projectscope': [],
            'totalretest': [],
            'vuln': [
                {
                    'title': 'SQL Injection Vulnerability',
                    'severity': 'Critical',
                    'description': 'Sample vulnerability description',
                    'cvssscore': 9.8
                }
            ],
            'instances': [],
            'projectmanagers': [],
            'customeruser': [],
            'pie_chart': '<svg>Sample Chart</svg>'
        }
    
    def _get_cache_key(self, template_id: int, context: Dict[str, Any], format: str) -> str:
        """Generate cache key for template rendering"""
        # Create hash of context to ensure cache key uniqueness
        context_str = json.dumps(context, sort_keys=True, default=str)
        context_hash = hashlib.md5(context_str.encode()).hexdigest()[:8]
        return f'template:render:{template_id}:{format}:{context_hash}'
    
    def _track_usage(
        self,
        template: ReportTemplate,
        format: str,
        user=None,
        project=None
    ):
        """Track template usage"""
        try:
            template.usage_count += 1
            template.last_used_at = timezone.now()
            template.save(update_fields=['usage_count', 'last_used_at'])
        except Exception as e:
            # Don't fail rendering if usage tracking fails
            logger.warning(f"Failed to track template usage: {str(e)}")
