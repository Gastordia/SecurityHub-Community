"""
Template Engine - Main facade/service that coordinates all template operations.
Single entry point for template rendering, validation, preview, and management.
"""
import logging
from typing import Dict, Any, Optional, Union
from .template_repository import TemplateRepository
from .template_validator import TemplateValidator, ValidationResult
from .context_adapter import ContextAdapter
from .renderer import Renderer, TemplateRenderError, RenderTimeoutError
from .exporter import Exporter
from .template_cache import TemplateCache
from .template_sandbox import SandboxDataGenerator
from ..models import ReportTemplate

logger = logging.getLogger(__name__)


class TemplateEngineError(Exception):
    """Base exception for template engine errors."""
    pass


class TemplateNotFoundError(TemplateEngineError):
    """Template not found."""
    pass


class TemplateValidationError(TemplateEngineError):
    """Template validation failed."""
    pass


class TemplateEngine:
    """
    Main template engine facade.
    Coordinates repository, validator, adapter, renderer, exporter, and cache.
    """
    
    def __init__(
        self,
        enable_cache: bool = True,
        cache_timeout: int = 3600,
        autoescape: bool = True,
    ):
        """
        Initialize template engine with all components.

        Args:
            enable_cache: Enable template caching
            cache_timeout: Cache timeout in seconds
            autoescape: Enable auto-escaping in templates
        """
        settings = self._get_default_settings()

        self.repository = TemplateRepository()
        self.validator = TemplateValidator()
        self.context_adapter = ContextAdapter()

        self.renderer = Renderer(
            autoescape=autoescape,
            enable_loader=settings.get('allow_inheritance', True),
            render_timeout=settings.get('render_timeout', 30),
        )

        self.exporter = Exporter()
        self.cache = TemplateCache(default_timeout=settings.get('cache_timeout', cache_timeout))
        self.enable_cache = settings.get('enable_cache', enable_cache) if settings else enable_cache

        # Store settings for validation
        self.settings = settings
    
    def _get_default_settings(self) -> Dict[str, Any]:
        """Get default template settings."""
        return {
            'allow_custom_filters': False,
            'max_loop_depth': 3,
            'max_range_size': 1000,
            'render_timeout': 30,
            'allow_inheritance': True,
            'allow_components': True,
            'strict_validation': True,
            'require_schema': False,
            'enable_cache': True,
            'cache_timeout': 3600,
        }
    
    def render(
        self,
        template_id: int,
        report_data: Dict[str, Any],
        format: str = "html",
        validate: bool = True,
        user=None,
        project=None,
        base_url: Optional[str] = None
    ) -> Union[str, bytes]:
        """
        Render a template with report data.

        Args:
            template_id: Template ID
            report_data: Report data from domain services
            format: Output format (html, pdf, docx, csv)
            validate: Whether to validate template before rendering
            user: User for usage tracking
            project: Project for usage tracking
            base_url: Base URL for PDF generation

        Returns:
            Rendered output (string for HTML/CSV, bytes for PDF/DOCX)

        Raises:
            TemplateNotFoundError: If template not found
            TemplateValidationError: If validation fails
            TemplateRenderError: If rendering fails
        """
        try:
            template = self.repository.get_template(template_id)

            if validate:
                validation = self.validator.validate_template_object(template)
                if not validation.is_valid:
                    error_messages = [e.message for e in validation.errors]
                    raise TemplateValidationError(
                        f"Template validation failed: {'; '.join(error_messages)}"
                    )

            context = self.context_adapter.adapt(
                report_data,
                template.variables_schema or {}
            )

            cache_key = None
            if self.enable_cache:
                cache_key = self.cache.build_key(
                    template_id,
                    context,
                    format,
                    version_id=template.current_version
                )
                cached = self.cache.get(cache_key)
                if cached:
                    logger.debug(f"Cache hit for template {template_id}")
                    return cached

            html = self.renderer.render(template.content, context)
            output = self.exporter.export(html, format, base_url=base_url)

            if self.enable_cache and cache_key:
                self.cache.set(cache_key, output)
                self.cache.register_key(template_id, cache_key)

            return output

        except ReportTemplate.DoesNotExist:
            raise TemplateNotFoundError(f"Template with id {template_id} not found")
        except (TemplateValidationError, TemplateRenderError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error in render: {str(e)}", exc_info=True)
            raise TemplateEngineError(f"Error rendering template: {str(e)}") from e
    
    def preview(
        self,
        template_id: int,
        sample_data: Optional[Dict[str, Any]] = None,
        format: str = "html",
        project_id: Optional[int] = None,
        base_url: Optional[str] = None
    ) -> Union[str, bytes]:
        """
        Preview a template with sample or real data.
        ALWAYS bypasses cache and usage tracking for real-time feedback.

        Args:
            template_id: Template ID
            sample_data: Optional sample data
            format: Output format
            project_id: Optional project ID to load real data
            base_url: Base URL for PDF generation

        Returns:
            Preview output (string for HTML/CSV, bytes for PDF/DOCX)

        Raises:
            TemplateNotFoundError: If template not found
            TemplateEngineError: If preview fails
        """
        try:
            template = self.repository.get_template(template_id)
            
            # Generate or load context data
            if sample_data:
                data = sample_data
            elif project_id:
                # Load real project data
                data = self._prepare_project_context(project_id)
            else:
                # Use sandbox data generator for realistic preview
                sandbox = SandboxDataGenerator()
                data = sandbox.generate_complete_context(
                    report_type=template.category or 'Audit'
                )
            
            # Always validate for preview
            validation = self.validator.validate_template_object(template)
            if not validation.is_valid:
                error_messages = [e.message for e in validation.errors]
                raise TemplateValidationError(
                    f"Template validation failed: {'; '.join(error_messages)}"
                )
            
            # Adapt context
            context = self.context_adapter.adapt(
                data,
                template.variables_schema or {}
            )
            
            # Render from scratch (no cache, no usage tracking)
            html = self.renderer.render(template.content, context)
            output = self.exporter.export(html, format, base_url=base_url)
            
            return output
            
        except ReportTemplate.DoesNotExist:
            raise TemplateNotFoundError(f"Template with id {template_id} not found")
        except (TemplateValidationError, TemplateRenderError):
            raise
        except Exception as e:
            logger.error(f"Error previewing template {template_id}: {str(e)}", exc_info=True)
            raise TemplateEngineError(f"Error previewing template: {str(e)}") from e
    
    def _render_raw(
        self,
        template_id: int,
        report_data: Dict[str, Any],
        format: str = "html",
        base_url: Optional[str] = None,
        validate: bool = True
    ) -> Union[str, bytes]:
        """
        Internal method: Render template without cache or usage tracking.
        Used by preview and for testing.

        Args:
            template_id: Template ID
            report_data: Report data
            format: Output format
            base_url: Base URL for PDF generation
            validate: Whether to validate before rendering

        Returns:
            Rendered output
        """
        template = self.repository.get_template(template_id)
        
        # Validate if requested
        if validate:
            validation = self.validator.validate_template_object(template)
            if not validation.is_valid:
                error_messages = [e.message for e in validation.errors]
                raise TemplateValidationError(
                    f"Template validation failed: {'; '.join(error_messages)}"
                )
        
        # Adapt context
        context = self.context_adapter.adapt(
            report_data,
            template.variables_schema or {}
        )
        
        # Render
        html = self.renderer.render(template.content, context)
        output = self.exporter.export(html, format, base_url=base_url)
        
        return output
    
    def validate(
        self,
        template_id: Optional[int] = None,
        content: Optional[str] = None,
        variables_schema: Optional[Dict[str, Any]] = None,
        format: str = "html"
    ) -> ValidationResult:
        """
        Validate template syntax and structure.
        
        Args:
            template_id: Template ID (if validating saved template)
            content: Template content (if validating unsaved content)
            variables_schema: Variable schema for validation
            format: Template format
        
        Returns:
            ValidationResult with errors and warnings
        
        Raises:
            TemplateNotFoundError: If template_id provided but not found
        """
        if template_id:
            template = self.repository.get_template(template_id)
            return self.validator.validate_template_object(template)
        elif content:
            return self.validator.validate(content, variables_schema, format)
        else:
            raise ValueError("Either template_id or content must be provided")
    
    def generate_sample_data(self, template_id: int) -> Dict[str, Any]:
        """
        Generate sample data for a template based on its schema.

        Args:
            template_id: Template ID

        Returns:
            Dictionary with sample data
        """
        template = self.repository.get_template(template_id)
        return self.context_adapter.generate_sample_data(template.variables_schema or {})
    
    def _prepare_project_context(self, project_id: int) -> Dict[str, Any]:
        """
        Prepare context data from a project.
        Delegates to ReportContextBuilder for proper separation of concerns.
        """
        try:
            from project.services.report_context_builder import ReportContextBuilder
            
            return ReportContextBuilder.build_project_context(
                project_id=project_id,
                report_type='Audit',  # Default, should be passed
                standard='NIST',  # Default, should be passed
                is_staff=True  # Default, should be passed
            )
        except Exception as e:
            logger.error(f"Error preparing project context: {str(e)}", exc_info=True)
            # Return minimal context on error
            return self.context_adapter.generate_sample_data(None)

