"""
Template Loader - Jinja2 loader for database templates.
Supports template inheritance ({% extends %}) and includes ({% include %}).
"""
import logging
from typing import Optional
from jinja2 import BaseLoader, TemplateNotFound
from ..models import ReportTemplate, TemplateVersion

logger = logging.getLogger(__name__)


class DatabaseTemplateLoader(BaseLoader):
    """
    Jinja2 loader that loads templates from the database.
    Supports template inheritance and component includes.
    """
    
    def __init__(self):
        """Initialize loader."""
        pass

    def get_source(self, environment, template_name):
        """
        Get template source from database.
        
        Template name format:
        - "template:123" - Load template by ID
        - "component:header" - Load component by name
        - "base:layout" - Load base template by name
        
        Args:
            environment: Jinja2 environment
            template_name: Template identifier
        
        Returns:
            Tuple of (source, filename, uptodate)
        
        Raises:
            TemplateNotFound: If template not found
        """
        try:
            # Parse template identifier
            if template_name.startswith('template:'):
                # Load by ID
                template_id = int(template_name.split(':', 1)[1])
                template = self._get_template_by_id(template_id)
            elif template_name.startswith('component:'):
                raise TemplateNotFound(template_name)
            elif template_name.startswith('base:'):
                # Load base template by name
                base_name = template_name.split(':', 1)[1]
                template = self._get_base_template_by_name(base_name)
            else:
                # Try to find by name directly
                template = self._get_template_by_name(template_name)
            
            if not template:
                raise TemplateNotFound(template_name)
            
            # Get latest version content
            latest_version = TemplateVersion.objects.filter(
                template=template
            ).order_by('-version_number').first()
            
            source = latest_version.content if latest_version else template.content
            
            # Create uptodate callback
            def uptodate():
                # Check if template has been updated since load
                if latest_version:
                    return template.updated_at <= latest_version.created_at
                return True
            
            return source, f"template:{template.id}", uptodate
            
        except (ValueError, ReportTemplate.DoesNotExist) as e:
            logger.warning(f"Template not found: {template_name} - {str(e)}")
            raise TemplateNotFound(template_name)
        except Exception as e:
            logger.error(f"Error loading template {template_name}: {str(e)}", exc_info=True)
            raise TemplateNotFound(template_name)
    
    def _get_template_by_id(self, template_id: int) -> Optional[ReportTemplate]:
        """Get template by ID."""
        return ReportTemplate.objects.filter(id=template_id, is_active=True).first()

    def _get_template_by_name(self, name: str) -> Optional[ReportTemplate]:
        """Get template by name."""
        return ReportTemplate.objects.filter(name=name, is_active=True).first()

    def _get_base_template_by_name(self, name: str) -> Optional[ReportTemplate]:
        """Get base template by name (tagged as base layout)."""
        return ReportTemplate.objects.filter(
            name=name,
            is_active=True,
            category='custom',  # Base templates are custom
            tags__contains=['base', 'layout']  # Base templates have these tags
        ).first()

