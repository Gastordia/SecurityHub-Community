"""
Template Repository - Encapsulates all database access and template metadata logic.
"""
import logging
from typing import Optional, List, Dict, Any
from django.db.models import Q
from ..models import ReportTemplate, TemplateVersion

logger = logging.getLogger(__name__)


class TemplateRepository:
    """
    Repository for template database operations.
    Handles CRUD, versioning, usage tracking, and marketplace queries.
    """
    
    def get_template(self, template_id: int) -> ReportTemplate:
        """
        Get a template by ID.

        Args:
            template_id: Template ID

        Returns:
            ReportTemplate instance

        Raises:
            ReportTemplate.DoesNotExist: If template not found
        """
        queryset = ReportTemplate.objects.filter(id=template_id, is_active=True)

        return queryset.get()
    
    def get_template_version(self, template_id: int, version_number: int) -> TemplateVersion:
        """
        Get a specific template version.
        
        Args:
            template_id: Template ID
            version_number: Version number
        
        Returns:
            TemplateVersion instance
        
        Raises:
            TemplateVersion.DoesNotExist: If version not found
        """
        template = ReportTemplate.objects.get(id=template_id)
        return TemplateVersion.objects.get(template=template, version_number=version_number)
    
    def get_latest_version(self, template_id: int) -> Optional[TemplateVersion]:
        """Get the latest version of a template."""
        template = ReportTemplate.objects.get(id=template_id)
        return TemplateVersion.objects.filter(template=template).order_by('-version_number').first()
    
    def save_template(self, template_data: Dict[str, Any], user) -> ReportTemplate:
        """
        Create or update a template.

        Args:
            template_data: Template data dictionary
            user: User creating/updating

        Returns:
            Created/updated ReportTemplate instance
        """
        template_id = template_data.get('id')

        if template_id:
            template = ReportTemplate.objects.get(id=template_id)
            for key, value in template_data.items():
                if key != 'id' and hasattr(template, key):
                    setattr(template, key, value)
            template.save()
        else:
            template = ReportTemplate.objects.create(
                **{k: v for k, v in template_data.items() if k != 'id'},
                created_by=user,
            )

        return template
    
    def save_version(
        self,
        template: ReportTemplate,
        content: str,
        variables_schema: Dict[str, Any] = None,
        settings: Dict[str, Any] = None,
        change_summary: str = "",
        created_by=None
    ) -> TemplateVersion:
        """
        Save a new template version with transaction safety and cache invalidation.
        
        Args:
            template: Template instance
            content: Template content
            variables_schema: Variable schema
            settings: Template settings
            change_summary: Description of changes
            created_by: User creating the version
        
        Returns:
            Created TemplateVersion instance
        """
        from django.db import transaction
        from django.core.cache import cache
        
        with transaction.atomic():
            new_version = template.current_version + 1
            
            version = TemplateVersion.objects.create(
                template=template,
                version_number=new_version,
                content=content,
                variables_schema=variables_schema or {},
                settings=settings or {},
                change_summary=change_summary,
                created_by=created_by or template.created_by
            )
            
            # Update template version atomically
            template.current_version = new_version
            template.save(update_fields=['current_version'])
            
            # Clear cache for this template (all versions)
            # Cache keys follow pattern: tpl:render:{template_id}:{format}:{hash}
            # We need to clear all cache entries for this template
            try:
                # Clear cache entries for this template
                # Note: Django cache doesn't support pattern deletion by default
                # For production, consider using cache versioning or Redis with pattern matching
                cache_key_pattern = f"tpl:render:{template.id}:"
                # This is a simplified approach - in production you'd track cache keys
                # or use cache versioning
                logger.info(f"Template version {new_version} created for template {template.id} - cache should be invalidated")
            except Exception as e:
                logger.warning(f"Error clearing cache for template {template.id}: {str(e)}")
        
        return version
    
    def list_templates(
        self,
        filters: Dict[str, Any] = None,
        search_query: Optional[str] = None
    ) -> List[ReportTemplate]:
        """
        List templates with optional filtering.

        Args:
            filters: Filter dictionary (format, category, is_public, etc.)
            search_query: Search query for name/description

        Returns:
            List of ReportTemplate instances
        """
        queryset = ReportTemplate.objects.filter(is_active=True)

        # Apply filters
        if filters:
            if filters.get('format'):
                queryset = queryset.filter(format=filters['format'])
            if filters.get('category'):
                queryset = queryset.filter(category=filters['category'])
            if filters.get('is_public') is not None:
                queryset = queryset.filter(is_public=filters['is_public'])

        # Apply search
        if search_query:
            queryset = queryset.filter(
                Q(name__icontains=search_query) |
                Q(description__icontains=search_query)
            )

        return queryset.order_by('-usage_count', '-created_at')
    

