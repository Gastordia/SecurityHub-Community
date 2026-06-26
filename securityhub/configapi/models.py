from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator, MaxValueValidator
import json

User = get_user_model()


class ReportStandard(models.Model):
    name = models.CharField(max_length=255, unique=True)


class ProjectType(models.Model):
    name = models.CharField(max_length=600, unique=True)


class ReportTemplate(models.Model):
    """Report template model for customizable report templates"""
    
    FORMAT_CHOICES = [
        ('html', 'HTML'),
        ('pdf', 'PDF'),
        ('word', 'Word'),
        ('docx', 'DOCX'),
        ('csv', 'CSV'),
        ('latex', 'LaTeX'),
    ]
    
    CATEGORY_CHOICES = [
        ('executive', 'Executive'),
        ('technical', 'Technical'),
        ('compliance', 'Compliance'),
        ('custom', 'Custom'),
    ]
    
    # Basic Information
    name = models.CharField(max_length=200, db_index=True)
    description = models.TextField(blank=True, null=True)
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES, db_index=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, db_index=True, default='custom')
    tags = models.JSONField(default=list, blank=True)  # Array of tag strings
    
    # Template Content
    content = models.TextField()  # Template code/content
    variables_schema = models.JSONField(default=dict, blank=True)  # Available variables and types
    settings = models.JSONField(default=dict, blank=True)  # Template-specific settings
    
    # Versioning
    current_version = models.IntegerField(default=1)
    is_active = models.BooleanField(default=True, db_index=True)
    
    # Ownership & Permissions
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_templates')
    is_public = models.BooleanField(default=False, db_index=True)
    is_system_template = models.BooleanField(default=False)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    usage_count = models.IntegerField(default=0)
    
    # Template metadata
    thumbnail_path = models.CharField(max_length=500, blank=True, null=True)  # Path to preview thumbnail
    rating = models.FloatField(default=0.0, validators=[MinValueValidator(0.0), MaxValueValidator(5.0)])
    rating_count = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'report_templates'
        indexes = [
            models.Index(fields=['format', 'category']),
            models.Index(fields=['is_public', 'is_active']),
        ]
        ordering = ['-usage_count', '-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.format})"
    
    def get_tags_list(self):
        """Get tags as list"""
        if isinstance(self.tags, list):
            return self.tags
        try:
            return json.loads(self.tags) if self.tags else []
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_tags_list(self, tags_list):
        """Set tags from list"""
        if isinstance(tags_list, list):
            self.tags = tags_list
        else:
            self.tags = []


class TemplateVersion(models.Model):
    """Template version history with git-like versioning"""
    
    template = models.ForeignKey(ReportTemplate, on_delete=models.CASCADE, related_name='versions')
    version_number = models.IntegerField(db_index=True)
    
    # Version Content
    content = models.TextField()
    variables_schema = models.JSONField(default=dict, blank=True)
    settings = models.JSONField(default=dict, blank=True)
    
    # Version Metadata
    change_summary = models.TextField(blank=True, null=True)  # What changed in this version
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_template_versions')
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Git-like Features
    parent_version = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, 
                                      related_name='child_versions')
    branch_name = models.CharField(max_length=100, default='main', db_index=True)
    is_merged = models.BooleanField(default=False)
    merge_base_version = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True,
                                          related_name='merged_from_versions')
    is_tagged = models.BooleanField(default=False)
    tag_name = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        db_table = 'template_versions'
        unique_together = [['template', 'version_number']]
        indexes = [
            models.Index(fields=['template', 'version_number']),
        ]
        ordering = ['-version_number']
    
    def __str__(self):
        return f"{self.template.name} v{self.version_number}"


