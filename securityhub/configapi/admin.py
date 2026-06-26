from django.contrib import admin
from .models import ReportStandard, ProjectType, ReportTemplate, TemplateVersion


@admin.register(ReportStandard)
class ReportStandardAdmin(admin.ModelAdmin):
    list_display = ['name', 'id']
    search_fields = ['name']


@admin.register(ProjectType)
class ProjectTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'id']
    search_fields = ['name']


@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    list_display = ['name', 'format', 'category', 'current_version', 'is_active', 'is_public', 'usage_count', 'created_by', 'created_at']
    list_filter = ['format', 'category', 'is_active', 'is_public', 'is_system_template']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at', 'last_used_at', 'usage_count', 'rating', 'rating_count']
    fieldsets = (
        ('Basic Information', {'fields': ('name', 'description', 'format', 'category', 'tags')}),
        ('Template Content', {'fields': ('content', 'variables_schema', 'settings')}),
        ('Versioning', {'fields': ('current_version', 'is_active')}),
        ('Ownership & Permissions', {'fields': ('created_by', 'is_public', 'is_system_template')}),
        ('Metadata', {'fields': ('created_at', 'updated_at', 'last_used_at', 'usage_count', 'thumbnail_path', 'rating', 'rating_count')}),
    )


@admin.register(TemplateVersion)
class TemplateVersionAdmin(admin.ModelAdmin):
    list_display = ['template', 'version_number', 'branch_name', 'is_tagged', 'tag_name', 'created_by', 'created_at']
    list_filter = ['branch_name', 'is_tagged', 'is_merged', 'template']
    search_fields = ['template__name', 'change_summary', 'tag_name']
    readonly_fields = ['created_at']


