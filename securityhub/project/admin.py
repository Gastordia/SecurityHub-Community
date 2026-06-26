from django.contrib import admin
from django.utils.html import format_html
from .models import Project, Vulnerability, VulnerableInstance


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ['name', 'projecttype', 'status', 'startdate', 'enddate']
    list_filter = ['status', 'projecttype', 'testingtype', 'startdate', 'enddate']
    search_fields = ['name', 'description', 'projecttype']


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['vulnerabilityname', 'project', 'vulnerabilityseverity', 'status', 'created']
    list_filter = ['vulnerabilityseverity', 'status', 'has_exploit', 'published']
    search_fields = ['vulnerabilityname', 'project__name', 'cve', 'cwe', 'vulnerabilitydescription']
    readonly_fields = ['created', 'published_date', 'fixed_date']

    def mark_as_published(self, request, queryset):
        queryset.update(published=True)
    mark_as_published.short_description = "Mark as published"

    def mark_as_fixed(self, request, queryset):
        queryset.update(status='Confirm Fixed')
    mark_as_fixed.short_description = "Mark as fixed"

    actions = ['mark_as_published', 'mark_as_fixed']


@admin.register(VulnerableInstance)
class VulnerableInstanceAdmin(admin.ModelAdmin):
    list_display = ['vulnerabilityid', 'URL', 'Parameter', 'status', 'project']
    list_filter = ['status', 'project', 'vulnerabilityid__vulnerabilityseverity']
    search_fields = ['URL', 'Parameter', 'vulnerabilityid__vulnerabilityname', 'project__name']
