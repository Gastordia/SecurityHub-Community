from rest_framework import serializers
from .models import ReportStandard, ProjectType, ReportTemplate, TemplateVersion


class ReportStandardSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportStandard
        fields = ['id', 'name']
        read_only_fields = ['id']


class ProjectTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectType
        fields = ['id', 'name']
        read_only_fields = ['id']


class ReportTemplateSerializer(serializers.ModelSerializer):
    """Serializer for ReportTemplate model"""
    created_by_email = serializers.EmailField(source='created_by.email', read_only=True)

    class Meta:
        model = ReportTemplate
        fields = [
            'id', 'name', 'description', 'format', 'category', 'tags',
            'content', 'variables_schema', 'settings',
            'current_version', 'is_active', 'is_public', 'is_system_template',
            'created_by', 'created_by_email',
            'created_at', 'updated_at', 'last_used_at', 'usage_count',
            'thumbnail_path', 'rating', 'rating_count'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'last_used_at', 
            'usage_count', 'rating', 'rating_count', 'created_by'
        ]


class TemplateVersionSerializer(serializers.ModelSerializer):
    """Serializer for TemplateVersion model"""
    created_by_email = serializers.EmailField(source='created_by.email', read_only=True)
    template_name = serializers.CharField(source='template.name', read_only=True)
    
    class Meta:
        model = TemplateVersion
        fields = [
            'id', 'template', 'template_name', 'version_number',
            'content', 'variables_schema', 'settings',
            'change_summary', 'created_by', 'created_by_email', 'created_at',
            'parent_version', 'branch_name', 'is_merged', 'merge_base_version',
            'is_tagged', 'tag_name'
        ]
        read_only_fields = ['id', 'created_at', 'created_by']


