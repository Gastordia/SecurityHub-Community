"""
Project Management Serializers with OpenAPI Documentation
Comprehensive serializers for project, vulnerability, and scope management
"""

from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from drf_spectacular.types import OpenApiTypes
from .models import Project, ProjectScope, Vulnerability, VulnerableInstance
from accounts.models import CustomUser


@extend_schema_serializer()
class ProjectSerializer(serializers.ModelSerializer):
    """
    Serializer for Project model with comprehensive project management features.
    
    This serializer handles the core project entity including status tracking,
    owner management, and project lifecycle.
    """
    
    # Read-only field for owner (returns user strings)
    owner = serializers.StringRelatedField(many=True, read_only=True)
    # Write-only field for owner (accepts user IDs)
    # Also accept 'owner' array in request for backward compatibility
    owner_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=CustomUser.objects.all(),
        write_only=True,
        required=False
    )
    calculated_status = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = [
            'id', 'name', 'description',
            'business_criticality', 'business_value',
            'projecttype', 'startdate', 'enddate', 'testingtype',
            'projectexception', 'owner', 'owner_ids', 'status',
            'calculated_status', 'standard', 'hold_reason',
        ]
        read_only_fields = ['id']
        extra_kwargs = {
            'status':      {'required': False, 'allow_blank': False},
            'startdate':   {'required': False},
            'enddate':     {'required': False},
            'projecttype': {'required': False, 'allow_blank': True},
        }
    
    @extend_schema_field(OpenApiTypes.STR)
    def get_calculated_status(self, obj):
        return obj.calculate_status

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['owner_ids'] = list(instance.owner.values_list('id', flat=True))
        return data
    
    def create(self, validated_data):
        """Create project with owner assignment"""
        # Handle owner - check both 'owner' and 'owner_ids' from request data
        # (owner_ids is the write-only field, but request might send 'owner')
        request_data = self.context.get('request').data if self.context.get('request') else {}
        owner_ids = request_data.get('owner') or request_data.get('owner_ids') or []
        # Remove from validated_data if it somehow got in
        validated_data.pop('owner_ids', None)
        validated_data.pop('companyname', None)  # removed field, ignore if sent

        # Supply defaults for required model fields when omitted by caller
        from django.utils import timezone as tz
        import datetime
        today = tz.now().date()
        if not validated_data.get('startdate'):
            validated_data['startdate'] = today
        if not validated_data.get('enddate'):
            validated_data['enddate'] = today + datetime.timedelta(days=90)
        if not validated_data.get('projecttype'):
            validated_data['projecttype'] = 'Web Application'

        # Auto-calculate status if not provided (based on dates)
        # Status is required by model, so always set it
        if 'status' not in validated_data or not validated_data.get('status'):
            from django.utils import timezone
            current_date = timezone.now().date()
            startdate = validated_data.get('startdate')
            enddate = validated_data.get('enddate')
            
            if startdate and enddate:
                if current_date < startdate:
                    validated_data['status'] = 'Upcoming'
                elif startdate <= current_date <= enddate:
                    validated_data['status'] = 'In Progress'
                elif current_date > enddate:
                    validated_data['status'] = 'Delay'
                else:
                    validated_data['status'] = 'Upcoming'  # Default fallback
            else:
                # Default to 'Upcoming' if dates not available yet
                validated_data['status'] = 'Upcoming'
        
        # Ensure status is always set (required by model)
        if not validated_data.get('status'):
            validated_data['status'] = 'Upcoming'  # Final fallback
        
        # Create project
        project = super().create(validated_data)

        # Set owners if provided
        if owner_ids:
            # Convert to list if single value
            if not isinstance(owner_ids, list):
                owner_ids = [owner_ids]
            project.owner.set(owner_ids)
        
        return project
    
    def update(self, instance, validated_data):
        """Update project with owner assignment"""
        # Handle owner - check both 'owner' and 'owner_ids' from request data
        request_data = self.context.get('request').data if self.context.get('request') else {}
        owner_ids = request_data.get('owner') or request_data.get('owner_ids')
        # Remove from validated_data if it somehow got in
        validated_data.pop('owner_ids', None)
        validated_data.pop('companyname', None)  # removed field, ignore if sent

        # Update project
        project = super().update(instance, validated_data)

        # Set owners if provided
        if owner_ids is not None:
            # Convert to list if single value
            if not isinstance(owner_ids, list):
                owner_ids = [owner_ids]
            project.owner.set(owner_ids)
        
        return project


@extend_schema_serializer()
class ProjectScopeSerializer(serializers.ModelSerializer):
    """
    Serializer for ProjectScope model with Nmap integration.
    
    This serializer handles project scope management including
    scope entries and detailed Nmap scan information.
    """
    
    project_name = serializers.CharField(source='project.name', read_only=True)
    
    class Meta:
        model = ProjectScope
        fields = [
            'id', 'project', 'project_name', 'scope', 'description',
            'nmap_details'
        ]
        read_only_fields = ['id', 'project']


@extend_schema_serializer()
class VulnerabilitySerializer(serializers.ModelSerializer):
    """
    Serializer for Vulnerability model with comprehensive intelligence features.
    
    This serializer handles vulnerability management including threat intelligence,
    asset correlation, and intelligence scoring.
    """
    
    project_name = serializers.CharField(source='project.name', read_only=True)
    created_by_name = serializers.CharField(
        source='created_by.full_name', read_only=True, allow_null=True, default=None
    )
    last_updated_by_name = serializers.CharField(
        source='last_updated_by.full_name', read_only=True, allow_null=True, default=None
    )
    cve_list = serializers.SerializerMethodField()
    cwe_list = serializers.SerializerMethodField()
    kev_summary = serializers.SerializerMethodField()
    instance_count = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = [
            # Core identity
            'id', 'project', 'project_name',
            # Finding details
            'vulnerabilityname', 'vulnerabilityseverity', 'cvssscore', 'cvssvector',
            'status', 'vulnerabilitydescription', 'POC', 'vulnerabilitysolution',
            'vulnerabilityreferlnk', 'cwe', 'published',
            # Dates
            'created', 'published_date', 'fixed_date',
            # Authorship
            'created_by', 'created_by_name', 'last_updated_by', 'last_updated_by_name',
            # Basic intelligence: CVE + CISA KEV only
            'cve', 'cve_list', 'cwe_list',
            'has_exploit', 'has_cisa_kev_exploit', 'kev_urgency_level', 'kev_summary',
            # Workflow
            'false_positive', 'suppressed', 'verified',
            # Instance count
            'instance_count',
        ]
        read_only_fields = ['id', 'created', 'created_by', 'last_updated_by']
    
    @extend_schema_field(OpenApiTypes.STR)
    def get_cve_list(self, obj):
        """Get list of CVE IDs"""
        return obj.get_cve_list()
    
    @extend_schema_field(OpenApiTypes.STR)
    def get_cwe_list(self, obj):
        """Get list of CWE IDs"""
        return obj.get_cwe_list()
    
    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_kev_summary(self, obj):
        data = obj.enrichment_data
        if isinstance(data, dict):
            return data.get('kev_summary')
        return None

    @extend_schema_field(OpenApiTypes.INT)
    def get_instance_count(self, obj):
        # Use annotated value from queryset to avoid N+1; fall back to live count
        annotated = getattr(obj, 'instance_count_annotated', None)
        if annotated is not None:
            return annotated
        return obj.instances.count()
    
    def create(self, validated_data):
        """Override create method to handle auto-population"""
        # Create the vulnerability instance
        vulnerability = super().create(validated_data)
        request = self.context.get('request')
        if request and getattr(request, 'user', None) and request.user.is_authenticated:
            vulnerability.created_by = request.user
            vulnerability.last_updated_by = request.user
        
        # Try to auto-populate from VulnerabilityDB
        vulnerability.auto_populate_from_template()
        
        # Save the vulnerability with auto-populated data and audit fields
        vulnerability.save()
        
        return vulnerability


@extend_schema_serializer()
class VulnerableInstanceSerializer(serializers.ModelSerializer):
    """
    Serializer for VulnerableInstance model with asset integration.
    
    This serializer handles vulnerability instances including
    URL, parameter, and asset association.
    """
    
    vulnerability_name = serializers.CharField(source='vulnerabilityid.vulnerabilityname', read_only=True)
    project_name = serializers.CharField(source='project.name', read_only=True)

    class Meta:
        model = VulnerableInstance
        fields = [
            'id', 'vulnerabilityid', 'project', 'project_name', 'URL',
            'Parameter', 'status', 'vulnerability_name'
        ]
        read_only_fields = ['id']
        extra_kwargs = {
            'vulnerabilityid': {'required': False, 'allow_null': True},
            'project': {'required': False, 'allow_null': True}
        }
    
    def create(self, validated_data):
        """
        Override create to handle vulnerabilityid and project being set from context
        """
        # Get vulnerabilityid and project from context if not in validated_data
        context = self.context or {}
        vulnerabilityid = validated_data.pop('vulnerabilityid', None)
        if not vulnerabilityid and 'vulnerabilityid' in context:
            vuln_obj = context['vulnerabilityid']
            vulnerabilityid = vuln_obj.id if hasattr(vuln_obj, 'id') else vuln_obj
        
        project = validated_data.pop('project', None)
        if not project and 'project' in context:
            proj_obj = context['project']
            project = proj_obj.id if hasattr(proj_obj, 'id') else proj_obj
        
        # Create instance with vulnerabilityid and project
        instance = VulnerableInstance(**validated_data)
        if vulnerabilityid:
            instance.vulnerabilityid_id = vulnerabilityid
        if project:
            instance.project_id = project
        instance.save()
        return instance
    




@extend_schema_serializer()
class VulnerabilityPublishSerializer(serializers.Serializer):
    """
    Serializer for vulnerability publishing requests.

    Accepts UUID or integer vulnerability IDs.
    """
    vulnerability_ids = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of vulnerability IDs to publish"
    )
    publish = serializers.BooleanField(default=True)


@extend_schema_serializer()
class UpdateProjectOwnerSerializer(serializers.Serializer):
    """
    Serializer for updating project owners.
    
    This serializer handles requests to update project ownership.
    """
    
    owner_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="List of user IDs to assign as project owners"
    )


@extend_schema_serializer()
class ImageSerializer(serializers.Serializer):
    """
    Serializer for image uploads.

    This serializer handles image file uploads for projects.
    """

    image = serializers.ImageField(help_text="Image file to upload")
    project_id = serializers.IntegerField(help_text="Project ID to associate with the image")
    description = serializers.CharField(
        max_length=500,
        required=False,
        help_text="Optional description for the image"
    )


