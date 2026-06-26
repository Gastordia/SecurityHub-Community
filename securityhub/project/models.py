#django import
import uuid
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

# local import
from accounts.models import CustomUser
from utils.validators import xss_validator
from utils.project_status import update_project_status
VULNERABLE = 'Vulnerable'
CONFIRMED = 'Confirm Fixed'
ACCEPTED_RISK = 'Accepted Risk'
STATUS_CHOICES = [
        (VULNERABLE, 'Vulnerable'),
        (CONFIRMED, 'Confirm Fixed'),
        (ACCEPTED_RISK, 'Accepted Risk'),
    ]

PROJECT_STATUS_CHOICES = [
        ('Upcoming', 'Upcoming'),
        ('In Progress', 'In Progress'),
        ('Delay', 'Delay'),
        ('On Hold', 'On Hold'),
        ('Completed', 'Completed'),
    ]

class Project(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=False, null=False, blank=False)
    description = models.TextField(unique=False, null=False, blank=True, default='', validators=[xss_validator])
    business_criticality = models.CharField(
        max_length=20,
        choices=[
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
            ('unknown', 'Unknown'),
        ],
        default='unknown',
    )
    business_value = models.CharField(
        max_length=20,
        choices=[
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
            ('unknown', 'Unknown'),
        ],
        default='unknown',
    )
    projecttype = models.CharField(max_length=100, unique=False, null=False, blank=False)
    startdate = models.DateField()
    enddate = models.DateField()
    testingtype = models.CharField(max_length=100, unique = False, null = True, blank = True, default="White Box")
    projectexception = models.TextField(unique = False, null = True, blank = True,validators=[xss_validator])
    owner = models.ManyToManyField(CustomUser,blank=True)
    status = models.CharField(max_length=20, choices=PROJECT_STATUS_CHOICES)
    standard = models.JSONField(default=list)
    hold_reason = models.TextField(null=True, blank=True, help_text="Reason why the project is on hold")

    def clean(self):
        if self.enddate < self.startdate:
            raise ValidationError(_('End date cannot be earlier than start date'))

    @property
    def companyname(self):
        """Stub for DOCX template compatibility."""
        return None

    @property
    def calculate_status(self):
        current_date = timezone.now().date()
        if self.status == 'On Hold':
            return 'On Hold'
        if self.status == 'Completed':
            return 'Completed'
        if current_date < self.startdate:
            return 'Upcoming'
        elif self.startdate <= current_date <= self.enddate:
            return 'In Progress'
        elif current_date > self.enddate:
            return 'Delay'

    def save(self, *args, **kwargs):
        # ✅ FIXED: Issue #12 - Wrap save() in transaction for atomicity
        from django.db import transaction

        with transaction.atomic():
            # Clear hold_reason if status is not "On Hold"
            if self.status != 'On Hold' and self.hold_reason:
                self.hold_reason = None

            # Only update status if project is not completed or on hold
            if self.status not in ['Completed', 'On Hold']:
                update_project_status(self)
            super(Project, self).save(*args, **kwargs)

    class Meta:
        ordering = ['-id']
        indexes = [
            models.Index(fields=['status'], name='proj_status_idx'),
            models.Index(fields=['startdate'], name='proj_start_idx'),
            models.Index(fields=['enddate'], name='proj_end_idx'),
            models.Index(fields=['projecttype'], name='proj_type_idx'),
        ]



class ProjectScope(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    scope = models.CharField(max_length=500, unique=False, null=False, blank=False)
    description = models.CharField(max_length=100, unique=False, null=True, blank=True, default=None)
    nmap_details = models.JSONField(null=True, blank=True, help_text="Detailed Nmap scan information for this scope item")

    class Meta:
        unique_together = ['project', 'scope']



class Vulnerability(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    vulnerabilityname = models.CharField(max_length=300,default=None,blank=True,null=True)
    vulnerabilityseverity = models.CharField(max_length=300,null=True)
    cvssscore = models.FloatField(blank=True,null=True)
    cvssvector = models.CharField(max_length=300,default=None,null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=VULNERABLE)
    vulnerabilitydescription = models.TextField(blank=True,null=True,validators=[xss_validator])
    POC = models.TextField(default=None,blank=True,null=True,validators=[xss_validator])
    created = models.DateTimeField(auto_now_add=True,editable=False,null=True)
    published_date = models.DateTimeField(null=True, blank=True)
    fixed_date = models.DateTimeField(null=True, blank=True)
    vulnerabilitysolution = models.TextField(blank=True,null=True,validators=[xss_validator])
    vulnerabilityreferlnk = models.TextField(blank=True,null=True,validators=[xss_validator])
    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, editable=False,to_field='id',related_name='vulnerability_created_by')
    last_updated_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True,to_field='id',related_name='vulnerability_last_updated_by')
    cwe = models.JSONField(null=True, blank=True)
    published = models.BooleanField(default=False)
    
    # ✅ CVE Information
    cve = models.JSONField(null=True, blank=True, help_text="CVE IDs associated with this vulnerability")
    
    # ✅ Intelligence Engine Fields - Threat Intelligence
    has_exploit = models.BooleanField(default=False, help_text="Vulnerability has known exploits")
    exploit_code_maturity = models.CharField(max_length=50, blank=True, null=True, help_text="Exploit code maturity level")
    exploitation_availability = models.CharField(max_length=50, blank=True, null=True, help_text="Exploitation availability")
    exploitation_complexity = models.CharField(max_length=50, blank=True, null=True, help_text="Exploitation complexity")
    exploitation_impact = models.CharField(max_length=50, blank=True, null=True, help_text="Exploitation impact")
    exploitation_method = models.CharField(max_length=100, blank=True, null=True, help_text="Exploitation method")
    exploitation_score = models.FloatField(blank=True, null=True, help_text="Exploitation score")

    # ✅ Intelligence Engine Fields - Asset Intelligence
    asset_criticality = models.CharField(max_length=50, blank=True, null=True, help_text="Asset criticality level")
    asset_value = models.CharField(max_length=50, blank=True, null=True, help_text="Asset business value")
    asset_tags = models.JSONField(blank=True, null=True, help_text="Asset tags and metadata")
    business_units = models.JSONField(blank=True, null=True, help_text="Affected business units")
    tech_owners = models.JSONField(blank=True, null=True, help_text="Technical owners")
    scope = models.CharField(max_length=50, blank=True, null=True, help_text="Scope classification")
    out_of_scope = models.BooleanField(default=False, help_text="Vulnerability is out of scope")
    
    # ✅ Intelligence Engine Fields - Cloud & Container Context
    cloud_platform = models.CharField(max_length=50, blank=True, null=True, help_text="Cloud platform (AWS, Azure, GCP)")
    kubernetes_cluster = models.CharField(max_length=200, blank=True, null=True, help_text="Kubernetes cluster name")
    kubernetes_namespace = models.CharField(max_length=200, blank=True, null=True, help_text="Kubernetes namespace")
    kubernetes_workload = models.CharField(max_length=200, blank=True, null=True, help_text="Kubernetes workload")
    container_image = models.CharField(max_length=500, blank=True, null=True, help_text="Container image")
    container_image_digest = models.CharField(max_length=200, blank=True, null=True, help_text="Container image digest")
    
    # ✅ Intelligence Engine Fields - Temporal Intelligence
    first_detected = models.DateTimeField(blank=True, null=True, help_text="First detection timestamp")
    last_detected = models.DateTimeField(blank=True, null=True, help_text="Last detection timestamp")
    fix_available = models.BooleanField(default=False, help_text="Fix is available")
    fix_deferred = models.BooleanField(default=False, help_text="Fix is deferred")
    fixed_at = models.DateTimeField(blank=True, null=True, help_text="Fix timestamp")
    fixed_in_version = models.CharField(max_length=100, blank=True, null=True, help_text="Fixed in version")
    patched_versions = models.JSONField(blank=True, null=True, help_text="Patched versions")
    
    # ✅ Intelligence Engine Fields - Technical Intelligence
    source_file = models.CharField(max_length=500, blank=True, null=True, help_text="Source file path")
    source_line = models.IntegerField(blank=True, null=True, help_text="Source line number")
    sink_file = models.CharField(max_length=500, blank=True, null=True, help_text="Sink file path")
    sink_line = models.IntegerField(blank=True, null=True, help_text="Sink line number")
    tainted_flow = models.BooleanField(default=False, help_text="Tainted data flow")
    proof_of_concept = models.TextField(blank=True, null=True, help_text="Proof of concept")
    steps_to_reproduce = models.TextField(blank=True, null=True, help_text="Steps to reproduce")
    
    # ✅ Intelligence Engine Fields - Multi-Source Scoring
    vendor_score = models.FloatField(blank=True, null=True, help_text="Vendor-specific score")
    custom_risk_score = models.FloatField(blank=True, null=True, help_text="Custom risk score")
    
    # ✅ Intelligence Engine Fields - Compliance & Regulatory
    compliance_frameworks = models.JSONField(blank=True, null=True, help_text="Compliance frameworks")
    nist_800_53_controls = models.JSONField(blank=True, null=True, help_text="NIST 800-53 controls")
    masvs_controls = models.JSONField(blank=True, null=True, help_text="MASVS controls")
    disa_stig = models.JSONField(blank=True, null=True, help_text="DISA STIG controls")
    
    # ✅ Intelligence Engine Fields - Operational Intelligence
    scanner_confidence = models.FloatField(blank=True, null=True, help_text="Scanner confidence level")
    scanner_tags = models.JSONField(blank=True, null=True, help_text="Scanner tags")
    detection_method = models.CharField(max_length=100, blank=True, null=True, help_text="Detection method")
    detection_complexity = models.CharField(max_length=50, blank=True, null=True, help_text="Detection complexity")
    false_positive = models.BooleanField(default=False, help_text="Potential false positive")
    suppressed = models.BooleanField(default=False, help_text="Vulnerability is suppressed")
    verified = models.BooleanField(default=False, help_text="Vulnerability is verified")
    validated_at = models.DateTimeField(blank=True, null=True, help_text="Validation timestamp")
    
    # ✅ Intelligence Engine Fields - Dependency Intelligence
    package_name = models.CharField(max_length=200, blank=True, null=True, help_text="Package name")
    package_version = models.CharField(max_length=100, blank=True, null=True, help_text="Package version")
    package_type = models.CharField(max_length=50, blank=True, null=True, help_text="Package type")
    package_cpe = models.CharField(max_length=200, blank=True, null=True, help_text="Package CPE")
    vulnerable_versions = models.JSONField(blank=True, null=True, help_text="Vulnerable versions")
    installed_version = models.CharField(max_length=100, blank=True, null=True, help_text="Installed version")
    
    # ✅ Intelligence Engine Fields - Network & Service Context
    ip_addresses = models.JSONField(blank=True, null=True, help_text="Affected IP addresses")
    hostnames = models.JSONField(blank=True, null=True, help_text="Affected hostnames")
    ports = models.JSONField(blank=True, null=True, help_text="Affected ports")
    services = models.JSONField(blank=True, null=True, help_text="Affected services")
    protocols = models.JSONField(blank=True, null=True, help_text="Affected protocols")
    endpoints = models.JSONField(blank=True, null=True, help_text="Affected endpoints")
    
    # ✅ Intelligence Engine Fields - Advanced Correlation
    related_vulnerabilities = models.JSONField(blank=True, null=True, help_text="Related vulnerabilities")
    attack_vectors = models.JSONField(blank=True, null=True, help_text="Attack vectors")
    mitre_tactics = models.JSONField(blank=True, null=True, help_text="MITRE ATT&CK tactics")
    mitre_techniques = models.JSONField(blank=True, null=True, help_text="MITRE ATT&CK techniques")
    attack_entry_points = models.JSONField(blank=True, null=True, help_text="Actor entry points")
    attack_paths = models.JSONField(blank=True, null=True, help_text="Lateral movement or attack path notes")
    attack_exit_points = models.JSONField(blank=True, null=True, help_text="Actor exit or exfiltration points")
    threat_actors = models.JSONField(blank=True, null=True, help_text="Threat actors")
    threat_actions = models.JSONField(blank=True, null=True, help_text="Threat actions")
    impact_assessment = models.JSONField(blank=True, null=True, help_text="Impact assessment")
    risk_acceptance = models.BooleanField(default=False, help_text="Risk accepted")
    risk_acceptance_reason = models.TextField(blank=True, null=True, help_text="Risk acceptance reason")
    

    class Meta:
        unique_together = (("project", "vulnerabilityname"),)
        indexes = [
            models.Index(fields=['vulnerabilityseverity'], name='vuln_severity_idx'),
            models.Index(fields=['status'], name='vuln_status_idx'),
            models.Index(fields=['cvssscore'], name='vuln_cvss_idx'),
            models.Index(fields=['created'], name='vuln_created_idx'),
            models.Index(fields=['published_date'], name='vuln_published_idx'),
            models.Index(fields=['fixed_date'], name='vuln_fixed_idx'),
            models.Index(fields=['has_exploit'], name='vuln_exploit_idx'),
        ]

    def save(self, *args, **kwargs):
        # Set published_date when a vulnerability is published for the first time
        if self.published and not self.published_date:
            self.published_date = timezone.now()
        # If unpublished, clear the published date
        elif not self.published:
            self.published_date = None

        # Set fixed_date when a vulnerability is marked as fixed for the first time
        if self.status == CONFIRMED and not self.fixed_date:
            self.fixed_date = timezone.now()
        # If not confirmed fixed, clear the fixed date (but only if it was previously set)
        elif self.status != CONFIRMED and self.fixed_date:
            self.fixed_date = None

        super(Vulnerability, self).save(*args, **kwargs)

    def populate_from_template(self, template_entry):
        """✅ NEW: Populate basic vulnerability details from VulnerabilityDB template"""
        if template_entry:
            # Only copy basic template fields (no intelligence data)
            self.vulnerabilityname = template_entry.vulnerabilityname
            self.vulnerabilityseverity = template_entry.vulnerabilityseverity
            self.vulnerabilitydescription = template_entry.vulnerabilitydescription
            self.vulnerabilitysolution = template_entry.vulnerabilitysolution
            self.vulnerabilityreferlnk = template_entry.vulnerabilityreferlnk
            self.cvssscore = template_entry.cvssscore
            self.cvssvector = template_entry.cvssvector
            self.cwe = template_entry.cwe

    def auto_populate_from_template(self):
        """✅ NEW: Auto-populate basic vulnerability details from template database"""
        try:
            from vulnerability.models import VulnerabilityDB
            template_entry = VulnerabilityDB.objects.filter(
                vulnerabilityname__iexact=self.vulnerabilityname
            ).first()
            
            if template_entry:
                self.populate_from_template(template_entry)
                return True
            return False
        except ImportError:
            return False

    def get_cve_list(self):
        """Get list of CVE IDs"""
        if self.cve and isinstance(self.cve, list):
            return self.cve
        elif self.cve:
            return [self.cve]
        return []
    
    def get_cwe_list(self):
        """Get list of CWE IDs"""
        if self.cwe and isinstance(self.cwe, list):
            return self.cwe
        elif self.cwe:
            return [self.cwe]
        return []
    
    def __str__(self):
        return self.vulnerabilityname


class VulnerableInstance(models.Model):
    vulnerabilityid = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='instances')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, blank=True, null=True)
    URL = models.CharField(max_length=1000, default=None, blank=True, null=True)
    Parameter = models.CharField(max_length=1000, default=None, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=VULNERABLE)

    def save(self, *args, **kwargs):
        existing_instances = VulnerableInstance.objects.filter(
            vulnerabilityid=self.vulnerabilityid, URL=self.URL, Parameter=self.Parameter
        ).exists()
        if existing_instances:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "Duplicate VulnerableInstance skipped: vuln=%s URL=%s Param=%s",
                self.vulnerabilityid_id, self.URL, self.Parameter
            )
            return
        else:
            super(VulnerableInstance, self).save(*args, **kwargs)


__all__ = [
    'Project', 'Vulnerability', 'VulnerableInstance', 'ProjectScope',
]
