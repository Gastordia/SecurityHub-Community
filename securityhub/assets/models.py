import uuid
from django.db import models


CRITICALITY_CHOICES = [
    ('critical', 'Critical'),
    ('high', 'High'),
    ('medium', 'Medium'),
    ('low', 'Low'),
    ('unknown', 'Unknown'),
]


class Asset(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('project.Project', on_delete=models.CASCADE, related_name='assets')
    ip = models.GenericIPAddressField(null=True, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    os = models.CharField(max_length=100, blank=True)
    tags = models.JSONField(default=list, blank=True)
    criticality = models.CharField(max_length=20, choices=CRITICALITY_CHOICES, default='unknown')
    # Many-to-many link to vulnerabilities (a finding can affect multiple assets)
    vulnerabilities = models.ManyToManyField('project.Vulnerability', blank=True, related_name='assets')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['hostname', 'ip']
        unique_together = [['project', 'ip', 'hostname']]  # avoid duplicates per project

    def __str__(self):
        return self.hostname or str(self.ip) or str(self.id)

    @property
    def risk_score(self):
        """Weighted risk score: critical=10, high=7, medium=4, low=1."""
        weight = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1, 'Informational': 0}
        total = 0
        for v in self.vulnerabilities.all():
            total += weight.get(v.vulnerabilityseverity, 0)
        return total
