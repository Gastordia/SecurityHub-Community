import uuid
from django.db import models


class DashboardSnapshot(models.Model):
    """Daily snapshot of open vulnerability counts per severity, per project."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        'project.Project',
        on_delete=models.CASCADE,
        related_name='snapshots',
    )
    date = models.DateField()  # snapshot date
    # Open finding counts (status = 'Vulnerable')
    critical_open = models.IntegerField(default=0)
    high_open = models.IntegerField(default=0)
    medium_open = models.IntegerField(default=0)
    low_open = models.IntegerField(default=0)
    informational_open = models.IntegerField(default=0)
    total_open = models.IntegerField(default=0)
    # Mean time to remediate (days) for findings closed on this date
    mttr_critical = models.FloatField(null=True, blank=True)
    mttr_high = models.FloatField(null=True, blank=True)
    mttr_medium = models.FloatField(null=True, blank=True)
    mttr_low = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [['project', 'date']]
        ordering = ['-date']
