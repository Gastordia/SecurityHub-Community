from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from .models import Project, Vulnerability, VulnerableInstance
from utils.project_status import update_project_status as update_project_status_Utils
VULNERABLE = 'Vulnerable'
CONFIRMED = 'Confirm Fixed'
ACCEPTED_RISK = 'Accepted Risk'
STATUS_CHOICES = [
        (VULNERABLE, 'Vulnerable'),
        (CONFIRMED, 'Confirm Fixed'),
        (ACCEPTED_RISK, 'Accepted Risk'),
    ]

@receiver(post_save, sender=Vulnerability)
def update_vulnerability(sender, instance, created, **kwargs):
    # Status derivation from instances is handled by update_vulnerableinstance below.
    # Doing it here as well would override status changes made directly by the user
    # (e.g. manually marking a vulnerability as Confirm Fixed via the API).
    pass

@receiver(post_save, sender=VulnerableInstance)
def update_vulnerableinstance(sender, instance, created, **kwargs):
    """
    Update vulnerability status based on instance statuses.
    Only runs on instance updates (not creation) to avoid overriding user-set status during vulnerability creation.
    """
    # Only update status when instances are modified, not when they're first created
    # This prevents overriding the status set by the user during vulnerability creation
    if created:
        return
    
    try:
        vulnerability = Vulnerability.objects.get(id=instance.vulnerabilityid.pk)
        totalinstances = VulnerableInstance.objects.filter(vulnerabilityid=instance.vulnerabilityid.pk)
        
        # Don't update if no instances exist
        if not totalinstances.exists():
            return

        has_vulnerable = totalinstances.filter(status=VULNERABLE).exists()
        has_accepted_risk = totalinstances.filter(status=ACCEPTED_RISK).exists()
        has_confirm_fix = totalinstances.filter(status=CONFIRMED).count() == totalinstances.count()
        
        # Store original status to detect changes
        original_status = vulnerability.status
        status_changed = False

        # Determine new status based on instance statuses
        if has_vulnerable:
            new_status = VULNERABLE
        elif has_accepted_risk:
            new_status = ACCEPTED_RISK
        elif has_confirm_fix:
            new_status = CONFIRMED
        else:
            # If no instances match any status, keep current status (don't change)
            new_status = original_status

        # Only update if status actually changed
        if new_status != original_status:
            status_changed = True
            vulnerability.status = new_status
            
            # Set fixed_date when changing to CONFIRMED status
            if new_status == CONFIRMED and not vulnerability.fixed_date:
                vulnerability.fixed_date = timezone.now()
            # Clear fixed_date if status is changing from CONFIRMED to something else
            elif original_status == CONFIRMED and new_status != CONFIRMED:
                vulnerability.fixed_date = None

        # Only save if status changed to avoid unnecessary updates
        if status_changed:
            vulnerability.save(update_fields=['status', 'fixed_date'])
    except Vulnerability.DoesNotExist:
        # Vulnerability doesn't exist yet (shouldn't happen, but handle gracefully)
        pass
    except Exception as e:
        # Log error but don't break the save
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error updating vulnerability status from instance: {e}")

@receiver(models.signals.post_save, sender=Project)
def update_project_status(sender, instance, **kwargs):
    # For new projects, just use the calculated status (based on dates)
    if instance.id is None:
        pass
    else:
        try:
            update_project_status_Utils(instance)
        except Exception as e:
            # Tolerate failures during fixture loading (e.g. loaddata, where related
            # rows may not exist yet) but keep the failure visible for real bugs.
            import logging
            logging.getLogger(__name__).warning(f"Error updating project status for project {instance.id}: {e}")


