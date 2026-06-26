from django.utils import timezone
from .models import Project
from utils.email_notification import send_completion_notification, send_hold_notification
import logging

logger = logging.getLogger(__name__)


def update_project_status():
    from django.db import transaction

    today = timezone.now().date()
    projects = Project.objects.exclude(status__in=['Completed', 'On Hold'])

    for project in projects:
        try:
            with transaction.atomic():
                project = Project.objects.select_for_update().get(pk=project.pk)
                if project.status in ['Completed', 'On Hold']:
                    continue

                if today < project.startdate:
                    new_status = 'Upcoming'
                elif project.startdate <= today <= project.enddate:
                    new_status = 'In Progress'
                else:
                    new_status = 'Delay'

                if project.status != new_status:
                    project.status = new_status
                    project.save()
                    logger.info(f"Updated project {project.id} status: {project.status} → {new_status}")
        except Exception as e:
            logger.error(f"Error updating project {project.id} status: {e}", exc_info=True)
            continue


def send_completion_email(entity_id):
    send_completion_notification(entity_id, False)


def send_hold_email(entity_id):
    send_hold_notification(entity_id, False)
