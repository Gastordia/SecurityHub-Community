import logging
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from functools import wraps

from project.models import Project
from project.services.project_contacts import get_project_manager_queryset

logger = logging.getLogger(__name__)


def email_enabled_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if settings.USE_EMAIL == "False":
            return True
        return func(*args, **kwargs)
    return wrapper


def _get_url_data(project_id):
    base_url = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "#"
    if base_url != "#" and not base_url.startswith(('http://', 'https://')):
        base_url = f"https://{base_url}"
    return {
        'base_url': base_url,
        'project_url': f"{base_url}/project/{project_id}",
        'logo_url': f"{base_url}/static/images/logo.png" if base_url != "#" else "#",
    }


@email_enabled_check
def _send_email_notification(subject, template_name, context, to_recipients, cc_recipients):
    try:
        html_message = render_to_string(f'email/{template_name}', context)
        plain_message = strip_tags(html_message)
        email = EmailMultiAlternatives(
            subject=subject,
            body=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=to_recipients,
            cc=cc_recipients,
        )
        email.attach_alternative(html_message, "text/html")
        email.send(fail_silently=False)
        logger.info(f"Email '{subject}' sent successfully")
        return True
    except Exception as e:
        logger.error(f"Error sending email notification: {str(e)}")
        return False


def send_completion_notification(project_id, is_retest=False):
    try:
        project = Project.objects.get(id=project_id)
        url_data = _get_url_data(project.id)
        pm_qs = get_project_manager_queryset(project)
        to_recipients = list(pm_qs.values_list('email', flat=True))
        if not to_recipients:
            return False
        context = {
            'project': project,
            'project_name': project.name,
            'project_url': url_data['project_url'],
        }
        return _send_email_notification(
            subject=f"Project Completed: {project.name}",
            template_name='Project-Complete.html',
            context=context,
            to_recipients=to_recipients,
            cc_recipients=[],
        )
    except Project.DoesNotExist:
        logger.error(f"Project {project_id} not found when sending completion email")
        return False
    except Exception as e:
        logger.error(f"Error sending completion email for project {project_id}: {str(e)}")
        return False


def send_hold_notification(project_id, is_retest=False):
    try:
        project = Project.objects.get(id=project_id)
        url_data = _get_url_data(project.id)
        pm_qs = get_project_manager_queryset(project)
        to_recipients = list(pm_qs.values_list('email', flat=True))
        if not to_recipients:
            return False
        context = {
            'project': project,
            'project_name': project.name,
            'hold_reason': project.hold_reason or "Not specified",
            'project_url': url_data['project_url'],
        }
        return _send_email_notification(
            subject=f"Project On Hold: {project.name}",
            template_name='Project-Hold.html',
            context=context,
            to_recipients=to_recipients,
            cc_recipients=[],
        )
    except Project.DoesNotExist:
        logger.error(f"Project {project_id} not found when sending hold email")
        return False
    except Exception as e:
        logger.error(f"Error sending hold email for project {project_id}: {str(e)}")
        return False


def send_project_completion_email(project_id):
    return send_completion_notification(project_id)
