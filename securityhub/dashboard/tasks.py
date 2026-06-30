import logging
from datetime import date

logger = logging.getLogger(__name__)


def take_daily_snapshot(project=None):
    """
    Take a daily snapshot of open vulnerability counts for all active projects,
    or for a single project when `project` is passed.

    Call this daily (e.g. via a cron or management command).
    """
    from project.models import Project, Vulnerability
    from .models import DashboardSnapshot

    today = date.today()

    if project is not None:
        projects = [project]
    else:
        projects = list(Project.objects.exclude(status='Completed'))

    for proj in projects:
        vulns = Vulnerability.objects.filter(project=proj)
        open_vulns = vulns.filter(status='Vulnerable')

        counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0,
        }
        for v in open_vulns:
            sev = v.vulnerabilityseverity or 'Low'
            if sev in counts:
                counts[sev] += 1

        def mttr(severity):
            fixed_today = vulns.filter(
                vulnerabilityseverity=severity,
                status='Confirm Fixed',
                fixed_date__date=today,
            ).exclude(created=None)
            if not fixed_today.exists():
                return None
            days_list = [
                (v.fixed_date - v.created).days
                for v in fixed_today
                if v.fixed_date and v.created
            ]
            return sum(days_list) / len(days_list) if days_list else None

        DashboardSnapshot.objects.update_or_create(
            project=proj,
            date=today,
            defaults={
                'critical_open': counts['Critical'],
                'high_open': counts['High'],
                'medium_open': counts['Medium'],
                'low_open': counts['Low'],
                'informational_open': counts['Informational'],
                'total_open': sum(counts.values()),
                'mttr_critical': mttr('Critical'),
                'mttr_high': mttr('High'),
                'mttr_medium': mttr('Medium'),
                'mttr_low': mttr('Low'),
            },
        )
        logger.info('Snapshot taken for project %s on %s', proj.id, today)
