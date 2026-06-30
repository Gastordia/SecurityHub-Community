from django.utils import timezone
from .models import Project
from utils.email_notification import send_completion_notification, send_hold_notification
import logging

logger = logging.getLogger(__name__)


def enrich_vulnerability_cve(vulnerability_id):
    """
    Fetch CVE details from NVD and EPSS score from FIRST.org for the first CVE ID
    on the given Vulnerability, then persist the results.

    Sets cve_enrichment_status to:
      'skipped'   — vulnerability has no CVE IDs
      'enriched'  — at least one API returned useful data
      'not_found' — NVD explicitly returned an empty result and EPSS had no data
      (unchanged) — network/unexpected error; status stays 'pending'
    """
    import requests
    from .models import Vulnerability

    try:
        vuln = Vulnerability.objects.get(pk=vulnerability_id)
    except Vulnerability.DoesNotExist:
        logger.warning('enrich_vulnerability_cve: Vulnerability %s not found', vulnerability_id)
        return

    cve_list = vuln.get_cve_list()
    if not cve_list:
        vuln.cve_enrichment_status = 'skipped'
        vuln.save(update_fields=['cve_enrichment_status'])
        return

    cve_id = cve_list[0]
    nvd_found = False
    nvd_not_found = False
    epss_found = False

    # --- NVD API ---
    try:
        resp = requests.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params={'cveId': cve_id},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            nvd_vulns = data.get('vulnerabilities', [])
            if nvd_vulns:
                cve_data = nvd_vulns[0].get('cve', {})

                # English description
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        vuln.nvd_description = desc.get('value', '')
                        break

                # CVSS v3.1 first, then v3.0 fallback
                metrics = cve_data.get('metrics', {})
                cvss_v3_list = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30', [])
                if cvss_v3_list:
                    cvss_data = cvss_v3_list[0].get('cvssData', {})
                    if cvss_data.get('baseScore') is not None:
                        vuln.cvssscore = cvss_data['baseScore']
                    if cvss_data.get('vectorString'):
                        vuln.cvssvector = cvss_data['vectorString']

                nvd_found = True
            else:
                nvd_not_found = True
    except Exception as exc:
        logger.warning('enrich_vulnerability_cve: NVD request failed for %s: %s', cve_id, exc)

    # --- EPSS API ---
    try:
        resp = requests.get(
            'https://api.first.org/data/v1/epss',
            params={'cve': cve_id},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            epss_list = data.get('data', [])
            if epss_list:
                vuln.epss_score = float(epss_list[0].get('epss', 0))
                vuln.epss_percentile = float(epss_list[0].get('percentile', 0))
                epss_found = True
    except Exception as exc:
        logger.warning('enrich_vulnerability_cve: EPSS request failed for %s: %s', cve_id, exc)

    # Determine enrichment status
    if nvd_found or epss_found:
        vuln.cve_enrichment_status = 'enriched'
    elif nvd_not_found and not epss_found:
        vuln.cve_enrichment_status = 'not_found'
    # else: leave as 'pending' (network/unexpected error)

    vuln.enriched_at = timezone.now()
    vuln.save(update_fields=[
        'cve_enrichment_status',
        'enriched_at',
        'nvd_description',
        'epss_score',
        'epss_percentile',
        'cvssscore',
        'cvssvector',
    ])


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
