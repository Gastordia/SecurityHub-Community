"""
Report Context Builder - Builds report context data from project/mission.
Separated from template engine for proper architecture.
"""
import logging
from typing import Dict, Any, Optional
from project.models import Project, Vulnerability, VulnerableInstance, ProjectScope
from accounts.models import CustomUser
import pygal
from pygal.style import Style
from .project_contacts import get_project_manager_queryset

logger = logging.getLogger(__name__)


class ReportContextBuilder:
    """
    Builds report context data from project/mission domain models.
    This is domain logic, not template logic.
    """
    
    @staticmethod
    def build_project_context(
        project_id: int,
        report_type: str = 'Audit',
        standard: str = 'NIST',
        is_staff: bool = True
    ) -> Dict[str, Any]:
        """
        Build report context from project data.
        
        Args:
            project_id: Project ID
            report_type: Type of report (Audit, Re-Audit)
            standard: Report standard
            is_staff: Whether user is staff (affects vulnerability visibility)
        
        Returns:
            Dictionary with report context data
        """
        try:
            project = Project.objects.get(id=project_id)
            
            # Get vulnerabilities
            vuln = Vulnerability.objects.filter(project=project).order_by('-cvssscore')
            instances = VulnerableInstance.objects.filter(project=project)
            
            # Count by severity
            critical = vuln.filter(
                project=project,
                vulnerabilityseverity='Critical',
                status='Vulnerable'
            ).count()
            high = vuln.filter(
                project=project,
                vulnerabilityseverity='High',
                status='Vulnerable'
            ).count()
            medium = vuln.filter(
                project=project,
                vulnerabilityseverity='Medium',
                status='Vulnerable'
            ).count()
            low = vuln.filter(
                project=project,
                vulnerabilityseverity='Low',
                status='Vulnerable'
            ).count()
            info = vuln.filter(
                status='Vulnerable',
                vulnerabilityseverity__in=['Informational', 'None']
            ).count()
            
            # Create pie chart
            custom_style = Style(
                colors=("#FF491C", "#F66E09", "#FBBC02", "#20B803", "#3399FF"),
                background='transparent',
                plot_background='transparent',
                legend_font_size=0,
                legend_box_size=0,
                value_font_size=40
            )
            pie_chart = pygal.Pie(style=custom_style)
            pie_chart.legend_box_size = 0
            pie_chart.add('Critical', critical)
            pie_chart.add('High', high)
            pie_chart.add('Medium', medium)
            pie_chart.add('Low', low)
            pie_chart.add('Informational', info)
            
            # Get other data
            totalvulnerability = vuln.filter(project=project).count()
            mycompany = None
            projectscope = ProjectScope.objects.filter(project=project)
            totalretest = []
            
            projectmanagers = get_project_manager_queryset(project)
            
            customeruser = CustomUser.objects.none()
            
            # Build context (matching project/report.py structure)
            context = {
                'projectscope': projectscope,
                'totalvulnerability': totalvulnerability,
                'standard': standard,
                'Report_type': report_type,
                'mycomany': mycompany,
                'totalretest': totalretest,
                'vuln': vuln,
                'project': project,
                'ciritcal': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'info': info,
                'instances': instances,
                'projectmanagers': projectmanagers,
                'customeruser': customeruser,
                'pie_chart': pie_chart.render(is_unicode=True)
            }
            
            return context

        except Exception as e:
            logger.error(f"Error building project context: {str(e)}", exc_info=True)
            raise
