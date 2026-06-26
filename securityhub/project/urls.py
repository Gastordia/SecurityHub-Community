from django.urls import path
from .views import project, image_upload, scope, parser
from .views import vulnerability_crud, vulnerability_instances
from .views.image_upload import GetImageView

urlpatterns = [
    # ========================================================================
    # PROJECTS - Collection Operations
    # ========================================================================
    path('projects/', project.GetAllProjects.as_view(), name='project-list'),
    path('dashboard/summary/', project.dashboard_summary, name='dashboard-summary'),
    path('projects/filter/', project.get_all_projects_filter, name='project-filter'),
    path('projects/mine/', project.GetMyProjects.as_view(), name='project-mine'),

    # ========================================================================
    # PROJECTS - Item Operations
    # ========================================================================
    path('projects/<str:id>/', project.getproject, name='project-detail'),

    # ========================================================================
    # PROJECTS - Actions
    # ========================================================================
    path('projects/<str:id>/report/', project.project_report, name='project-report'),

    # ========================================================================
    # PROJECT SCOPES - Nested Resource
    # ========================================================================
    path('projects/<str:id>/scopes/', scope.get_project_scopes, name='project-scope-list'),
    path('projects/<str:id>/scopes/upload-nmap/', scope.upload_nmap_scope, name='project-scope-upload-nmap'),
    path('projects/<str:id>/scopes/<str:scope_id>/', scope.project_scope_edit, name='project-scope-update'),

    # ========================================================================
    # PROJECT VULNERABILITIES - Nested Resource
    # ========================================================================
    path('projects/<str:id>/instances/', vulnerability_instances.project_all_instances, name='project-all-instances'),
    path('projects/<str:id>/vulnerabilities/', vulnerability_crud.project_vuln_view, name='project-vulnerability-list'),
    path('projects/<str:id>/findings/', vulnerability_crud.project_finding_view, name='project-finding-list'),
    path('projects/<str:id>/vulnerabilities/statistics/', vulnerability_crud.get_vulnerability_stats, name='project-vulnerability-stats'),

    # ========================================================================
    # VULNERABILITIES - Standalone Operations
    # ========================================================================
    path('vulnerabilities/<str:id>/', vulnerability_crud.vulnerability_view, name='vulnerability-detail'),
    path('vulnerabilities/<str:id>/status/', vulnerability_crud.project_vulnerability_status, name='vulnerability-status'),

    # ========================================================================
    # VULNERABILITY INSTANCES - Nested Resource
    # ========================================================================
    path('vulnerabilities/<str:id>/instances/', vulnerability_instances.project_vuln_instances, name='vulnerability-instance-list'),
    path('vulnerabilities/<str:id>/instances/filter/', vulnerability_instances.project_vuln_instances_filter, name='vulnerability-instance-filter'),
    path('vulnerabilities/<str:id>/instances/status/', vulnerability_instances.project_instances_status, name='vulnerability-instance-status'),
    path('vulnerabilities/<str:id>/instances/<str:instance_id>/', vulnerability_instances.project_edit_instances, name='vulnerability-instance-update'),

    # ========================================================================
    # PARSER INTEGRATION
    # ========================================================================
    path('projects/<str:project_id>/parser/upload/', parser.upload_project_parser_file, name='project-parser-upload'),
    path('parser/upload/', parser.upload_parser_file, name='parser-upload-universal'),
    path('parser/scanners/', parser.get_supported_scanners, name='parser-scanners'),

    # ========================================================================
    # IMAGE MANAGEMENT
    # ========================================================================
    path('images/upload/', image_upload.ImageUploadView.as_view(), name='image-upload'),
    path('images/<str:id>/', GetImageView.as_view(), name='image-detail'),
]
