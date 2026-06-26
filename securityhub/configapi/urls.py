from django.urls import path
from .views.config import (
    list_report_standards,
    edit_report_standard,
    sync_report_standards_from_github,
    list_project_types,
    edit_project_type,
    sync_project_types_from_github,
    ping,
)

urlpatterns = [
    # =========================================================================
    # REPORT STANDARDS
    # =========================================================================
    path('report-standards/', list_report_standards, name='report-standard-list'),
    path('report-standards/sync/', sync_report_standards_from_github, name='report-standard-sync'),
    path('report-standards/<str:id>/', edit_report_standard, name='report-standard-update'),

    # =========================================================================
    # PROJECT TYPES
    # =========================================================================
    path('project-types/', list_project_types, name='project-type-list'),
    path('project-types/sync/', sync_project_types_from_github, name='project-type-sync'),
    path('project-types/<str:id>/', edit_project_type, name='project-type-update'),

    # =========================================================================
    # HEALTH CHECK
    # =========================================================================
    path('ping/', ping, name='ping'),
]
