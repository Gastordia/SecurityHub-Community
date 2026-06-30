from django.urls import path
from . import views

urlpatterns = [
    path('projects/<str:project_id>/trend/', views.project_trend, name='dashboard-trend'),
    path('projects/<str:project_id>/mttr/', views.project_mttr, name='dashboard-mttr'),
    path('projects/<str:project_id>/snapshot/', views.snapshot_now, name='dashboard-snapshot'),
]
