from django.urls import path

from . import views

urlpatterns = [
    path('', views.project_assets, name='asset-list'),
    path('<uuid:asset_id>/', views.asset_detail, name='asset-detail'),
]
