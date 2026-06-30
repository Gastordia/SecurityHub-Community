"""
Import required Django classes and methods.
CKEditor image upload has custom REST API to upload images
Default ckeditor image handler only requires for Django Admin
"""

from django.urls import path, include,re_path
from django.conf import settings
from django.conf.urls.static import serve
from django.contrib import admin
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework.permissions import IsAuthenticated

urlpatterns = [
    path('api/project/',include('project.urls')),
    path('api/vulndb/',include('vulnerability.urls')),
    path('api/auth/',include('accounts.urls')),
    path('api/config/', include('configapi.urls')),
    path('api/health/', include('utils.urls_health')),
    path('api/webhooks/', include('webhooks.urls')),
    path('api/dashboard/', include('dashboard.urls')),

    path('api/schema/', SpectacularAPIView.as_view(permission_classes=[IsAuthenticated]), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(permission_classes=[IsAuthenticated], url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(permission_classes=[IsAuthenticated], url_name='schema'), name='redoc'),
]

if settings.DEBUG:
    try:
        import debug_toolbar
        urlpatterns += [path("__debug__/", include("debug_toolbar.urls"))]
    except ImportError:
        pass

    urlpatterns += [
        path('admin/', admin.site.urls),
        re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT,}),
        re_path(r'^static-report/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
    ]
    
    # Only serve index.html if it exists (allows direct backend access without crashing if frontend not built/linked)
    from django.template.loader import get_template
    from django.template import TemplateDoesNotExist
    try:
        get_template('index.html')
        urlpatterns += [path('', TemplateView.as_view(template_name='index.html'))]
    except TemplateDoesNotExist:
        # Redirect or show simple API message if index.html is missing
        urlpatterns += [path('', lambda request: TemplateView.as_view(template_name='index.html')(request) if False else __import__('django.http').http.HttpResponse("SecurityHub API is running. Access the frontend via Nginx (port 80) or API Docs at /api/docs/."))]
