"""
WSGI config for SecurityHub project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/wsgi/
"""

import os
from django.core.wsgi import get_wsgi_application
from .init import current_version


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securityhub.settings')
application = get_wsgi_application()

# Print banner only in the master process (worker_id is absent), not in each forked worker.
if not os.environ.get('_SECURITYHUB_BANNER_PRINTED'):
    os.environ['_SECURITYHUB_BANNER_PRINTED'] = '1'
    BANNER, COPYRIGHT = current_version()
    print(BANNER + COPYRIGHT)
