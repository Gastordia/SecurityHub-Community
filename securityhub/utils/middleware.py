"""
Request ID middleware for the community edition.
Sets request.request_id for log correlation.
Organization and membership context are not used in the community edition.
"""
import logging
import uuid
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class RequestIdMiddleware(MiddlewareMixin):
    """
    Lightweight middleware that attaches a unique request ID and stubs out the
    tenant/membership attributes so view code that checks them gracefully gets None.
    """

    def process_request(self, request):
        request_id_header = request.META.get('HTTP_X_REQUEST_ID')
        if request_id_header:
            request.request_id = request_id_header[:32]
        else:
            request.request_id = str(uuid.uuid4())[:8]

        request.organization = None
        request.membership = None
        request.capabilities = None

        return None
