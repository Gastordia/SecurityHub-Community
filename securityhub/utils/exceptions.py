"""
Global DRF exception handler to standardize error responses and logging.
"""
import logging
from rest_framework.views import exception_handler as drf_default_handler
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)


def redact_sensitive(data):
    if not isinstance(data, dict):
        return data
    redacted = {}
    for k, v in data.items():
        if k.lower() in {"password", "token", "secret", "authorization", "auth", "jwt"}:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def drf_exception_handler(exc, context):
    response = drf_default_handler(exc, context)
    request = context.get('request')

    request_id = getattr(request, 'request_id', 'unknown') if request else 'unknown'
    user_id = getattr(request.user, 'id', None) if request and hasattr(request, 'user') else None

    if response is not None:
        payload = {
            "code": None,
            "detail": None,
        }

        if isinstance(response.data, dict):
            payload["code"] = response.data.get("code") or response.data.get("detail") or response.status_code
            payload["detail"] = response.data.get("detail") or response.data
        else:
            payload["detail"] = response.data

        # Standard error envelope
        standardized = {
            "request_id": request_id,
            "error": payload,
        }

        # Log denied/failed
        level = logging.ERROR if response.status_code >= 500 else logging.WARNING
        logger.log(level, "Request failed", extra={
            "request_id": request_id,
            "user_id": user_id,
            "status_code": response.status_code,
            "exception": type(exc).__name__,
        })

        return Response(standardized, status=response.status_code)

    # Unhandled exceptions -> 500
    logger.error("Unhandled exception", extra={
        "request_id": request_id,
        "user_id": user_id,
        "exception": type(exc).__name__,
    })
    return Response({
        "request_id": request_id,
        "error": {
            "code": "SERVER_ERROR",
            "detail": "An unexpected error occurred.",
        }
    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


