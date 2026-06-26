"""
Structured logging helpers for consistent logging across the application.

This module provides helper functions for structured logging that ensure:
- Consistent log format across all views
- Request context (request_id, user, org) in all logs
- Proper error logging with context
- Performance logging for slow operations

Usage:
    from utils.logging_helpers import log_view_start, log_view_success, log_view_error
    
    def my_view(request):
        log_view_start('my_view', request)
        try:
            # ... view logic ...
            log_view_success('my_view', request, {'result_count': 10})
        except Exception as e:
            log_view_error('my_view', request, e)
            raise
"""
import logging
import time
from typing import Optional, Dict, Any
from django.utils import timezone

logger = logging.getLogger(__name__)


def get_request_context(request: Any) -> Dict[str, Any]:
    """
    Extract standardized request context for logging.
    
    Returns:
        Dictionary with request_id, user_id, org_id, ip_address, etc.
    """
    context = {
        'request_path': request.path,
        'request_method': request.method,
    }
    
    # Request ID (from middleware)
    if hasattr(request, 'request_id'):
        context['request_id'] = request.request_id
    
    # User context
    if hasattr(request, 'user') and request.user.is_authenticated:
        context['user_id'] = request.user.id
        if hasattr(request.user, 'email'):
            context['user_email'] = request.user.email
    
    # IP address
    ip_address = _get_client_ip(request)
    if ip_address:
        context['ip_address'] = ip_address
    
    # User agent
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    if user_agent:
        context['user_agent'] = user_agent[:100]  # Truncate
    
    return context


def log_view_start(
    view_name: str,
    request: Any,
    additional_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Log the start of a view execution.
    
    Args:
        view_name: Name of the view function/class
        request: Django request object
        additional_context: Additional context to include
        
    Returns:
        Dictionary with start_time for use in log_view_success/error
    """
    context = get_request_context(request)
    context['view_name'] = view_name
    context['operation'] = f'{view_name}_start'
    context['start_time'] = time.time()
    
    if additional_context:
        context.update(additional_context)
    
    logger.debug(
        f"View started: {view_name}",
        extra=context
    )
    
    return context


def log_view_success(
    view_name: str,
    request: Any,
    additional_context: Optional[Dict[str, Any]] = None,
    start_time: Optional[float] = None
) -> None:
    """
    Log successful view execution.
    
    Args:
        view_name: Name of the view function/class
        request: Django request object
        additional_context: Additional context (e.g., result_count, created_id)
        start_time: Start time from log_view_start (for duration calculation)
    """
    context = get_request_context(request)
    context['view_name'] = view_name
    context['operation'] = f'{view_name}_success'
    context['status'] = 'success'
    
    # Calculate duration if start_time provided
    if start_time:
        duration = time.time() - start_time
        context['duration_ms'] = round(duration * 1000, 2)
        
        # Log warning if operation is slow
        if duration > 2.0:  # 2 seconds
            logger.warning(
                f"Slow operation detected: {view_name} took {duration:.2f}s",
                extra=context
            )
    
    if additional_context:
        context.update(additional_context)
    
    logger.info(
        f"View completed: {view_name}",
        extra=context
    )


def log_view_error(
    view_name: str,
    request: Any,
    error: Exception,
    additional_context: Optional[Dict[str, Any]] = None,
    exc_info: bool = True,
    level: str = 'error'
) -> None:
    """
    Log view error with full context.
    
    Args:
        view_name: Name of the view function/class
        request: Django request object
        error: Exception that occurred
        additional_context: Additional context
        exc_info: Include exception traceback
        level: Log level ('error', 'warning', 'critical')
    """
    context = get_request_context(request)
    context['view_name'] = view_name
    context['operation'] = f'{view_name}_error'
    context['status'] = 'error'
    context['error'] = str(error)
    context['error_type'] = type(error).__name__
    
    if additional_context:
        context.update(additional_context)
    
    log_method = getattr(logger, level, logger.error)
    log_method(
        f"View error: {view_name} - {type(error).__name__}: {str(error)}",
        exc_info=exc_info,
        extra=context
    )


def log_view_warning(
    view_name: str,
    request: Any,
    message: str,
    additional_context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log a warning in a view.
    
    Args:
        view_name: Name of the view function/class
        request: Django request object
        message: Warning message
        additional_context: Additional context
    """
    context = get_request_context(request)
    context['view_name'] = view_name
    context['operation'] = f'{view_name}_warning'
    context['warning_message'] = message
    
    if additional_context:
        context.update(additional_context)
    
    logger.warning(
        f"View warning: {view_name} - {message}",
        extra=context
    )


def log_performance(
    operation_name: str,
    duration_ms: float,
    request: Optional[Any] = None,
    additional_context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log performance metrics for an operation.
    
    Args:
        operation_name: Name of the operation
        duration_ms: Duration in milliseconds
        request: Django request object (optional)
        additional_context: Additional context
    """
    context = {
        'operation': operation_name,
        'duration_ms': duration_ms,
        'performance_event': True,
    }
    
    if request:
        request_context = get_request_context(request)
        context.update(request_context)
    
    if additional_context:
        context.update(additional_context)
    
    # Log as warning if slow
    if duration_ms > 1000:  # > 1 second
        logger.warning(
            f"Slow operation: {operation_name} took {duration_ms}ms",
            extra=context
        )
    else:
        logger.debug(
            f"Operation: {operation_name} took {duration_ms}ms",
            extra=context
        )


def log_data_operation(
    operation: str,
    model_name: str,
    instance_id: Optional[int] = None,
    request: Optional[Any] = None,
    additional_context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log a data operation (create, update, delete).
    
    Args:
        operation: Operation type ('CREATE', 'UPDATE', 'DELETE', 'READ')
        model_name: Name of the model
        instance_id: ID of the instance (optional)
        request: Django request object (optional)
        additional_context: Additional context
    """
    context = {
        'operation': f'{operation}_{model_name}',
        'model_name': model_name,
        'instance_id': instance_id,
        'data_operation': True,
    }
    
    if request:
        request_context = get_request_context(request)
        context.update(request_context)
    
    if additional_context:
        context.update(additional_context)
    
    logger.info(
        f"Data operation: {operation} {model_name}",
        extra=context
    )


def _get_client_ip(request: Any) -> Optional[str]:
    """Extract client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip











