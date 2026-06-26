"""
Audit logging service for compliance and security tracking.

This module provides a centralized audit logging service that:
- Logs all user actions for compliance (SOC 2, ISO 27001, etc.)
- Tracks data access patterns
- Records security events
- Provides structured logging for forensics

Usage:
    from utils.audit_logging import AuditLogger
    
    AuditLogger.log_operation(
        user=request.user,
        action='PROJECT_CREATED',
        resource_type='Project',
        resource_id=project.id,
        org_id=None,
        request=request,
        details={'project_name': project.name}
    )
"""
import logging
from typing import Optional, Dict, Any
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()

logger = logging.getLogger('audit')


class AuditLogger:
    """
    Centralized audit logging service for tracking user actions and security events.
    
    All audit logs are automatically structured with:
    - User identification
    - Organization context
    - Request correlation (request_id)
    - Timestamp
    - IP address and user agent
    - Action details
    """
    
    # Security event types
    SECURITY_EVENTS = {
        'LOGIN_SUCCESS',
        'LOGIN_FAILURE',
        'LOGOUT',
        'PASSWORD_CHANGE',
        'PERMISSION_DENIED',
        'RATE_LIMIT_EXCEEDED',
        'SUSPICIOUS_ACTIVITY',
        'DATA_ACCESS',
        'DATA_MODIFICATION',
        'DATA_DELETION',
    }
    
    # Compliance-required actions (must be logged)
    COMPLIANCE_ACTIONS = {
        'USER_CREATED',
        'USER_DELETED',
        'USER_MODIFIED',
        'PROJECT_CREATED',
        'PROJECT_DELETED',
        'PROJECT_MODIFIED',
        'VULN_CREATED',
        'VULN_DELETED',
        'VULN_MODIFIED',
        'ASSET_CREATED',
        'ASSET_DELETED',
        'ASSET_MODIFIED',
        'FILE_UPLOADED',
        'FILE_DELETED',
        'REPORT_GENERATED',
        'PASSWORD_CHANGE',
        'PERMISSION_CHANGED',
    }
    
    @staticmethod
    def log_operation(
        user: Optional[Any] = None,
        action: str = '',
        resource_type: str = '',
        resource_id: Optional[int] = None,
        org_id: Optional[int] = None,
        request: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None,
        level: str = 'info'
    ) -> None:
        """
        Log a user operation for audit trail.
        
        Args:
            user: User instance (optional, can be None for system actions)
            action: Action type (e.g., 'PROJECT_CREATED', 'USER_DELETED')
            resource_type: Type of resource (e.g., 'Project', 'User', 'Vulnerability')
            resource_id: ID of the resource (optional)
            org_id: Organization ID (optional)
            request: Django request object (optional, for extracting context)
            details: Additional details as dict (optional)
            level: Log level ('info', 'warning', 'error')
        """
        # Build audit context
        audit_context = {
            'event_type': 'AUDIT',
            'action': action,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'timestamp': timezone.now().isoformat(),
            'audit_event': True,
            'compliance_required': action in AuditLogger.COMPLIANCE_ACTIONS,
        }
        
        # Add user context
        if user:
            if hasattr(user, 'id'):
                audit_context['user_id'] = str(user.id)
            if hasattr(user, 'email'):
                audit_context['user_email'] = user.email
            if hasattr(user, 'username'):
                audit_context['username'] = user.username
        
        # Add organization context
        if org_id:
            audit_context['org_id'] = str(org_id)
        
        # Extract request context
        if request:
            # Request ID (from middleware)
            if hasattr(request, 'request_id'):
                audit_context['request_id'] = request.request_id
            
            # IP address
            ip_address = AuditLogger._get_client_ip(request)
            if ip_address:
                audit_context['ip_address'] = ip_address
            
            # User agent
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            if user_agent:
                audit_context['user_agent'] = user_agent[:200]  # Truncate if too long
            
            # Request path and method
            audit_context['request_path'] = request.path
            audit_context['request_method'] = request.method
            
        # Add additional details
        if details:
            # Sanitize details to remove sensitive data
            sanitized_details = AuditLogger._sanitize_details(details)
            audit_context['details'] = sanitized_details
        
        # Determine log level
        log_method = getattr(logger, level, logger.info)
        
        # Log the audit event
        log_method(
            f"Audit: {action}",
            extra=audit_context
        )
        
        # Also write to database for queryable audit trail
        try:
            from utils.models import AuditLog
            AuditLog.objects.create(
                event_type='AUDIT',
                user=user if user and hasattr(user, 'id') else None,
                user_email=audit_context.get('user_email'),
                username=audit_context.get('username'),
                org_id=audit_context.get('org_id'),
                org_name=audit_context.get('org_name'),
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                request_id=audit_context.get('request_id'),
                request_path=audit_context.get('request_path'),
                request_method=audit_context.get('request_method'),
                ip_address=audit_context.get('ip_address'),
                user_agent=audit_context.get('user_agent'),
                details=audit_context.get('details'),
                compliance_required=audit_context.get('compliance_required', False),
                timestamp=timezone.now(),
            )
        except Exception as e:
            # Don't fail if audit log write fails - log file is primary
            logger.error(f"Failed to write audit log to database: {e}", exc_info=True)
    
    @staticmethod
    def log_security_event(
        event_type: str,
        user: Optional[Any] = None,
        request: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: str = 'warning'
    ) -> None:
        """
        Log a security event (login failures, permission denials, etc.).
        
        Args:
            event_type: Type of security event (from SECURITY_EVENTS)
            user: User instance (optional)
            request: Django request object (optional)
            details: Additional details (optional)
            severity: Log severity ('warning' or 'error')
        """
        if event_type not in AuditLogger.SECURITY_EVENTS:
            logger.warning(
                f"Unknown security event type: {event_type}",
                extra={'event_type': event_type}
            )
        
        audit_context = {
            'event_type': 'SECURITY_EVENT',
            'security_event': event_type,
            'timestamp': timezone.now().isoformat(),
            'audit_event': True,
            'security_required': True,
        }
        
        # Add user context
        if user:
            if hasattr(user, 'id'):
                audit_context['user_id'] = str(user.id)
            if hasattr(user, 'email'):
                audit_context['user_email'] = user.email
        
        # Extract request context
        if request:
            if hasattr(request, 'request_id'):
                audit_context['request_id'] = request.request_id
            
            ip_address = AuditLogger._get_client_ip(request)
            if ip_address:
                audit_context['ip_address'] = ip_address
            
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            if user_agent:
                audit_context['user_agent'] = user_agent[:200]
            
            audit_context['request_path'] = request.path
            audit_context['request_method'] = request.method

        # Add details
        if details:
            sanitized_details = AuditLogger._sanitize_details(details)
            audit_context['details'] = sanitized_details

        # Log with appropriate severity
        log_method = getattr(logger, severity, logger.warning)
        log_method(
            f"Security Event: {event_type}",
            extra=audit_context
        )
        
        # Also write to database for queryable audit trail
        try:
            from utils.models import AuditLog
            AuditLog.objects.create(
                event_type='SECURITY_EVENT',
                user=user if user and hasattr(user, 'id') else None,
                user_email=audit_context.get('user_email'),
                username=audit_context.get('username'),
                org_id=audit_context.get('org_id'),
                org_name=audit_context.get('org_name'),
                action=event_type,
                resource_type=None,
                resource_id=None,
                request_id=audit_context.get('request_id'),
                request_path=audit_context.get('request_path'),
                request_method=audit_context.get('request_method'),
                ip_address=audit_context.get('ip_address'),
                user_agent=audit_context.get('user_agent'),
                details=audit_context.get('details'),
                security_event=event_type,
                security_required=True,
                timestamp=timezone.now(),
            )
        except Exception as e:
            # Don't fail if audit log write fails - log file is primary
            logger.error(f"Failed to write security event to database: {e}", exc_info=True)
    
    @staticmethod
    def log_data_access(
        user: Any,
        resource_type: str,
        action: str,
        org_id: Optional[int] = None,
        request: Optional[Any] = None,
        resource_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log data access for compliance tracking.
        
        Args:
            user: User instance
            resource_type: Type of resource accessed
            action: Action performed ('READ', 'LIST', 'SEARCH', etc.)
            org_id: Organization ID
            request: Django request object
            resource_id: ID of specific resource (optional)
            details: Additional details (optional)
        """
        # Build audit context
        audit_context = {
            'event_type': 'DATA_ACCESS',
            'action': f'{action}_{resource_type}',
            'resource_type': resource_type,
            'resource_id': resource_id,
            'timestamp': timezone.now().isoformat(),
            'audit_event': True,
        }
        
        # Add user context
        if user:
            if hasattr(user, 'id'):
                audit_context['user_id'] = str(user.id)
            if hasattr(user, 'email'):
                audit_context['user_email'] = user.email
            if hasattr(user, 'username'):
                audit_context['username'] = user.username
        
        # Add organization context
        if org_id:
            audit_context['org_id'] = str(org_id)
        
        # Extract request context
        if request:
            if hasattr(request, 'request_id'):
                audit_context['request_id'] = request.request_id
            
            ip_address = AuditLogger._get_client_ip(request)
            if ip_address:
                audit_context['ip_address'] = ip_address
            
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            if user_agent:
                audit_context['user_agent'] = user_agent[:200]
            
            audit_context['request_path'] = request.path
            audit_context['request_method'] = request.method

        # Add details
        if details:
            sanitized_details = AuditLogger._sanitize_details(details)
            audit_context['details'] = sanitized_details

        # Log to file
        logger.info(
            f"Data Access: {action} {resource_type}",
            extra=audit_context
        )
        
        # Also write to database
        try:
            from utils.models import AuditLog
            AuditLog.objects.create(
                event_type='DATA_ACCESS',
                user=user if user and hasattr(user, 'id') else None,
                user_email=audit_context.get('user_email'),
                username=audit_context.get('username'),
                org_id=audit_context.get('org_id'),
                org_name=audit_context.get('org_name'),
                action=f'{action}_{resource_type}',
                resource_type=resource_type,
                resource_id=resource_id,
                request_id=audit_context.get('request_id'),
                request_path=audit_context.get('request_path'),
                request_method=audit_context.get('request_method'),
                ip_address=audit_context.get('ip_address'),
                user_agent=audit_context.get('user_agent'),
                details=audit_context.get('details'),
                timestamp=timezone.now(),
            )
        except Exception as e:
            logger.error(f"Failed to write data access log to database: {e}", exc_info=True)
    
    @staticmethod
    def _get_client_ip(request: Any) -> Optional[str]:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get first IP in chain
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @staticmethod
    def _sanitize_details(details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize details dictionary to remove sensitive information.
        
        Removes or redacts:
        - Passwords
        - Tokens
        - API keys
        - Credit card numbers
        - SSNs
        """
        sanitized = {}
        sensitive_keys = {
            'password', 'passwd', 'pwd',
            'token', 'api_key', 'apikey', 'secret',
            'credit_card', 'cc_number', 'card_number',
            'ssn', 'social_security',
            'private_key', 'privatekey',
        }
        
        import uuid as _uuid
        for key, value in details.items():
            key_lower = key.lower()
            # Check if key contains sensitive substring
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = AuditLogger._sanitize_details(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    AuditLogger._sanitize_details(item) if isinstance(item, dict)
                    else (str(item) if isinstance(item, _uuid.UUID) else item)
                    for item in value
                ]
            elif isinstance(value, _uuid.UUID):
                sanitized[key] = str(value)
            else:
                sanitized[key] = value
        
        return sanitized


