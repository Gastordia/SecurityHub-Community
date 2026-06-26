"""
Audit Log Model for Django
Stores audit logs in database for queryable audit trail
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import json

User = get_user_model()


class AuditLog(models.Model):
    """
    Database model for storing audit logs.
    
    This model stores all audit events for compliance, security monitoring,
    and forensic analysis. All fields are indexed for efficient querying.
    """
    
    # Event identification
    event_type = models.CharField(
        max_length=50,
        choices=[
            ('AUDIT', 'Audit Event'),
            ('SECURITY_EVENT', 'Security Event'),
            ('DATA_ACCESS', 'Data Access'),
        ],
        default='AUDIT',
        db_index=True,
        help_text='Type of audit event'
    )
    
    # User context
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        db_index=True,
        help_text='User who performed the action (null for system actions)'
    )
    # Note: user_id is automatically created by Django for the ForeignKey above
    user_email = models.EmailField(null=True, blank=True, db_index=True)
    username = models.CharField(max_length=150, null=True, blank=True, db_index=True)
    
    # Organization context
    org_id = models.UUIDField(null=True, blank=True, db_index=True)
    org_name = models.CharField(max_length=255, null=True, blank=True)
    
    # Action details
    action = models.CharField(max_length=100, db_index=True, help_text='Action performed')
    resource_type = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        db_index=True,
        help_text='Type of resource (Project, User, Vulnerability, etc.)'
    )
    resource_id = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    
    # Request context
    request_id = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    request_path = models.CharField(max_length=500, null=True, blank=True)
    request_method = models.CharField(max_length=10, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.TextField(null=True, blank=True)
    
    # Event details
    details = models.JSONField(
        null=True,
        blank=True,
        help_text='Additional event details as JSON'
    )
    
    # Security and compliance flags
    security_event = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    compliance_required = models.BooleanField(default=False, db_index=True)
    security_required = models.BooleanField(default=False, db_index=True)
    
    # Timestamp
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        db_table = 'audit_log'
        ordering = ['-timestamp', '-created_at']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user', '-timestamp']),  # user_id is the actual column name
            models.Index(fields=['org_id', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['event_type', '-timestamp']),
            models.Index(fields=['compliance_required', '-timestamp']),
            models.Index(fields=['security_required', '-timestamp']),
        ]
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
    
    def __str__(self):
        return f"{self.action} by {self.username or 'System'} at {self.timestamp}"
    
    def to_dict(self):
        """Convert audit log to dictionary for API responses"""
        return {
            'id': self.id,
            'event_type': self.event_type,
            'user': {
                'id': self.user.id if self.user else None,
                'email': self.user_email,
                'username': self.username,
            } if self.user else None,
            'organization': {
                'id': self.org_id,
                'name': self.org_name,
            } if self.org_id else None,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'request': {
                'id': self.request_id,
                'path': self.request_path,
                'method': self.request_method,
            } if self.request_id else None,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'details': self.details,
            'security_event': self.security_event,
            'compliance_required': self.compliance_required,
            'security_required': self.security_required,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

