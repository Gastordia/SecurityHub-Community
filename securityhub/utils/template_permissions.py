"""
Template permission helpers (community edition).

All staff/superuser users have full access. Non-staff users are granted
access only to templates they created. There is no per-object permission
table in the community edition.
"""


def has_template_permission(user, template, permission_type, organization=None):
    if user.is_superuser or user.is_staff:
        return True
    return hasattr(template, 'created_by') and template.created_by == user


def can_view_template(user, template, organization=None):
    return has_template_permission(user, template, 'viewer', organization)


def can_edit_template(user, template, organization=None):
    return has_template_permission(user, template, 'collaborator', organization)


def can_delete_template(user, template, organization=None):
    return has_template_permission(user, template, 'owner', organization)


def can_publish_template(user, template, organization=None):
    return has_template_permission(user, template, 'publisher', organization)
