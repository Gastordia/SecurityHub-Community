from accounts.models import CustomUser


def get_project_manager_queryset(project):
    """Return active project owners, or all active staff if no owners set."""
    owner_ids = list(
        project.owner.filter(is_active=True).values_list("id", flat=True)
    )
    if owner_ids:
        return CustomUser.objects.filter(id__in=owner_ids, is_active=True).distinct()
    return CustomUser.objects.filter(is_active=True, is_staff=True).distinct()
