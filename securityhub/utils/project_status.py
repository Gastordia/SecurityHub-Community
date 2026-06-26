from django.utils import timezone


def update_project_status(project):
    """
    Update the status of a single project based on its start and end dates,
    or its active retests' dates if available.

    Args:
        project: A Project model instance
    """
    # Skip if project is completed or on hold
    if project.status in ['Completed', 'On Hold']:
        return

    today = timezone.now().date()

    start_date = project.startdate
    end_date = project.enddate

    # Determine the appropriate status based on dates
    if today < start_date:
        new_status = 'Upcoming'
    elif start_date <= today <= end_date:
        new_status = 'In Progress'
    else:  # today > end_date
        new_status = 'Delay'

    # Update only if status has changed
    if project.status != new_status:
        project.status = new_status


