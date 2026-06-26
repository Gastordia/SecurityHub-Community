from django.apps import AppConfig


class AccountsConfig(AppConfig):
    """
    This configuration is not required anymore, Should be removed with final release
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'
    
    def ready(self):
        # Import spectacular extensions to ensure they are loaded
        from . import spectacular_extensions