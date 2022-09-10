from django.apps import AppConfig
from django.db.models.signals import post_save


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        # Implicitly connect a signal handlers decorated with @receiver.
        from .signals import queue_expiry_emails
        from .models import CustomUser
        # Explicitly connect a signal handler.
        post_save.connect(queue_expiry_emails, sender=CustomUser)
