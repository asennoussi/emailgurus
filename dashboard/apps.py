from django.apps import AppConfig
from paypal.standard.ipn.signals import valid_ipn_received


class DashboardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'dashboard'

    def ready(self):
        # Implicitly connect a signal handlers decorated with @receiver.
        from . import signals
        # Explicitly connect a signal handler.
        valid_ipn_received.connect(signals.ipn_receiver)
