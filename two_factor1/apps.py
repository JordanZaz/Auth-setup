from django.apps import AppConfig
from django.contrib.auth.signals import user_logged_in
from .signals import (
    set_user_session_expiry,
    set_user_verified,
    set_user_session_expiry_after_2FA,
)
from two_factor.signals import user_verified


class two_factor1Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'two_factor1'

    def ready(self):
        # import signal handlers and connect them here
        from django.dispatch import receiver
        # receiver(user_logged_in)(set_user_session_expiry)
        receiver(user_logged_in)(set_user_session_expiry_after_2FA)
        receiver(user_verified)(set_user_session_expiry_after_2FA)
        receiver(user_verified)(set_user_verified)
