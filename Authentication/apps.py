from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Authentication'

    # def ready(self):
    #     from Authentication.forms import CustomSignupForm
    #     from allauth.account import app_settings

    #     app_settings.ACCOUNT_SIGNUP_FORM_CLASS = CustomSignupForm
