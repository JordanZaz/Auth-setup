from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.urls import reverse
from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount, SocialToken, SocialApp
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=255, blank=True)
    username_updated = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    def clean(self):
        super().clean()
        if self.username:
            if len(self.username) > 30:
                raise ValidationError(_('Username is too long.'))
            if CustomUser.objects.filter(username__iexact=self.username).exclude(pk=self.pk).exists():
                raise ValidationError(_('Username is already taken.'))
    # Add any other custom fields here, such as a profile picture or shipping address

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.username or self.email

    def get_short_name(self):
        return self.email

    def get_display_name(self):
        if self.username_updated:
            return self.username
        else:
            try:
                google_account = self.socialaccount_set.get(provider='google')
                name = google_account.extra_data.get('name', '')
            except SocialAccount.DoesNotExist:
                try:
                    microsoft_account = self.socialaccount_set.get(
                        provider='microsoft')
                    name = microsoft_account.extra_data.get('displayName', '')
                except SocialAccount.DoesNotExist:
                    name = ''

            if not name:
                name = self.username or self.email

            return name

    def has_social_account(self, provider):
        return self.socialaccount_set.filter(provider=provider).exists()

    def get_social_account(self, provider):
        return self.socialaccount_set.get(provider=provider)

    def get_avatar_url(self):
        try:
            social_account = self.get_social_account('google')
            return social_account.extra_data['picture']
        except SocialAccount.DoesNotExist:
            return reverse('accounts:avatar-placeholder')

    def get_provider(self):
        try:
            social_account = self.socialaccount_set.first()
            return social_account.provider.capitalize()
        except SocialAccount.DoesNotExist:
            return 'Email'

    @property
    def verified_email(self):
        try:
            return self.emailaddress_set.get(primary=True).email
        except EmailAddress.DoesNotExist:
            return None

    def has_verified_email(self):
        return self.verified_email is not None

    def verify_email(self):
        email_address = self.emailaddress_set.get(email=self.email)
        email_address.verified = True
        email_address.save()

    def send_verification_email(self):
        email_address = self.emailaddress_set.get(email=self.email)
        email_address.send_confirmation()
