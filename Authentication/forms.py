from .models import CustomUser
from allauth.account.forms import SignupForm
from django import forms
from django.utils.translation import gettext_lazy as _, gettext as trans
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags
from django.core.validators import EmailValidator, ValidationError, RegexValidator
import re
from django.contrib.auth.password_validation import UserAttributeSimilarityValidator


class CustomSignupForm(SignupForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update(
            {'autocomplete': 'off', 'autocapitalize': 'none', 'autocorrect': 'off', 'spellcheck': 'false'})
        self.fields['email'].widget.attrs.update(
            {'autocomplete': 'off', 'autocapitalize': 'none', 'autocorrect': 'off', 'spellcheck': 'false'})
        self.fields['password1'].widget.attrs.update(
            {'autocomplete': 'off', 'autocapitalize': 'none', 'autocorrect': 'off', 'spellcheck': 'false'})
        self.fields['password2'].widget.attrs.update(
            {'autocomplete': 'off', 'autocapitalize': 'none', 'autocorrect': 'off', 'spellcheck': 'false'})

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username:
            username = strip_tags(username.strip())
            username_validator = RegexValidator(
                regex=r'^[a-zA-Z0-9.@+-_]+$',
                message=_(
                    'Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.'),
                code='invalid_username'
            )
            username_validator(username)
            if len(username) > 30:
                raise ValidationError(_('Username is too long.'))
            if CustomUser.objects.filter(username__iexact=username).exists():
                raise ValidationError(_('Username is already taken.'))
            username = super().clean_username()
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            email = strip_tags(email).lower()
            email_validator = EmailValidator(
                message="Please enter a valid email address.",
                code="invalid_email",
                allowlist=None
            )
            try:
                email_validator(email)
            except ValidationError as e:
                raise forms.ValidationError(str(e))

            # Check if the email is already associated with an existing account
            if CustomUser.objects.filter(email__iexact=email).exists():
                raise ValidationError(_('Email is already taken.'))
        return email

    def clean_password1(self):
        password1 = self.cleaned_data.get('password1')
        if password1:
            password1 = strip_tags(password1)
            if len(password1) < 10 or len(password1) > 50:
                raise ValidationError(
                    _('Password length should be between 10 and 30 characters.'))
        return password1

    def clean_password2(self):
        password2 = self.cleaned_data.get('password2')
        if password2:
            password2 = strip_tags(password2)
        return password2


class MinimumUpperCaseValidator:
    def __init__(self, min_uppercase=1):
        self.min_uppercase = min_uppercase

    def validate(self, password, user=None):
        if sum(1 for c in password if c.isupper()) < self.min_uppercase:
            raise ValidationError(
                trans(
                    "This password must contain at least %(min_uppercase)d uppercase letter(s)."),
                code='password_no_uppercase',
                params={'min_uppercase': self.min_uppercase},
            )

    def get_help_text(self):
        return trans("Your password must contain at least %(min_uppercase)d uppercase letter(s)." % {'min_uppercase': self.min_uppercase})


class UsernameChangeForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ('username',)

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username:
            username = strip_tags(username.strip())
            username_validator = RegexValidator(
                regex=r'^[a-zA-Z0-9.@+-_]+$',
                message=_(
                    'Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.'),
                code='invalid_username'
            )
            username_validator(username)
            if len(username) > 30:
                raise ValidationError(_('Username is too long.'))
            if CustomUser.objects.filter(username__iexact=username).exists():
                raise ValidationError(_('Username is already taken.'))
        return username


class MinimumLowerCaseValidator:
    def __init__(self, min_lowercase=1):
        self.min_lowercase = min_lowercase

    def validate(self, password, user=None):
        if sum(1 for c in password if c.islower()) < self.min_lowercase:
            raise ValidationError(
                trans(
                    "This password must contain at least %(min_lowercase)d lowercase letter(s)."),
                code='password_no_lowercase',
                params={'min_lowercase': self.min_lowercase},
            )

    def get_help_text(self):
        return trans("Your password must contain at least %(min_lowercase)d lowercase letter(s)." % {'min_lowercase': self.min_lowercase})


class MinimumDigitValidator:
    def __init__(self, min_digits=1):
        self.min_digits = min_digits

    def validate(self, password, user=None):
        if sum(1 for c in password if c.isdigit()) < self.min_digits:
            raise ValidationError(
                trans("This password must contain at least %(min_digits)d digit(s)."),
                code='password_no_digits',
                params={'min_digits': self.min_digits},
            )

    def get_help_text(self):
        return trans("Your password must contain at least %(min_digits)d digit(s)." % {'min_digits': self.min_digits})


class MinimumSpecialCharacterValidator:
    def __init__(self, min_special_characters=1):
        self.min_special_characters = min_special_characters

    def validate(self, password, user=None):
        special_characters = r'~!@#$%^&*()_+`-={}|[]\:";\'<>?,./'
        if sum(1 for c in password if c in special_characters) < self.min_special_characters:
            raise ValidationError(
                trans(
                    "This password must contain at least %(min_special_characters)d special character(s)."),
                code='password_no_special_characters',
                params={'min_special_characters': self.min_special_characters},
            )

    def get_help_text(self):
        return trans("Your password must contain at least %(min_special_characters)d special character(s)." % {'min_special_characters': self.min_special_characters})


class MaximumSimilarCharactersValidator:
    def __init__(self, max_characters=3):
        self.max_characters = max_characters

    def validate(self, password, user=None):
        for i in range(len(password) - self.max_characters):
            if len(set(password[i:i + self.max_characters])) == 1:
                raise ValidationError(
                    trans("This password contains too many similar characters."),
                    code='password_too_similar',
                    params={'max_characters': self.max_characters},
                )

    def get_help_text(self):
        return trans("Your password must not contain more than %(max_characters)d identical character(s) in a row." % {'max_characters': self.max_characters})


class SignupPasswordContainsUsernameValidator:
    def validate(self, password, user=None):
        if user:
            username = user.get_username()
            if username and username.lower() in password.lower():
                raise ValidationError(
                    trans("This password contains the username."),
                    code='password_contains_username',
                )

    def get_help_text(self):
        return trans("Your password can't contain your username.")


class CustomUserAttributeSimilarityValidator(UserAttributeSimilarityValidator):
    def validate(self, password, user=None):
        super().validate(password=password, user=user)
        if user:
            username = user.get_username()
            if username and username.lower() in password.lower():
                raise ValidationError(
                    trans('This password is too similar to your username.'),
                    code='password_too_similar_to_username',
                    params={'username': username},
                )
