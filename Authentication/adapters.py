from allauth.account.adapter import DefaultAccountAdapter
from allauth.utils import generate_unique_username
from .models import CustomUser
from django.http import HttpResponseRedirect
from allauth.account import signals
from django.contrib import messages
from allauth.account.utils import get_login_redirect_url
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialAccount


class CustomAccountAdapter(DefaultAccountAdapter):

    def generate_unique_username_with_case(self, base_username):
        base_username = base_username.strip()
        i = 0
        username = base_username
        while CustomUser.objects.filter(username__iexact=username).exists():
            i += 1
            username = f"{base_username}{i}"
        return username

    def populate_username(self, request, user):
        social_username = user.username
        if not social_username:
            user_email = user.email
            if user_email:
                # Use the first part of the email if the social account doesn't provide a username
                username_base = user_email.split('@')[0]
                user.username = self.generate_unique_username_with_case(
                    username_base)
        else:
            # Ensure the social account username is unique
            user.username = self.generate_unique_username_with_case(
                social_username)

    def post_login(self, request, user, *, email_verification, signal_kwargs, email, signup, redirect_url):
        # from .utils import get_login_redirect_url

        response = HttpResponseRedirect(
            get_login_redirect_url(request, redirect_url, signup=signup)
        )

        if signal_kwargs is None:
            signal_kwargs = {}
        signals.user_logged_in.send(
            sender=user.__class__,
            request=request,
            response=response,
            user=user,
            **signal_kwargs,
        )
        display_name = user.get_display_name()
        self.add_message(
            request,
            messages.SUCCESS,
            "account/messages/logged_in_custom.txt",
            {"user": display_name},
        )
        return response
