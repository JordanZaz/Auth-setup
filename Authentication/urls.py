# from django.urls import include, path
# from django.contrib.auth import views as auth_views
# from allauth.account.views import LoginView, LogoutView, SignupView, EmailView, PasswordChangeView
# from .views import ProfileView, DeleteAccountView, ChangeUsernameView, CustomTwoFactorSetupView
# from .forms import CustomSignupForm
# from allauth.account.decorators import verified_email_required
# from two_factor.urls import urlpatterns as tf_urls

# urlpatterns = [
#     path('accounts/', include('allauth.urls')),
#     path('signup/', SignupView.as_view(form_class=CustomSignupForm),
#          name='account_signup'),
#     path('profile/', ProfileView.as_view(), name='profile'),
#     path('email/', verified_email_required(EmailView.as_view()), name='account_email'),
#     path('password/change/', verified_email_required(PasswordChangeView.as_view()),
#          name="account_change_password"),
#     path('delete_account/', DeleteAccountView.as_view(), name='delete_account'),
#     path('change_username/', ChangeUsernameView.as_view(), name='change_username'),
# path('', include(tf_urls)),
#     path('two_factor/setup/', verified_email_required(CustomTwoFactorSetupView.as_view()),
#          name='custom_two_factor_setup'),
# ]


from django.urls import include, path, re_path
from django.contrib.auth import views as auth_views
from allauth.account.views import (
    LoginView, LogoutView, SignupView, EmailView, PasswordChangeView,
    PasswordResetView, PasswordResetDoneView, PasswordResetFromKeyView, PasswordResetFromKeyDoneView,
    AccountInactiveView, EmailVerificationSentView, ConfirmEmailView, PasswordSetView
)
from allauth.socialaccount.views import ConnectionsView, SignupView as SocialSignupView
from two_factor.plugins.phonenumber.views import (
    PhoneDeleteView, PhoneSetupView,
)
from two_factor.views import (
    BackupTokensView, QRGeneratorView,
    SetupCompleteView
)
from .views import ProfileView, DeleteAccountView, ChangeUsernameView
from .forms import CustomSignupForm
from allauth.account.decorators import verified_email_required

from allauth.socialaccount.views import ConnectionsView, SignupView as SocialSignupView, LoginCancelledView, LoginErrorView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter, oauth2_login, oauth2_callback
from allauth.socialaccount.providers.microsoft.views import MicrosoftGraphOAuth2Adapter, oauth2_login as oauth2_login1, oauth2_callback as oauth2_callback1
from allauth.socialaccount.providers.oauth2.client import OAuth2Error


urlpatterns = [
    # Allauth paths
    path('accounts/signup/', SignupView.as_view(form_class=CustomSignupForm),
         name='account_signup'),
    path('accounts/login/', LoginView.as_view(), name='account_login'),
    path('accounts/logout/', LogoutView.as_view(), name='account_logout'),
    path('accounts/email/', verified_email_required(EmailView.as_view()),
         name='account_email'),
    path('accounts/password/change/', verified_email_required(
        PasswordChangeView.as_view()), name='account_change_password'),
    path('accounts/password/set/', PasswordSetView.as_view(),
         name="account_set_password"),
    path('accounts/password/reset/', PasswordResetView.as_view(),
         name='account_reset_password'),
    path('accounts/password/reset/done/', PasswordResetDoneView.as_view(),
         name='account_reset_password_done'),
    re_path(r"^accounts/password/reset/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$",
            PasswordResetFromKeyView.as_view(), name='account_reset_password_from_key'),
    path('accounts/password/reset/key/done/', PasswordResetFromKeyDoneView.as_view(),
         name='account_reset_password_from_key_done'),
    path('accounts/inactive/', AccountInactiveView.as_view(),
         name='account_inactive'),
    path('accounts/confirm-email/', EmailVerificationSentView.as_view(),
         name='account_email_verification'),
    re_path(r"^accounts/confirm-email/(?P<key>[-:\w]+)/$",
            ConfirmEmailView.as_view(), name="account_confirm_email"),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('delete_account/', DeleteAccountView.as_view(), name='delete_account'),
    path('change_username/', ChangeUsernameView.as_view(), name='change_username'),


    path('accounts/social/signup/', SocialSignupView.as_view(),
         name='socialaccount_signup'),
    path('accounts/social/connections/', ConnectionsView.as_view(),
         name='socialaccount_connections'),
    path('accounts/social/login/cancelled/', LoginCancelledView.as_view(),
         name="socialaccount_login_cancelled"),
    path('accounts/social/login/error/', LoginErrorView.as_view(),
         name="socialaccount_login_error"),
    path('accounts/google/login/', oauth2_login,
         {'adapter_class': GoogleOAuth2Adapter}, name='google_login'),
    path('accounts/google/login/callback/', oauth2_callback,
         {'adapter_class': GoogleOAuth2Adapter}, name='google_callback'),
    path('accounts/microsoft/login/', oauth2_login1,
         {'adapter_class': MicrosoftGraphOAuth2Adapter}, name='microsoft_login'),
    path('accounts/microsoft/login/callback/', oauth2_callback1,
         {'adapter_class': MicrosoftGraphOAuth2Adapter}, name='microsoft_callback'),
]
