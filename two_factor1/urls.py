from django.urls import path, include
from django.contrib.auth import views as auth_views

from two_factor.views import (
    QRGeneratorView,
    SetupCompleteView
)
from .views import CustomTwoFactorSetupView
from allauth.account.views import LoginView
from Authentication.views import ProfileView
from allauth.account.decorators import verified_email_required
from django.contrib.auth.decorators import login_required
from two_factor.urls import urlpatterns as tf_urls

app_name = 'two_factor'


urlpatterns = [
    path('setup/', login_required(verified_email_required(CustomTwoFactorSetupView.as_view())),
         name='setup'),
    # path('qrcode/', login_required(verified_email_required(QRGeneratorView.as_view())), name='qr',),
    # path('setup/complete/',
    #      login_required(verified_email_required(SetupCompleteView.as_view())), name='setup_complete',),
    path('profile/', ProfileView.as_view(), name='profile'),


]
