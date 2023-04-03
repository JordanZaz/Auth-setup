from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_out
from django.contrib.sessions.backends.db import SessionStore
from datetime import timedelta
from two_factor.signals import user_verified
import hashlib


def get_hashed_info(user_agent, ip_address):
    combined = f"{user_agent}-{ip_address}"
    hashed_info = hashlib.sha3_256(combined.encode('utf-8')).hexdigest()
    return hashed_info


def set_user_session_expiry(sender, request, **kwargs):
    # added this for the tests
    user = getattr(request, 'user', None)
    if user is not None:
        # --------------------------
        remember_me = request.POST.get("remember_me", False)
        if remember_me:
            session_duration = timedelta(days=14)  # 14 days
        else:
            # or any other duration you want for non-remember me sessions
            session_duration = timedelta(minutes=90)

        session = SessionStore(session_key=request.session.session_key)
        session.set_expiry(session_duration)
        request.session.set_expiry(session_duration)

        # Import the TOTPDevice and EmailDevice models here
        from django_otp.plugins.otp_totp.models import TOTPDevice
        from django_otp.plugins.otp_email.models import EmailDevice

        # Set confirmed=False for all TOTP devices
        TOTPDevice.objects.filter(user=user).update(confirmed=False)

        # Set confirmed=False for all email devices
        EmailDevice.objects.filter(user=user).update(confirmed=False)

        session.save()


def set_user_session_expiry_after_2FA(sender, request, **kwargs):
    remember_me = request.POST.get("remember_me", False)

    if remember_me:
        session_duration = timedelta(days=14)  # 14 days
    else:
        # or any other duration you want for non-remember me sessions
        session_duration = timedelta(minutes=90)

    session = SessionStore(session_key=request.session.session_key)
    session.set_expiry(session_duration)
    request.session.set_expiry(session_duration)

    session.save()


@receiver(user_verified)
def set_user_verified(sender, request, user, method_code, **kwargs):
    # Update the confirmed status of the specific device that was just added or verified
    from django_otp.plugins.otp_totp.models import TOTPDevice
    from django_otp.plugins.otp_email.models import EmailDevice
    from .models import TrustedDevice

    if method_code == 'email':
        EmailDevice.objects.filter(user=user).update(confirmed=True)
    elif method_code == 'generator':
        TOTPDevice.objects.filter(user=user).update(confirmed=True)

    has_totp_device = TOTPDevice.objects.filter(
        user=request.user, confirmed=True).exists()
    has_email_device = EmailDevice.objects.filter(
        user=request.user, confirmed=True).exists()
    if method_code == 'email':
        print(f"Email is confirmed!: {has_email_device}")
    elif method_code == 'generator':
        print(f"TOTP is confirmed!: {has_totp_device}")

    # Store the hashed user agent and IP address in the TrustedDevice model
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    ip_address = request.META.get('REMOTE_ADDR', '')
    hashed_info = get_hashed_info(user_agent, ip_address)

    TrustedDevice.objects.get_or_create(user=user, hashed_info=hashed_info)
