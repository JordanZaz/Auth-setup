from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.urls import reverse
from django_otp.plugins.otp_totp.models import TOTPDevice
from two_factor.views import SetupView
from django_otp import user_has_device
from allauth.account.views import LoginView
from two_factor.signals import user_verified
from django_otp.plugins.otp_email.models import EmailDevice
from .models import TrustedDevice
from .signals import get_hashed_info, set_user_session_expiry
from two_factor.forms import TOTPDeviceForm
from .custom_registry import MethodForm1


class CustomTwoFactorSetupView(SetupView):
    template_name = 'two_factor/setup.html'
    # custom_registry = CustomRegistry()
    form_list = (('method', MethodForm1),)

    # def get_method(self):
    #     method_data = self.storage.validated_step_data.get('method', {})
    #     method_key = method_data.get('method', None)
    #     return self.custom_registry.get_method(method_key)

    # def get_available_methods(self):
    #     return self.custom_registry.get_methods()

    def get_success_url(self):
        return reverse('profile')

    # def get_form(self, step=None, **kwargs):
    #     form = super().get_form(step=step, **kwargs)
    #     if step == 'method':
    #         # Remove the generator (TOTP) option from the method form
    #         form.fields['method'].choices = [
    #             choice for choice in form.fields['method'].choices if choice[0] != 'generator'
    #         ]
    #     return form

    # def render_next_step(self, form, **kwargs):
    #     """
    #     In the validation step, ask the device to generate a challenge.
    #     """
    #     next_step = self.steps.next
    #     if next_step == 'token':
    #         method_data = self.storage.validated_step_data.get('method', {})
    #         method_key = method_data.get('method', None)

    #         if method_key == 'email':
    #             device = EmailDevice.objects.get(user=self.request.user)
    #             try:
    #                 device.generate_challenge()
    #                 kwargs["challenge_succeeded"] = True
    #             except Exception:
    #                 # logger.exception("Could not generate challenge")
    #                 kwargs["challenge_succeeded"] = False
    #     return super().render_next_step(form, **kwargs)

    def done(self, form_list, **kwargs):
        # Call the original `done` method to perform the 2FA setup
        response = super().done(form_list, **kwargs)
        # Call the `set_user_verified` signal receiver to set the device as verified
        method_code = self.get_method().code
        print("user_verified sent!!")
        user_verified.send(sender=None, request=self.request,
                           user=self.request.user, method_code=method_code)

        # Redirect the user to their profile page
        return response

    def is_device_trusted(self):
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')
        ip_address = self.request.META.get('REMOTE_ADDR', '')
        hashed_info = get_hashed_info(user_agent, ip_address)

        return TrustedDevice.objects.filter(user=self.request.user, hashed_info=hashed_info).exists()

    def dispatch(self, request, *args, **kwargs):

        has_totp_device = TOTPDevice.objects.filter(
            user=request.user, confirmed=True).exists()
        has_email_device = EmailDevice.objects.filter(
            user=request.user, confirmed=True).exists()

        print("TOTP:", has_totp_device)
        print("EMAIL:", has_email_device)
        print("AUTH:", request.user.is_authenticated)
        print("HAS DEV:", user_has_device(request.user))
        print("IS DEV TRUSTED:", self.is_device_trusted())

        if not request.user.is_authenticated:
            return redirect('account_login')
        elif not user_has_device(request.user, confirmed=True):
            return super().dispatch(request, *args, **kwargs)
        else:
            has_totp_device = TOTPDevice.objects.filter(
                user=request.user, confirmed=True).exists()
            has_email_device = EmailDevice.objects.filter(
                user=request.user, confirmed=True).exists()
            if (has_totp_device or has_email_device) and self.is_device_trusted() == True:
                return redirect('profile')
            else:
                set_user_session_expiry(
                    sender=None, request=self.request, **kwargs)
                return super().dispatch(request, *args, **kwargs)
