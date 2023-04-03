from django.shortcuts import render, redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from allauth.socialaccount.models import SocialAccount
from django.views import View
from django.core.validators import ValidationError
from django.contrib import messages
from django.contrib.auth import logout
from django.urls import reverse_lazy
from django.views.generic.edit import UpdateView
from .forms import UsernameChangeForm
from .models import CustomUser


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = 'profile/profile.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        if user.is_authenticated:
            context['username'] = user.get_display_name()
        return context


class DeleteAccountView(LoginRequiredMixin, View):
    def post(self, request):
        user = request.user
        logout(request)
        user.delete()
        messages.success(
            request, 'Your account has been deleted successfully.')
        return redirect('account_login')


class ChangeUsernameView(LoginRequiredMixin, UpdateView):
    model = CustomUser
    form_class = UsernameChangeForm
    template_name = 'account/change_username.html'
    success_url = reverse_lazy('profile')

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        user = self.request.user
        user.username_updated = True
        user.save()
        messages.success(
            self.request, 'Your username has been changed successfully.')
        return super().form_valid(form)

    def get_initial(self):
        initial = super().get_initial()
        user = self.request.user
        initial['username'] = user.get_display_name()
        return initial
