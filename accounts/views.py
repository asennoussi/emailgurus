from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy
from django.views.generic import CreateView, RedirectView
from django.contrib.auth import login

from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.shortcuts import render
from django.contrib import messages

from .forms import LoginForm, SignUpForm, token_generator, CustomUser
# Create your views here.


class LogoutView(auth_views.LogoutView):
    form_class = LoginForm
    template_name = 'accounts/login.html'
    next_page = reverse_lazy('dashboard')


class LoginView(auth_views.LoginView):
    form_class = LoginForm
    template_name = 'accounts/login.html'
    next_page = reverse_lazy('dashboard')


class SignUpView(CreateView):
    template_name = "accounts/sign-up.html"
    form_class = SignUpForm
    success_url = reverse_lazy(
        'onboarding', kwargs={'step_name': 'link-account'})

    def form_valid(self, form):
        to_return = super().form_valid(form)

        user = form.save()
        user.is_verified = False  # Turns the user status to inactive
        user.save()

        form.send_activation_email(self.request, user)

        login(self.request, self.object,
              backend='accounts.backends.EmailBackend')
        return to_return


class ActivateView(RedirectView):

    url = reverse_lazy('dashboard')

    # Custom get method
    def get(self, request, uidb64, token):

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None

        if user is not None and token_generator.check_token(user, token):
            user.is_verified = True
            user.save()
            messages.success(
                request, 'Awesome! You successfully verified your email. Enjoy Emailgurus', extra_tags='text-center')
        else:
            messages.error(
                request, 'We could not verify your account. Please try again', extra_tags='alert alert-danger text-center')

        return super().get(request, uidb64, token)
