from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy
from django.views.generic import CreateView, RedirectView, UpdateView
from django.contrib.auth import login
from django.http import JsonResponse, HttpResponseRedirect
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib import messages
from django.shortcuts import redirect

from .forms import LoginForm, PasswordResetForm, SignUpForm, token_generator, CustomUser, UserEditForm

# Create your views here.


class LogoutView(auth_views.LogoutView):
    form_class = LoginForm
    template_name = 'accounts/login.html'
    next_page = reverse_lazy('dashboard')


class LoginView(auth_views.LoginView):
    form_class = LoginForm
    template_name = 'accounts/login.html'
    next_page = reverse_lazy('dashboard')


class PasswordResetView(auth_views.PasswordResetView):
    form_class = PasswordResetForm
    template_name = 'accounts/password_reset.html'
    html_email_template_name = 'emails/email-password-reset.html'
    subject_template_name = 'emails/password_reset_subject.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        if self.request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'ok', 
                'message': "If the email address exists in our database, you'll receive password reset instructions shortly."
            }, status=200)
        else:
            return response

    def form_invalid(self, form):
        response = super().form_invalid(form)
        if self.request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
        else:
            return response


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = 'accounts/password_reset_confirm.html'
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Your password has been reset successfully, you can now login.")
        return response


class SignUpView(CreateView):
    template_name = "accounts/sign-up.html"
    form_class = SignUpForm
    success_url = reverse_lazy('onboarding', kwargs={'step_name': 'link-account'})

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        # Set the default value for the referral_code field from cookies
        kwargs['initial'] = {
            'referral_code': self.request.COOKIES.get('referral_code', '')
        }
        return kwargs

    def form_valid(self, form):
        form.instance.email = form.instance.email.lower()
        # Save the user once and assign to self.object
        self.object = form.save()
        self.object.is_verified = False  # Ensure email verification is marked false
        self.object.save()

        form.send_activation_email(self.request, self.object)
        # If a referral code is provided, create the referral record
        if form.cleaned_data['referral_code']:
            form.create_referral(form.cleaned_data['referral_code'], self.object)
        # Log in the user using our custom authentication backend
        login(self.request, self.object, backend='accounts.backends.EmailBackend')
        return HttpResponseRedirect(self.get_success_url())


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
                request, 'Awesome! You successfully verified your email. Enjoy Emailgurus', extra_tags='text-center'
            )
        else:
            messages.error(
                request, 'We could not verify your account. Please try again', extra_tags='alert alert-danger text-center'
            )

        return super().get(request, uidb64, token)


class CustomUserEditView(UpdateView):
    model = CustomUser
    form_class = UserEditForm
    template_name_suffix = '_update_form'
    success_url = reverse_lazy('settings')

    def get_object(self, queryset=None):
        # Return the current logged in user
        if self.request.user.is_authenticated:
            return self.request.user
        else:
            return redirect('home')

    def form_valid(self, form):
        # Subscription logic can be added here if needed.
        if self.object.subscription_status not in ['subscribed']:
            pass
        messages.success(self.request, "User details updated successfully!")
        return super().form_valid(form)