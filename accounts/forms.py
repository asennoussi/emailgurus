from .tokens import token_generator

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
import django_rq

from .models import CustomUser
from referral.models import Referral


class SignUpForm(UserCreationForm):
    password1 = forms.CharField(widget=forms.PasswordInput())
    password2 = forms.CharField(widget=forms.PasswordInput())
    email = forms.EmailField(label='Email', max_length=254)
    referral_code = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = CustomUser
        fields = [
            'email',
            'password1',
            'password2',
        ]
    # We need the user object, so it's an additional parameter

    def send_activation_email(self, request, user):
        current_site = get_current_site(request)
        subject = 'Activate Your Account'
        message = render_to_string(
            'emails/email-verification.html',
            {
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token_generator.make_token(user),
            }
        )

        django_rq.enqueue(user.email_user,
                          subject, message, html_message=message)

    def clean_referral_code(self):
        referral_code = self.cleaned_data['referral_code']
        if referral_code:
            # Validate the referral code and retrieve the referral object
            try:
                referral = CustomUser.objects.get(referral_code=referral_code)
            except CustomUser.DoesNotExist:
                raise forms.ValidationError('Invalid referral code')
            return referral.referral_code
        return None

    def create_referral(self, referral_code, user):
        referrer = CustomUser.objects.get(
            referral_code=referral_code)

        referral, created = Referral.objects.get_or_create(user=referrer)
        import pdb
        pdb.set_trace()
        return referral.referred_users.add(user)


class LoginForm(AuthenticationForm):
    username = forms.CharField(label='Email')
