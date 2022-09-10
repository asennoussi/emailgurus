from .tokens import token_generator

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
import django_rq

from .models import CustomUser


class SignUpForm(UserCreationForm):
    password1 = forms.CharField(widget=forms.PasswordInput())
    password2 = forms.CharField(widget=forms.PasswordInput())
    email = forms.EmailField(label='Email', max_length=254)

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


class LoginForm(AuthenticationForm):
    username = forms.CharField(label='Email')
