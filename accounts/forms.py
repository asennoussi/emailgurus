from django.db import IntegrityError
from .tokens import token_generator

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordResetForm
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
import django_rq

from .models import CustomUser
from referral.models import Referral


class UserEditForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['full_name', 'paypal_email', 'email']
        widgets = {
            'full_name': forms.TextInput(attrs={'class': 'form-control'}),
            'paypal_email': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }


class SignUpForm(UserCreationForm):
    password1 = forms.CharField(widget=forms.PasswordInput())
    password2 = forms.CharField(widget=forms.PasswordInput())
    email = forms.EmailField(label='Email', max_length=254)
    referral_code = forms.CharField(required=False, widget=forms.HiddenInput())
    # Renamed honeypot field to extra_info
    extra_info = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'extra-info-field',
            'autocomplete': 'off',
            'tabindex': '-1',
            'aria-hidden': 'true',
            'style': 'position:absolute; left:-9999px;'
        })
    )

    class Meta:
        model = CustomUser
        fields = [
            'email',
            'password1',
            'password2',
        ]

    def clean_email(self):
        email = self.cleaned_data.get('email').lower()
        if CustomUser.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Email address already exists.")
        return email

    def clean_extra_info(self):
        """Reject submission if extra_info field is filled."""
        data = self.cleaned_data.get('extra_info')
        if data:
            raise forms.ValidationError("Invalid submission.")
        return data

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

    def create_referral(self, referral_code, new_user):
        try:
            inviter = CustomUser.objects.get(referral_code=referral_code)
            # Check if the new user is not the inviter
            if inviter == new_user:
                raise ValueError("A user cannot invite themselves.")
            referral = Referral.objects.create(
                inviter=inviter, referred_user=new_user)
            return referral
        except CustomUser.DoesNotExist:
            raise ValueError("Invalid referral code.")
        except IntegrityError:
            raise ValueError(
                "This user has already been invited by the inviter.")

class LoginForm(AuthenticationForm):
    username = forms.CharField(label='Email')


class PasswordResetForm(PasswordResetForm):
    email = forms.EmailField(max_length=254, widget=forms.EmailInput(
        attrs={'autocomplete': 'email'}))

    def clean_email(self):
        email = self.cleaned_data.get('email')
        return email