from django import forms

from accounts.models import LinkedAccounts


class OnboardingUpdateLinkedAccountForm(forms.ModelForm):

    class Meta:
        CHOICES = [('0', 'Don\'t archive, Just label (Recommended)'),
                   ('1', 'Archive')]
        model = LinkedAccounts
        fields = ['archive_emails', 'whitelist_domains']
        widgets = {
            'whitelist_domains': forms.HiddenInput(attrs={'id': 'inputWhitelist'}),
            'archive_emails': forms.RadioSelect(attrs={'class': 'form-check-input'}, choices=CHOICES)
        }
