from paypal.standard.forms import PayPalPaymentsForm
from django.utils.html import format_html
from django import forms

from accounts.models import LinkedAccounts


class PaymentButtonForm(PayPalPaymentsForm):
    def render(self):
        form_open = u'''<form action="%s" method="post">''' % (
            self.get_login_url())
        form_close = u'</form>'
        # format html as you need
        submit_elm = u''' 
        <button class="btn btn-paypal btn-secondary  d-inline-flex align-items-center me-3 mb-3" type="submit">
                            <span class="sidebar-icon d-inline-flex align-items-center justify-content-center">
                            <svg aria-hidden="true" class="icon icon-xs me-2" focusable="false" data-prefix="fab" data-icon="paypal"
                                role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512">
                                <path fill="currentColor"
                                d="M111.4 295.9c-3.5 19.2-17.4 108.7-21.5 134-.3 1.8-1 2.5-3 2.5H12.3c-7.6 0-13.1-6.6-12.1-13.9L58.8 46.6c1.5-9.6 10.1-16.9 20-16.9 152.3 0 165.1-3.7 204 11.4 60.1 23.3 65.6 79.5 44 140.3-21.5 62.6-72.5 89.5-140.1 90.3-43.4.7-69.5-7-75.3 24.2zM357.1 152c-1.8-1.3-2.5-1.8-3 1.3-2 11.4-5.1 22.5-8.8 33.6-39.9 113.8-150.5 103.9-204.5 103.9-6.1 0-10.1 3.3-10.9 9.4-22.6 140.4-27.1 169.7-27.1 169.7-1 7.1 3.5 12.9 10.6 12.9h63.5c8.6 0 15.7-6.3 17.4-14.9.7-5.4-1.1 6.1 14.4-91.3 4.6-22 14.3-19.7 29.3-19.7 71 0 126.4-28.8 142.9-112.3 6.5-34.8 4.6-71.4-23.8-92.6z">
                                </path>
                            </svg>
                            </span>
                            Subscribe $12.99/mo
                        </button>
                    '''
        return format_html(form_open+self.as_p()+submit_elm+form_close)


class UpdateLinkedAccountForm(forms.ModelForm):

    class Meta:
        model = LinkedAccounts
        fields = ['active', 'archive_emails',
                  'trash_emails', 'check_spam', 'whitelist_domains', 'whitelist_on_label', 'use_contact_labels']
        widgets = {
            'active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'whitelist_domains': forms.HiddenInput(attrs={'id': 'inputWhitelist'}),
            'archive_emails': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'trash_emails': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'check_spam': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'whitelist_on_label': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'use_contact_labels': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }


class EmailSearchForm(forms.Form):
    email_search = forms.CharField(
        label='Email search',
        required=False,
        widget=forms.TextInput(
            attrs={'class': 'form-control', 'style': 'margin-bottom:0;'})
    )
    time_window = forms.ChoiceField(
        label='Time window',
        choices=[('', 'Select time window'), ('7d', 'Last 7 days'),
                 ('14d', 'Last 14 days'), ('30d', 'Last 30 days')],
        required=False,
        widget=forms.Select(
            attrs={'class': 'form-select', 'onchange': 'this.form.submit()'})
    )
