from django import forms


class SubscriptionForm(forms.Form):
    subscription_options = [
        ('1-month', '1-Month subscription ($7.99 USD/Mon)'),
        # ('6-month', '6-Month subscription Save $10 ($50 USD/Mon)'),
        # ('1-year', '1-Year subscription Save $30 ($90 USD/Mon)'),
    ]
    plans = forms.ChoiceField(choices=subscription_options)
