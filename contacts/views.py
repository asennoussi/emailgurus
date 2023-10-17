# from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.views.generic import RedirectView

from django.contrib import messages
from accounts.models import LinkedAccounts
from emailguru.utils import send_invite_emails


def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")


class InviteContactsRedirectView(RedirectView):
    url = reverse_lazy('user_referrals')

    def get(self, request):
        try:
            linked_accounts = LinkedAccounts.objects.filter(
                owner=request.user, active=True)
            for la in linked_accounts:
                send_invite_emails(la.associated_email)
            # Here, pull the contacts, then create chunks of emails to be scheduled.
            messages.success(
                request, 'Invitations sent to your contact list.')
        except Exception as error:
            print(f'An error occurred: {error}')
            messages.error(
                request, 'Couldn\'t send the invites to all contacts ', extra_tags='alert alert-danger')
        return super().get(request)
