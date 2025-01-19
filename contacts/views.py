import logging

from django.shortcuts import get_object_or_404, redirect
from django.views.generic import TemplateView, View, RedirectView
from django.http import HttpResponse
from django.urls import reverse_lazy, reverse
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.signing import Signer
from django.db import transaction

import google.oauth2.credentials
from googleapiclient.discovery import build

from accounts.models import LinkedAccounts
from emailguru.utils import send_invite_emails, update_contacts

from .models import Label

logger = logging.getLogger(__name__)
signer = Signer()


def index(request):
    """
    Simple index view returning a basic HttpResponse.
    """
    return HttpResponse("Hello, world. You're at the polls index.")


def get_linked_account(pk, user):
    """
    Retrieve a single LinkedAccounts instance or 404.
    """
    return get_object_or_404(
        LinkedAccounts,
        id=pk,
        owner=user
    )


def get_credentials_from_linked(linked_account):
    """
    Return google.oauth2.credentials.Credentials object by unsigning
    and unpacking the credentials JSON stored in LinkedAccounts.
    """
    credentials_dict = signer.unsign_object(linked_account.credentials)
    return google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"]
    )


class InviteContactsRedirectView(RedirectView):
    """
    Redirects to 'user_referrals' after attempting to send invite emails.
    """
    url = reverse_lazy('user_referrals')

    def get(self, request, *args, **kwargs):
        try:
            send_invite_emails(request.user)
            messages.success(request, 'Invitations sent to your contact list.')
        except Exception as exc:
            logger.exception("Error sending invitation emails.")
            messages.error(
                request,
                'Could not send invites to all contacts. Please try again.',
                extra_tags='alert alert-danger'
            )
        return super().get(request, *args, **kwargs)


class SelectLabelsView(LoginRequiredMixin, TemplateView):
    """
    Displays a list of contact groups retrieved via the People API and
    allows users to select which labels/groups they want to synchronize.
    """
    template_name = 'contacts/select_labels.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        linked_account = get_linked_account(self.kwargs['pk'], self.request.user)
        credentials = get_credentials_from_linked(linked_account)

        # Use People API to retrieve contact groups
        service = build('people', 'v1', credentials=credentials)
        try:
            results = service.contactGroups().list(
                fields='contactGroups(resourceName,name,groupType)'
            ).execute()
        except Exception as exc:
            logger.exception("Error retrieving contact groups.")
            messages.error(
                self.request,
                'Unable to load contact groups. Please try again.',
                extra_tags='alert alert-danger'
            )
            context['available_labels'] = []
            return context

        available_labels = [
            {
                'name': group['name'],
                'id': group['resourceName'].split('/')[-1]  # Extract ID
            }
            for group in results.get('contactGroups', [])
            if group.get('groupType') != 'SYSTEM_CONTACT_GROUP'
        ]

        context['available_labels'] = available_labels
        context['linked_account'] = linked_account
        return context


class SyncContactsWithLabelsView(LoginRequiredMixin, View):
    """
    Synchronize contacts based on the selected labels/groups previously chosen.
    This calls update_contacts() to do a full cleanup and re-import in one place.
    """

    def post(self, request, pk):
        selected_labels = request.POST.getlist('selected_labels')
        linked_account = get_linked_account(pk, request.user)

        try:
            # We wrap everything in a transaction to ensure atomicity.
            with transaction.atomic():
                # Directly call update_contacts, passing the label strings.
                update_contacts(linked_account.associated_email, selected_labels=selected_labels)

            messages.success(
                request, 
                'Contacts and labels successfully synchronized.'
            )
        except Exception as exc:
            logger.exception("Error syncing contacts with labels.")
            messages.error(
                request, 
                'Could not sync contacts. Please try again.',
                extra_tags='alert alert-danger'
            )

        return redirect('linked_accounts')