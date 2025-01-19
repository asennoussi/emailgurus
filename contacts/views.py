# from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.views.generic import RedirectView

from django.contrib import messages
from accounts.models import LinkedAccounts
from emailguru.utils import send_invite_emails

from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import TemplateView
from django.urls import reverse
from googleapiclient.discovery import build
from django.core.signing import Signer

from .models import Label

signer = Signer()

def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")


class InviteContactsRedirectView(RedirectView):
    url = reverse_lazy('user_referrals')

    def get(self, request):
        try:
            send_invite_emails(request.user)
            # Here, pull the contacts, then create chunks of emails to be scheduled.
            messages.success(
                request, 'Invitations sent to your contact list.')
        except Exception as error:
            print(f'An error occurred: {error}')
            messages.error(
                request, 'Couldn\'t send the invites to all contacts ', extra_tags='alert alert-danger')
        return super().get(request)


class SelectLabelsView(LoginRequiredMixin, TemplateView):
    template_name = 'contacts/select_labels.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        linked_account = get_object_or_404(
            LinkedAccounts, 
            id=self.kwargs['pk'], 
            owner=self.request.user
        )
        
        # Get credentials
        credentials_dict = signer.unsign_object(linked_account.credentials)
        credentials = google.oauth2.credentials.Credentials(
            credentials_dict["token"],
            refresh_token=credentials_dict["refresh_token"],
            token_uri=credentials_dict["token_uri"],
            client_id=credentials_dict["client_id"],
            client_secret=credentials_dict["client_secret"],
            scopes=credentials_dict["scopes"]
        )

        # Get all Gmail labels
        gmail_service = build('gmail', 'v1', credentials=credentials)
        results = gmail_service.users().labels().list(userId='me').execute()
        available_labels = []
        
        for label in results.get('labels', []):
            if label.get('type') == 'user':  # Only show user-created labels
                available_labels.append({
                    'name': label['name'],
                    'id': label['id']
                })

        context['available_labels'] = available_labels
        context['linked_account'] = linked_account
        return context

    def post(self, request, *args, **kwargs):
        selected_labels = request.POST.getlist('selected_labels')
        linked_account = get_object_or_404(
            LinkedAccounts, 
            id=self.kwargs['pk'], 
            owner=request.user
        )
        
        # Store selected labels in session for use in sync_contacts
        label_data = []
        for label_str in selected_labels:
            name, gmail_id = label_str.split('|')
            label_data.append({
                'name': name,
                'gmail_label_id': gmail_id
            })
        
        request.session['selected_labels'] = label_data
        
        # Redirect to sync contacts
        return redirect('sync_contacts', pk=linked_account.id)
