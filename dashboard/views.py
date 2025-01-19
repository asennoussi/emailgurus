import base64
import json
import re
from datetime import datetime, timedelta
from hashlib import sha256
from urllib.parse import unquote

import google.oauth2.credentials
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.signing import Signer
from django.db.models import FloatField, Q, Sum
from django.db.models.functions import Cast, Coalesce
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import ListView, RedirectView, TemplateView, UpdateView

from googleapiclient.discovery import build

from accounts.models import deletedAccounts
from dashboard.forms import UpdateLinkedAccountForm, EmailSearchForm
from dashboard.models import EmailDebugInfo, FilteredEmails, Jobs
from emailguru.utils import (
    LinkedAccounts,
    create_or_update_linked_account,
    get_associated_email,
    get_google_flow,
    get_paypal_button,
    get_scopes,
    handle_email,
    is_user_active,
    stop_watcher,
    update_contacts,
    watch_email,
)
from referral.models import Referral

signer = Signer()


class DashboardView(LoginRequiredMixin, TemplateView):
    """Shows basic stats and charts on the dashboard."""
    template_name = "dashboard/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        # PayPal button and user info
        context['paypal_button'] = get_paypal_button(self.request)
        context['user'] = user
        context['has_linked_accounts'] = LinkedAccounts.objects.filter(owner=user).count()

        # Combine repeated aggregations into a single query
        stats = FilteredEmails.objects.filter(owner=user).aggregate(
            total_processed=Sum('count_emails'),
            total_filtered=Sum('count_emails', filter=Q(process_status='filtered')),
            total_filtered_today=Sum(
                'count_emails',
                filter=Q(process_status='filtered', date_filtered=timezone.now().date())
            ),
        )

        total_processed = stats['total_processed'] or 0
        total_filtered = stats['total_filtered'] or 0
        total_filtered_today = stats['total_filtered_today'] or 0

        context['total_processed'] = total_processed
        context['total_filtered'] = total_filtered
        context['total_filtered_today'] = total_filtered_today
        # Approximate hours saved
        context['time_saved'] = int(total_filtered / 360) if total_filtered else 0
        # Filteration rate
        context['filteration_rate'] = (
            (total_filtered / total_processed) * 100 if total_processed else 0
        )

        # Generate a 7-day date list in ascending order
        base = timezone.now()
        date_list = []
        for x in range(7):
            date_str = (base - timedelta(days=x)).strftime("%d-%m-%Y")
            date_list.append(date_str)
        date_list.reverse()
        context['series_x'] = date_list

        # Raw query to populate daily filtered stats for each Linked Account
        filtered_emails_q = LinkedAccounts.objects.raw(
            '''
            SELECT
                laid AS id,
                ae,
                calendar_day::date,
                COALESCE(df.count_emails,0) AS count_filtered
            FROM (
                SELECT
                    la.associated_email AS ae,
                    la.id AS laid,
                    la.owner_id AS owner
                FROM accounts_linkedaccounts la
                WHERE la.owner_id = %s
                  AND deleted = 'false'
            ) AS sq
            CROSS JOIN generate_series(
                current_date - interval '6 days',
                current_date,
                interval '1 day'
            ) AS calendar_day
            LEFT JOIN dashboard_filteredemails AS df
                ON calendar_day = df.date_filtered
               AND sq.laid = df.linked_account_id
               AND process_status = 'filtered'
            ''',
            [user.id]
        )

        context['linked_accounts'] = []
        series_y_dict = {}

        for fe in filtered_emails_q:
            if fe.ae not in context['linked_accounts']:
                context['linked_accounts'].append(fe.ae)
            series_y_dict.setdefault(fe.ae, []).append(fe.count_filtered)

        context['series_y'] = list(series_y_dict.values())

        return context


@method_decorator(csrf_exempt, name='dispatch')
class PaymentDoneView(View):
    """
    Payment completed successfully.
    Render a success page or handle any additional payment logic.
    """

    def get(self, request, *args, **kwargs):
        return render(request, 'dashboard/success.html')

    def post(self, request, *args, **kwargs):
        return render(request, 'dashboard/success.html')


@method_decorator(csrf_exempt, name='dispatch')
class PaymentCanceledView(View):
    """
    Payment canceled or failed.
    Render a cancellation page or handle any cleanup logic.
    """

    def get(self, request, *args, **kwargs):
        return render(request, 'ecommerce_app/payment_cancelled.html')

    def post(self, request, *args, **kwargs):
        return render(request, 'ecommerce_app/payment_cancelled.html')


class LinkStatusView(LoginRequiredMixin, TemplateView):
    """Used to show the status of account linking attempts."""
    template_name = "dashboard/link_status.html"
    pass


class ToggleStatusRedirectView(LoginRequiredMixin, RedirectView):
    """Enable or disable a Linked Account."""
    url = reverse_lazy('linked_accounts')

    def get(self, request, pk):
        la = get_object_or_404(LinkedAccounts, pk=pk, owner=request.user)
        la.active = not la.active
        la.save()
        messages.success(request, 'Linked account updated successfully.')
        return super().get(request, pk)


class RefreshListenerRedirectView(LoginRequiredMixin, RedirectView):
    """Refresh watch listener for a given Linked Account."""
    url = reverse_lazy('linked_accounts')

    def get(self, request, pk):
        la = get_object_or_404(LinkedAccounts, pk=pk, owner=request.user)
        try:
            watch_email(la.associated_email)
            messages.success(request, 'Listener refreshed successfully.')
        except Exception as error:
            print(f'An error occurred: {error}')
            messages.error(
                request,
                'Can\'t refresh the listener now.. try refreshing access to the app.',
                extra_tags='alert alert-danger'
            )
        return super().get(request, pk)


class SyncContactsRedirectView(LoginRequiredMixin, RedirectView):
    """Sync contacts for a given Linked Account."""
    url = reverse_lazy('linked_accounts')

    def get(self, request, pk):
        la = get_object_or_404(LinkedAccounts, pk=pk, owner=request.user)
        
        # If using contact labels, redirect to label selection first
        if la.use_contact_labels:
            return redirect('select_labels', pk=pk)
            
        try:
            update_contacts(la.associated_email)
            messages.success(request, 'Contacts updated successfully.')
        except Exception as error:
            print(f'An error occurred: {error}')
            messages.error(
                request,
                'Can\'t sync contacts now.',
                extra_tags='alert alert-danger'
            )
        return super().get(request, pk)


class UnlinkAccountRedirectView(LoginRequiredMixin, RedirectView):
    """Soft-delete (unlink) a Linked Account."""
    url = reverse_lazy('linked_accounts')

    def get(self, request, pk):
        account = get_object_or_404(LinkedAccounts, id=pk, owner=request.user)
        stop_watcher(account.associated_email)
        Jobs.objects.filter(linked_account=account).delete()
        account.deleted = True
        account.save()
        deletedAccounts.objects.create(
            owner=request.user,
            linked_account=account.associated_email
        )
        messages.success(request, 'Account unlinked successfully.')
        return super().get(request, pk)


class LinkedaccountsView(LoginRequiredMixin, ListView):
    """Lists all non-deleted Linked Accounts for the current user."""
    template_name = "dashboard/linked_accounts.html"
    model = LinkedAccounts

    def get_queryset(self):
        user = self.request.user
        total_filtered = Sum(
            'filteredemails__count_emails',
            filter=Q(filteredemails__process_status='filtered')
        )
        total_processed = Coalesce(Sum('filteredemails__count_emails'), 0)
        return (
            LinkedAccounts.objects.filter(owner=user, deleted=False)
            .annotate(total_processed=total_processed)
            .annotate(total_filtered=total_filtered)
            .annotate(
                filteration_rate=(
                    Cast(total_filtered, FloatField()) /
                    Cast(total_processed, FloatField()) * 100
                )
            )
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['paypal_button'] = get_paypal_button(self.request)
        return context


class LinkAccounts(LoginRequiredMixin, RedirectView):
    """
    Final step in the OAuth flow for linking a Google account.
    User is redirected back here from Google with a code.
    """
    url = reverse_lazy('onboarding-update', kwargs={'step_name': 'contacts'})
    ERROR_PERMISSION = (
        'Linking the account failed, please allow all required '
        'permissions for Emailgurus to work.'
    )

    def get(self, request):
        flow = get_google_flow()
        authorization_response = request.build_absolute_uri(request.get_full_path())

        try:
            flow.fetch_token(authorization_response=authorization_response)
        except Exception:
            messages.info(request, self.ERROR_PERMISSION, extra_tags='alert alert-danger')
            fail_url = reverse_lazy('link_status', kwargs={'status': 'failure'})
            return HttpResponseRedirect(fail_url)

        # Validate scopes
        if not set(get_scopes()).issubset(set(request.GET.get('scope', '').split(' '))):
            messages.info(request, self.ERROR_PERMISSION, extra_tags='alert alert-danger')
            fail_url = reverse_lazy('link_status', kwargs={'status': 'failure'})
            return HttpResponseRedirect(fail_url)

        # Get email from Google
        email_address = get_associated_email(flow)
        EMAIL_ALREADY_ASSOCIATED = (
            f'The email "{email_address}" is already in the system, credentials updated.'
        )
        success_url = reverse_lazy('onboarding-update', kwargs={'step_name': 'contacts'})

        # Create/update the Linked Account
        linked_account, created, credentials_dict, created_label, error = create_or_update_linked_account(
            request, flow.credentials, email_address
        )

        if error:
            # Non-fatal; proceed but show message
            messages.info(request, 'Account linked with some issues.', extra_tags='alert alert-info')
            return HttpResponseRedirect(reverse_lazy('linked_accounts'))

        if not created:
            messages.info(request, EMAIL_ALREADY_ASSOCIATED, extra_tags='alert alert-info')
            linked_account.credentials = credentials_dict
            linked_account.save()
            return redirect(success_url)

        # New account setup
        linked_account.account_type = 'Google'
        linked_account.associated_email = email_address
        linked_account.label = created_label
        linked_account.save()

        # Sync contacts right after linking
        update_contacts(associated_email=email_address)
        return super().get(request)


class LinkGoogleRedirectView(LoginRequiredMixin, RedirectView):
    """Initiates Google's OAuth flow by redirecting user to the consent screen."""
    flow = get_google_flow()
    url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    url = unquote(url)

    def get(self, request):
        request.session['state'] = self.state
        return super().get(request)


class AccountSettings(LoginRequiredMixin, UpdateView):
    """Allows user to update label settings or preferences for a Linked Account."""
    model = LinkedAccounts
    template_name_suffix = '_update_form'
    context_object_name = 'account'
    form_class = UpdateLinkedAccountForm

    def get_success_url(self):
        return reverse_lazy('account_settings', kwargs={'pk': self.object.id})

    def form_valid(self, form):
        messages.success(self.request, 'Success! Account updated.')
        return super().form_valid(form)


@method_decorator(csrf_exempt, name='dispatch')
class EmailCatcherView(View):
    """
    Receives push notifications from Gmail Pub/Sub,
    detects label changes and new messages, handles them.
    """

    def post(self, request, *args, **kwargs):
        try:
            # Parse Pub/Sub request
            response_body = json.loads(request.body)
            email_change = json.loads(base64.b64decode(response_body['message']['data']))
            email_address = email_change["emailAddress"]
        except Exception as error:
            print(f'Error parsing Pub/Sub message: {error}')
            return HttpResponse(status=200)

        # Get the linked account, or ignore if not found
        la = LinkedAccounts.objects.filter(associated_email=email_address).first()
        if not la:
            return HttpResponse(status=200)

        # If user is inactive, stop watcher
        if not is_user_active(la.owner):
            stop_watcher(la.associated_email)
            return HttpResponse(status=200)

        # Rebuild Google credentials
        credentials_dict = signer.unsign_object(la.credentials)
        credentials = google.oauth2.credentials.Credentials(
            credentials_dict["token"],
            refresh_token=credentials_dict["refresh_token"],
            token_uri=credentials_dict["token_uri"],
            client_id=credentials_dict["client_id"],
            client_secret=credentials_dict["client_secret"],
            scopes=credentials_dict["scopes"]
        )

        try:
            gmail = build('gmail', 'v1', credentials=credentials)
            history_object = gmail.users().history().list(
                userId='me',
                historyTypes=['labelRemoved', 'messageAdded'],
                startHistoryId=la.last_history_id
            ).execute()

            histories = history_object.get('history', [])
            if 'historyId' in history_object:
                la.last_history_id = history_object['historyId']
                la.save()

            for history in histories:
                # 1) labelsRemoved -> check if user wants to whitelist
                if 'labelsRemoved' in history and la.whitelist_on_label:
                    for labels_removed in history.get('labelsRemoved', []):
                        if la.label in labels_removed.get('labelIds', []):
                            message_id = labels_removed['message']['id']
                            message_details = gmail.users().messages().get(
                                userId='me',
                                id=message_id,
                                format='metadata',
                                metadataHeaders='From'
                            ).execute()
                            from_field = message_details['payload']['headers'][0]['value']
                            match = re.search(r'<(.*)>', from_field)
                            from_email = match.group(1) if match else from_field

                            domain = from_email.split('@')[1] if '@' in from_email else None
                            if domain and domain not in la.whitelist_domains:
                                la.whitelist_domains.append(domain)
                                la.save()

                # 2) messagesAdded -> new emails
                if 'messagesAdded' in history:
                    for msg_data in history['messagesAdded']:
                        msg_id = msg_data['message']['id']
                        message_details = gmail.users().messages().get(
                            userId='me',
                            id=msg_id,
                            format='metadata',
                            metadataHeaders='From'
                        ).execute()

                        from_field = message_details['payload']['headers'][0]['value']
                        match = re.search(r'<(.*)>', from_field)
                        from_email = match.group(1) if match else from_field

                        # Debug contact labeling
                        print(f"Processing email from: {from_email}")
                        print(f"use_contact_labels setting: {la.use_contact_labels}")
                        
                        if la.use_contact_labels:
                            from contacts.models import Contact
                            hashed_email = sha256(from_email.encode('utf-8')).hexdigest()
                            
                            try:
                                # Get the contact and all its labels
                                contact = Contact.objects.filter(
                                    hashed_email=hashed_email,
                                    linked_account=la
                                ).first()
                                
                                if contact:
                                    print(f"Found contact for email: {from_email}")
                                    # Get all label IDs for this contact
                                    label_ids = list(contact.labels.values_list('gmail_label_id', flat=True))
                                    
                                    if label_ids:
                                        gmail.users().messages().modify(
                                            userId='me',
                                            id=msg_id,
                                            body={'addLabelIds': label_ids}
                                        ).execute()
                                        print(f"Applied {len(label_ids)} labels to message {msg_id}")
                                    
                            except Exception as e:
                                print(f"Label application error: {str(e)}")

                        # Handle the incoming email
                        handle_email(msg_id, from_email, la.owner, email_address)

        except Exception as error:
            print(f'Error in EmailCatcherView logic: {error}')

        return HttpResponse(status=200)


class UserReferralsView(LoginRequiredMixin, ListView):
    """Displays referrals made by the current user."""
    template_name = 'user_referrals.html'
    context_object_name = 'referrals'

    def get_queryset(self):
        user = self.request.user
        return Referral.objects.filter(inviter=user).select_related('referred_user')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['show_invite_button'] = LinkedAccounts.objects.filter(invites_sent=False).exists()
        return context


class DebuggerView(LoginRequiredMixin, ListView):
    """
    A simple debugger view to examine processed emails.
    Users can search by sender or filter by time window.
    """
    template_name = 'dashboard/debugger.html'
    paginate_by = 10
    ordering = ['-date_processed']

    def get_queryset(self):
        user = self.request.user
        queryset = EmailDebugInfo.objects.filter(owner=user)
        form = EmailSearchForm(self.request.GET)

        if form.is_valid():
            email_search = form.cleaned_data['email_search']
            time_window = form.cleaned_data['time_window']

            if email_search:
                hashed_sender = sha256(email_search.encode('utf-8')).hexdigest()
                queryset = queryset.filter(from_email_hashed=hashed_sender)

            if time_window:
                now = timezone.now()
                if time_window == '7d':
                    queryset = queryset.filter(date_processed__gte=now - timedelta(days=7))
                elif time_window == '14d':
                    queryset = queryset.filter(date_processed__gte=now - timedelta(days=14))
                elif time_window == '30d':
                    queryset = queryset.filter(date_processed__gte=now - timedelta(days=30))

        return queryset.order_by('-date_processed')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = EmailSearchForm(self.request.GET)
        return context