# TODO: Separate the payment logic in a different views and models and signals
import base64
from hashlib import sha256
import json
import re
from datetime import datetime, timedelta
from urllib.parse import unquote
from datetime import timedelta
from django.utils import timezone

import google.oauth2.credentials
from accounts.models import deletedAccounts
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.signing import Signer
from django.db.models import FloatField, Q, Sum
from django.db.models.functions import Cast
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import (ListView, RedirectView, TemplateView,
                                  UpdateView)
from django.db.models.functions import Coalesce
from emailguru.utils import (LinkedAccounts, create_or_update_linked_account,
                             get_associated_email, get_google_flow,
                             get_paypal_button, get_scopes, handle_email,
                             is_user_active, stop_watcher, update_contacts,
                             watch_email)
from googleapiclient.discovery import build

from dashboard.forms import UpdateLinkedAccountForm, EmailSearchForm
from referral.models import Referral

from .models import EmailDebugInfo, FilteredEmails, Jobs

signer = Signer()

# Create your views here.


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/dashboard.html"

    def get_context_data(self, **kwargs):
        """Returns the data passed to the template"""
        context = super(DashboardView, self).get_context_data(**kwargs)
        context['paypal_button'] = get_paypal_button(self.request)
        context['user'] = self.request.user
        context['has_linked_accounts'] = LinkedAccounts.objects.filter(
            owner=self.request.user).count()

        # filter_emails = FilteredEmails.objects.filter(
        #     owner=self.request.user, date_filtered__gte=last_seven_days, process_status='filtered').order_by('date_filtered')

        filtered_emails_q = LinkedAccounts.objects.raw(
            '''
                SELECT
                    laid as id, ae,calendar_day::date, COALESCE(df.count_emails,0) as count_filtered
                FROM
                    (SELECT
                        la.associated_email ae, la.id as laid, la.owner_id as owner
                    FROM
                        accounts_linkedaccounts la
                    WHERE
                        la.owner_id = %s and deleted ='false') as sq

                CROSS JOIN
                    generate_series(current_date - interval '6 days', current_date , interval '1 days') as calendar_day

                LEFT JOIN
                    dashboard_filteredemails as df
                ON
                    calendar_day  = df.date_filtered
                AND
                    sq.laid = df.linked_account_id
                AND
                        process_status = 'filtered'
            ''', [self.request.user.id]
        )

        # Get Dashboard data
        context['total_processed'] = FilteredEmails.objects.filter(
            owner=self.request.user).aggregate(Sum('count_emails'))['count_emails__sum']
        context['total_filtered'] = FilteredEmails.objects.filter(
            owner=self.request.user, process_status='filtered').aggregate(Sum('count_emails'))['count_emails__sum']
        context['total_filtered_today'] = FilteredEmails.objects.filter(
            owner=self.request.user, process_status='filtered', date_filtered=datetime.now()).aggregate(
            Sum('count_emails'))['count_emails__sum'] or 0
        context['time_saved'] = int(context['total_filtered'] or 0) / \
            360  # Total hours saved
        context['filteration_rate'] = int(context['total_filtered'] or 0) / \
            int(context['total_processed'] or 1) * 100
        base = datetime.today()
        date_list = [(base - timedelta(days=x)).strftime("%d-%m-%Y")
                     for x in range(7)]
        date_list = [datetime.strptime(date, "%d-%m-%Y") for date in date_list]
        date_list.sort()
        date_list = [date.strftime("%d-%m-%Y") for date in date_list]
        context['series_x'] = date_list
        context['linked_accounts'] = []
        series_y_dict = {}

        for fe in filtered_emails_q:
            if(fe.ae not in context['linked_accounts']):
                context['linked_accounts'].append(fe.ae)
            series_y_dict.setdefault(
                fe.ae, []).append(fe.count_filtered)

        context['series_y'] = list(series_y_dict.values())

        return context

    @csrf_exempt
    def payment_done(request):
        return render(request, 'dashboard/success.html')

    @csrf_exempt
    def payment_canceled(request):
        return render(request, 'ecommerce_app/payment_cancelled.html')


class LinkStatusView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/link_status.html"
    pass


class ToggleStatusRedirectView(RedirectView):
    url = reverse_lazy('linked_accounts')

    def get(self, request, pk):
        la = LinkedAccounts.objects.get(pk=pk, owner=request.user)
        if la:
            la.active = not la.active
            la.save()
            messages.success(request, 'Linked account updated successfully.')
            # Show success message
        else:
            # Show error message
            messages.error(request, 'Can\'t update the account ')

        return super().get(request, pk)


class RefreshListenerRedirectView(RedirectView):
    url = reverse_lazy('linked_accounts')

    def get(self, request, pk):
        la = LinkedAccounts.objects.get(pk=pk, owner=request.user)
        if la:
            try:
                watch_email(la.associated_email)
                messages.success(
                    request, 'Listener refreshed successfully.')
            except Exception as error:
                print(f'An error occurred: {error}')
                messages.error(
                    request, 'Can\'t refresh the listener now.. try refreshing access to the app. ', extra_tags='alert alert-danger')
            # Show success message
        else:
            # Show error message
            messages.error(request, 'Can\'t refresh the listener now',
                           extra_tags='alert alert-danger')

        return super().get(request, pk)


class SyncContactsRedirectView(RedirectView):
    url = reverse_lazy('linked_accounts')

    def get(self, request, pk):
        la = LinkedAccounts.objects.get(pk=pk, owner=request.user)
        if la:
            try:
                update_contacts(la.associated_email)
                messages.success(
                    request, 'Contacts updated successfully.')
            except Exception as error:
                print(f'An error occurred: {error}')
                messages.error(
                    request, 'Can\'t sync contacts now. ', extra_tags='alert alert-danger')
            # Show success message
        else:
            # Show error message
            messages.error(request, 'Can\'t sync contacts now',
                           extra_tags='alert alert-danger')
        return super().get(request, pk)


class UnlinkAccountRedirectView(RedirectView):
    url = reverse_lazy('linked_accounts')

    def get(self, request, pk):
        account = LinkedAccounts.objects.get(id=pk, owner=request.user)

        if account:
            stop_watcher(account.associated_email)
            Jobs.objects.filter(linked_account=account).delete()
            account.deleted = True
            account.save()
            deletedAccounts.objects.create(owner=request.user,
                                           linked_account=account.associated_email)
            messages.success(request, 'Account unliked successfully.')
            # Show success message
        else:
            # Show error message
            messages.error(request, 'Can\'t unlink the account ')

        return super().get(request, pk)


class LinkedaccountsView(LoginRequiredMixin, ListView):
    template_name = "dashboard/linked_accounts.html"
    model = LinkedAccounts

    def get_queryset(self):
        total_filtered = Sum('filteredemails__count_emails', filter=Q(
            filteredemails__process_status='filtered'))
        total_processed = Coalesce(Sum('filteredemails__count_emails'), 0)
        return (
            LinkedAccounts.objects.filter(
                owner=self.request.user, deleted=False)
            .annotate(total_processed=total_processed)
            .annotate(total_filtered=total_filtered)
            .annotate(filteration_rate=Cast(total_filtered, FloatField())/Cast(total_processed, FloatField())*100)
        )

    def get_context_data(self, **kwargs):
        """Returns the data passed to the template"""
        context = super(LinkedaccountsView, self).get_context_data(**kwargs)
        context['paypal_button'] = get_paypal_button(self.request)
        return context


class LinkAccounts(LoginRequiredMixin, RedirectView):
    url = reverse_lazy('onboarding-update', kwargs={'step_name': 'contacts'})
    ERROR_PERMISSION = 'Linking the account failed, please allow all the required accesses to make Emailgurus work'

    def get(self, request):
        # Get the credentials from Google
        flow = get_google_flow()
        authorization_response = request.build_absolute_uri(
            request.get_full_path())
        try:
            flow.fetch_token(authorization_response=authorization_response)
        except Exception:
            messages.info(request, self.ERROR_PERMISSION,
                          extra_tags='alert alert-danger')
            fail_url = reverse_lazy('link_status', kwargs={
                'status': 'failure'})
            return HttpResponseRedirect(fail_url)

        if not set(get_scopes()).issubset(
                set(request.GET.get('scope').split(' '))):
            messages.info(request, self.ERROR_PERMISSION,
                          extra_tags='alert alert-danger')
            fail_url = reverse_lazy('link_status', kwargs={
                'status': 'failure'})
            return HttpResponseRedirect(fail_url)

        # Get the email associated with the credentials
        email_address = get_associated_email(flow)

        # Function Variables
        EMAIL_ALREADY_ASSOCIATED = f'The email "{email_address}" is already associated in the system, credentials updated.'
        success_url = reverse_lazy(
            'onboarding-update', kwargs={'step_name': 'contacts'})
        # Create the linked account
        linked_account, created, credentials_dict, created_label, error = create_or_update_linked_account(
            request, flow.credentials, email_address)

        if error:
            return_url = reverse_lazy('linked_accounts')
            # Show error message
            messages.info(request, 'Account linked successfully ',
                          extra_tags='alert alert-info')
            return HttpResponseRedirect(return_url)

        if not created:
            messages.info(request, EMAIL_ALREADY_ASSOCIATED,
                          extra_tags='alert alert-info')
            linked_account.credentials = credentials_dict
            linked_account.save()
            return redirect(success_url)
        linked_account.account_type = 'Google'
        linked_account.associated_email = email_address
        linked_account.label = created_label
        linked_account.save()
        update_contacts(associated_email=email_address)
        return super().get(request)


class LinkGoogleRedirectView(RedirectView):
    flow = get_google_flow()
    url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')
    url = unquote(url)

    def get(self, request):
        request.session['state'] = self.state
        return super().get(request)


class AccountSettings(LoginRequiredMixin, UpdateView):
    model = LinkedAccounts
    template_name_suffix = '_update_form'
    context_object_name = 'account'
    form_class = UpdateLinkedAccountForm

    def get_success_url(self):
        return reverse_lazy('account_settings', kwargs={'pk': self.object.id})

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.

        success_message = 'Success! Account is updated'
        messages.success(self.request, success_message)
        return super().form_valid(form)


class EmailCatcher(View):
    @csrf_exempt
    def catch_email(request):
        try:
            # Process request data
            response = json.loads(request.body)
            email_change = json.loads(
                base64.b64decode(response['message']['data']))
            email_address = email_change["emailAddress"]
            # Get credentials and update Linked account
            la = LinkedAccounts.objects.get(associated_email=email_address)
            if not is_user_active(la.owner):
                stop_watcher(la.associated_email)
                return HttpResponse(status=200)
            credentials_dict = signer.unsign_object(la.credentials)

            credentials = google.oauth2.credentials.Credentials(
                credentials_dict["token"],
                refresh_token=credentials_dict["refresh_token"],
                token_uri=credentials_dict["token_uri"],
                client_id=credentials_dict["client_id"],
                client_secret=credentials_dict["client_secret"],
                scopes=credentials_dict["scopes"])
        except Exception as error:
            print(f'An error occurred: {error}')

        try:
            gmail = build('gmail', 'v1', credentials=credentials)
            history_object = gmail.users().history().list(userId='me', historyTypes=[
                'labelRemoved', 'messageAdded'], startHistoryId=la.last_history_id).execute()
            histories = history_object.get('history', [])

            la.last_history_id = history_object['historyId']
            la.save()
            for history in histories:
                if 'labelsRemoved' in history and la.whitelist_on_label:
                    for labels_removed in history.get('labelsRemoved', []):
                        if la.label in labels_removed.get('labelIds', []):
                            message_id = labels_removed['message']['id']
                            message_details = gmail.users().messages().get(
                                userId='me', id=message_id, format='metadata', metadataHeaders='From').execute()
                            from_field = message_details['payload']['headers'][0]['value']
                            try:
                                from_email = re.search(
                                    '<(.*)>', from_field).group(1)
                            except AttributeError:
                                from_email = from_field

                            domain = from_email.split('@')[1]
                            # add domain to the allow list
                            if domain not in la.whitelist_domains:
                                la.whitelist_domains.append(domain)
                                la.save()

                if 'messagesAdded' in history:
                    for message_added in history.get('messagesAdded', []):
                        message_details = gmail.users().messages().get(
                            userId='me', id=message_added['message']['id'], format='metadata', metadataHeaders='From').execute()
                        from_field = message_details['payload']['headers'][0]['value']
                        try:
                            from_email = re.search(
                                '<(.*)>', from_field).group(1)
                        except AttributeError:
                            from_email = from_field

                        # Handle email addition (as per your existing code)
                        handle_email(
                            message_added['message']['id'], from_email, la.owner, email_address)

        except Exception as error:
            print(f'An error occurred: {error}')
        return HttpResponse(status=200)


class UserReferralsView(LoginRequiredMixin, ListView):
    template_name = 'user_referrals.html'
    context_object_name = 'referrals'

    def get_context_data(self, **kwargs):
        """Returns the data passed to the template"""
        context = super(UserReferralsView, self).get_context_data(**kwargs)
        context['show_invite_button'] = LinkedAccounts.objects.filter(
            invites_sent=False).exists()
        return context

    def get_queryset(self):
        user = self.request.user
        return Referral.objects.filter(inviter=user).select_related('referred_user')


class DebuggerView(ListView):
    template_name = 'dashboard/debugger.html'
    paginate_by = 10  # Show 10 emails per page
    ordering = ['-date_processed']

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = EmailSearchForm(self.request.GET)
        return context

    def get_queryset(self):
        form = EmailSearchForm(self.request.GET)
        user = self.request.user
        queryset = EmailDebugInfo.objects.filter(owner=user)

        if form.is_valid():
            email_search = form.cleaned_data['email_search']
            time_window = form.cleaned_data['time_window']

            if email_search:
                hashed_sender = sha256(
                    email_search.encode('utf-8')).hexdigest()
                queryset = queryset.filter(from_email_hashed=hashed_sender)

            if time_window:
                now = timezone.now()
                if time_window == '7d':
                    queryset = queryset.filter(
                        date_processed__gte=now - timedelta(days=7))
                elif time_window == '14d':
                    queryset = queryset.filter(
                        date_processed__gte=now - timedelta(days=14))
                elif time_window == '30d':
                    queryset = queryset.filter(
                        date_processed__gte=now - timedelta(days=30))
        return queryset.order_by('-date_processed')
