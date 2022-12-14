from datetime import datetime, timedelta
from hashlib import sha256

import django_rq
from accounts.models import LinkedAccounts
from contacts.models import Contact
from dashboard.forms import PaymentButtonForm
from dashboard.models import FilteredEmails, Jobs
from django.conf import settings
import google.oauth2.credentials

from django.urls import reverse_lazy
from django_rq.queues import get_queue
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from django.core.signing import Signer

signer = Signer()


def get_associated_email(flow):
    try:
        service = build('oauth2', 'v2', credentials=flow.credentials)
        # Call the People API
        results = service.userinfo().get().execute()
        email_address = results['email']
        return email_address
    except HttpError as err:
        print(err)


def credentials_to_dict(credentials):
    return signer.sign_object({'token': credentials.token,
                               'refresh_token': credentials.refresh_token,
                               'token_uri': credentials.token_uri,
                               'client_id': credentials.client_id,
                               'client_secret': credentials.client_secret,
                               'scopes': credentials.scopes})


def get_scopes():
    scopes_urls = ['/auth/userinfo.email',
                   '/auth/contacts.readonly', '/auth/gmail.modify', '/auth/contacts.other.readonly']
    return ['https://www.googleapis.com' + x for x in scopes_urls]


def get_google_flow():
    import os
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

    scopes = get_scopes()

    try:
        flow = Flow.from_client_secrets_file(
            settings.GOOGLE_APP_SECRET_JSON_PATH, scopes=scopes)

        flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
    except FileNotFoundError:
        print("The file doesn't exist. Please create credentials file")
        flow = {}
    return flow


def handle_email(email_id, from_email, user, associated_email):

    encrypted_contact = sha256(from_email.encode('utf-8')).hexdigest()

    la = LinkedAccounts.objects.get(associated_email=associated_email)
    qs = Contact.objects.filter(
        hashed_email=encrypted_contact, linked_account=la)

    domain = get_email_domain(from_email)

    credentials_dict = signer.unsign_object(la.credentials)
    credentials = google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"])

    if not is_user_active(user) or domain in la.whitelist_domains or not la.active:
        return

    service = build('gmail', 'v1', credentials=credentials)

    if(qs.exists()):
        update_label = {
            "addLabelIds": [],
            "removeLabelIds": [la.label]
        }
        service.users().messages().modify(
            userId='me', id=email_id, body=update_label).execute()
        passed_email, created = FilteredEmails.objects.get_or_create(
            date_filtered=datetime.now(), process_status='passed', owner=user, linked_account=la,
            defaults={'owner': user, 'linked_account': la, 'process_status': 'passed'})
        passed_email.count_emails = passed_email.count_emails + 1
        passed_email.save()
        return

    update_label = {
        "addLabelIds": [la.label],
        "removeLabelIds": ['INBOX']
    }
    if not la.archive_emails:
        update_label.pop('removeLabelIds')

    if la.trash_emails:
        update_label = {
            "addLabelIds": ['TRASH'],
            "removeLabelIds": ['INBOX']
        }

    service.users().messages().modify(
        userId='me', id=email_id, body=update_label).execute()
    filtered_email, created = FilteredEmails.objects.get_or_create(
        date_filtered=datetime.now(), process_status='filtered', owner=user, linked_account=la,
        defaults={'owner': user, 'linked_account': la, 'process_status': 'filtered'})
    if not created:
        filtered_email.count_emails = filtered_email.count_emails + 1
        filtered_email.save()
    pass


def stop_watcher(associated_email):
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    credentials_dict = signer.unsign_object(la.credentials)
    credentials = google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"])
    gmail = build('gmail', 'v1', credentials=credentials)
    try:
        gmail.users().stop(userId='me').execute()
    except Exception:
        pass


def watch_email(associated_email):

    la = LinkedAccounts.objects.get(associated_email=associated_email)
    credentials_dict = signer.unsign_object(la.credentials)
    credentials = google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"])

    if la.owner.subscription_status not in ['subscribed', 'trial'] or not la.active:
        return
    try:
        request = {
            'labelIds': ['SPAM'],
            'labelFilterAction': 'exclude',

            'topicName': settings.GOOGLE_TOPIC_NAME
        }

        # Call the Gmail API
        gmail = build('gmail', 'v1', credentials=credentials)
        gmail.users().stop(userId='me').execute()
        watcher = gmail.users().watch(userId='me', body=request).execute()

        # Set the last id
        last_history_id = watcher["historyId"]
        la.last_history_id = last_history_id
        la.save()

        job = Jobs.objects.filter(owner=la.owner,
                                  linked_account=la, job_type='watcher')
        queue = get_queue('default')

        if job.exists():
            job_queue = queue.fetch_job(job[0].job_id)
            if not job_queue or job_queue.get_status() != 'scheduled':
                nq = queue.enqueue_in(timedelta(days=1),
                                      watch_email, associated_email)
                job.delete()
                Jobs.objects.create(job_id=nq.id, owner=la.owner,
                                    linked_account=la, job_type='watcher')
        else:
            nq = queue.enqueue_in(timedelta(days=1),
                                  watch_email, associated_email)
            Jobs.objects.create(job_id=nq.id, owner=la.owner,
                                linked_account=la, job_type='watcher')

    except Exception as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')

    return


def update_contacts(associated_email):

    la = LinkedAccounts.objects.get(associated_email=associated_email)

    la.owner.count_contact = Contact.objects.filter(user=la.owner).count()
    Contact.objects.filter(linked_account=la).delete()
    credentials_dict = signer.unsign_object(la.credentials)
    credentials = google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"])

    h_c = get_hashed_contacts(credentials)
    h_o_c = get_hashed_other_contacts(credentials)
    contacts = (Contact(linked_account=la, user=la.owner, hashed_email='%s' % i)
                for i in (h_c + h_o_c))
    # Create a list of contacts, and other contacts
    Contact.objects.bulk_create(contacts)
    # Update the user contact's count
    la.owner.count_contact = la.owner.count_contact + len(h_c + h_o_c)
    la.owner.save()
    job = Jobs.objects.filter(owner=la.owner,
                              linked_account=la, job_type='contact')
    queue = get_queue('default')

    if job.exists():
        job_queue = queue.fetch_job(job[0].job_id)
        if not job_queue or job_queue.get_status() != 'scheduled':
            nq = queue.enqueue_in(timedelta(hours=1),
                                  update_contacts, associated_email)
            job.delete()
            Jobs.objects.create(job_id=nq.id, owner=la.owner,
                                linked_account=la, job_type='contact')
    else:
        nq = queue.enqueue_in(timedelta(hours=1),
                              update_contacts, associated_email)
        Jobs.objects.create(job_id=nq.id, owner=la.owner,
                            linked_account=la, job_type='contact')
    return


def get_hashed_contacts(credentials):
    all_connections = []
    hashed_emails = []
    try:
        service = build('people', 'v1', credentials=credentials)
        has_next_page = True

        kwargs = dict(resourceName='people/me',
                      pageSize=1000,
                      personFields='emailAddresses',
                      pageToken=False
                      )
        while (has_next_page):
            results = service.people().connections().list(
                **{k: v for k, v in kwargs.items() if v}
            ).execute()

            connections = results.get('connections', [])
            all_connections.extend(connections)
            kwargs['pageToken'] = has_next_page = results.get(
                'nextPageToken', False)

        for person in all_connections:
            emails = person.get('emailAddresses', [])
            if emails:
                for email in emails:
                    hashed_email = sha256(
                        email['value'].encode('utf-8')).hexdigest()
                    hashed_emails.append(hashed_email)
    except HttpError as err:
        print(err)
    return hashed_emails


def get_hashed_other_contacts(credentials):
    all_connections = []
    hashed_emails = []
    try:
        service = build('people', 'v1', credentials=credentials)
        has_next_page = True

        kwargs = dict(resourceName=False,
                      pageSize=1000,
                      readMask='emailAddresses',
                      pageToken=False
                      )
        while (has_next_page):
            results = service.otherContacts().list(
                **{k: v for k, v in kwargs.items() if v}
            ).execute()

            connections = results.get('otherContacts', [])
            all_connections.extend(connections)
            kwargs['pageToken'] = has_next_page = results.get(
                'nextPageToken', False)
        for person in all_connections:
            emails = person.get('emailAddresses', [])
            if emails:
                for email in emails:
                    hashed_email = sha256(
                        email['value'].encode('utf-8')).hexdigest()
                    hashed_emails.append(hashed_email)
    except HttpError as err:
        print(err)
    return hashed_emails


def get_email_domain(email):
    return email[email.index(
        '@') + 1:] if email[email.index('@') + 1:] != 'gmail.com' else ''


def is_user_active(user):
    today = datetime.today()
    return (user.subscription_status in ['subscribed', 'trial']
            or (user.subscription_status == 'canceled' and user.expires_at.date() > today))


def create_or_update_linked_account(request, credentials, email):
    # Create label for user
    service = build('gmail', 'v1', credentials=credentials)
    new_label = {
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
        "name": settings.EG_LABEL,
        "color": {
            "backgroundColor": "#8e63ce",
            "textColor": "#ffffff"
        },
        "type": "system"
    }
    try:
        created_label_object = service.users().labels().create(
            userId='me', body=new_label).execute()
        created_label = created_label_object['id']
    except:
        # get the label from the API
        labels = service.users().labels().list(
            userId='me').execute()
        for label in labels['labels']:
            if label.get('color'):
                if label['name'] == settings.EG_LABEL or label['color']['backgroundColor'] == '#8e63ce':
                    created_label = label['id']

    credentials_dict = credentials_to_dict(credentials)
    domain = get_email_domain(email)

    # If there is no refresh token, return an error
    if credentials.refresh_token:
        # Try to see if the account is already associated, if not create
        linked_account, created = LinkedAccounts.objects.get_or_create(
            associated_email=email, defaults={'owner': request.user, 'credentials': credentials_dict, 'whitelist_domains': [domain]})

        if not created and linked_account.deleted:
            linked_account.deleted = False
            linked_account.whitelist_domains.append(domain)
            linked_account.save()
        # Watch the inbox
        django_rq.enqueue(watch_email,
                          associated_email=email)

        return linked_account, created, credentials_dict, created_label, False
    else:  # Account linked before we're just reactivating it.
        linked_account = LinkedAccounts.objects.get(
            owner=request.user, associated_email=email)
        if linked_account.deleted:
            linked_account.deleted = False
        linked_account.label = created_label
        linked_account.save()
        # Watch the inbox
        django_rq.enqueue(watch_email,
                          associated_email=email)

        return None, False, {}, '', True


def get_paypal_button(request):
    paypal_dict = {
        "cmd": "_xclick-subscriptions",
        'business': settings.PAYPAL_RECEIVER_EMAIL,
        "a3": 6.99,  # monthly price
        "p3": 1,  # duration of each unit (depends on unit)
        "t3": 'M',  # duration unit ("M for Month")
        "src": "1",  # make payments recur
        "sra": "1",  # reattempt payment on payment error
        "no_note": "1",  # remove extra notes (optional)
        'item_name': 'Emailgurus subscription',
        'custom': request.user.id,     # custom data, pass something meaningful here
        'currency_code': 'USD',
        'notify_url': request.build_absolute_uri(reverse_lazy('paypal-ipn')),
        'return_url': request.build_absolute_uri(reverse_lazy('payment_done')),
        'cancel_return': request.build_absolute_uri(reverse_lazy('payment_canceled')),
    }
    return PaymentButtonForm(initial=paypal_dict)
