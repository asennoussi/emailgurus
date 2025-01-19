from datetime import datetime, timedelta
from hashlib import sha256
import json
import re

import django_rq
from django.conf import settings
from django.core.mail import EmailMessage
from django.core.signing import Signer
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils import timezone

from django_rq.queues import get_queue

import google.oauth2.credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from accounts.models import CustomUser, LinkedAccounts
from contacts.models import Contact, Label
from dashboard.forms import PaymentButtonForm
from dashboard.models import EmailDebugInfo, FilteredEmails, Jobs

signer = Signer()


################################################################################
#                          AUTH / UTILITY FUNCTIONS
################################################################################

def get_associated_email(flow):
    """
    Retrieves the associated email address from the given OAuth flow credentials.
    """
    try:
        service = build('oauth2', 'v2', credentials=flow.credentials)
        results = service.userinfo().get().execute()
        return results.get('email', None)
    except HttpError as err:
        print(err)
        return None


def credentials_to_dict(credentials):
    """
    Securely signs and returns a dictionary of credentials that can be stored.
    """
    return signer.sign_object({
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    })


def get_scopes():
    """
    Returns the list of required Google API scopes.
    """
    scopes_urls = [
        '/auth/userinfo.email',
        '/auth/contacts.readonly',
        '/auth/gmail.modify',
        '/auth/contacts.other.readonly'
    ]
    return ['https://www.googleapis.com' + x for x in scopes_urls]


def get_google_flow():
    """
    Creates a Flow instance from the client secrets file for OAuth2.
    """
    import os
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

    scopes = get_scopes()
    try:
        flow = Flow.from_client_secrets_file(
            settings.GOOGLE_APP_SECRET_JSON_PATH,
            scopes=scopes
        )
        flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
        return flow
    except FileNotFoundError:
        print("The file doesn't exist. Please create credentials file")
        return {}


################################################################################
#                          GMAIL HANDLING FUNCTIONS
################################################################################

def is_part_of_contact_thread(service, email_id, user, la):
    """
    Checks if the given email is part of an existing thread
    involving any contact in the database for that linked account.
    """
    try:
        message = service.users().messages().get(
            userId='me', id=email_id, format='full'
        ).execute()
        thread_id = message['threadId']

        thread = service.users().threads().get(
            userId='me', id=thread_id
        ).execute()

        email_pattern = r'([\w\.-]+@[\w\.-]+)'
        for msg in thread['messages']:
            headers = msg['payload']['headers']
            for header in headers:
                if header["name"].lower() == "from":
                    from_value = header["value"]
                    match = re.search(email_pattern, from_value)
                    if match:
                        from_email = match.group(1)
                        encrypted_contact = sha256(
                            from_email.encode('utf-8')
                        ).hexdigest()
                        if Contact.objects.filter(
                            hashed_email=encrypted_contact,
                            linked_account=la
                        ).exists():
                            return True

    except HttpError as error:
        print(f"An error occurred: {error}")
        return False

    return False


def get_email_domain(email):
    """
    Returns the domain of the given email address,
    unless it's gmail.com, in which case returns an empty string.
    """
    domain = email[email.index('@') + 1:]
    return '' if domain == 'gmail.com' else domain


def is_user_active(user):
    """
    Checks whether a user is active based on subscription status or expiration.
    """
    today = timezone.now().date()
    return (
        user.subscription_status in ['subscribed', 'trial'] or
        (user.subscription_status == 'canceled' and user.expires_at.date() > today)
    )


def handle_email(email_id, from_email, user, associated_email):
    """
    Determines how to handle an incoming email based on:
    - Whether the user is active.
    - Whether the domain is whitelisted.
    - Whether the LinkedAccount is active.
    - Whether the email is from an existing contact or is part of an existing thread.

    It then applies the appropriate Gmail label modifications (pass or filter).
    Also logs debug info.
    """
    encrypted_contact = sha256(from_email.encode('utf-8')).hexdigest()
    la = LinkedAccounts.objects.get(associated_email=associated_email)

    qs = Contact.objects.filter(hashed_email=encrypted_contact, linked_account=la)
    domain = get_email_domain(from_email)

    # Prepare credentials for Gmail service
    credentials_dict = signer.unsign_object(la.credentials)
    credentials = google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"]
    )
    service = build('gmail', 'v1', credentials=credentials)

    debug_info = []

    if not is_user_active(user):
        debug_info.append("User is not active.")
    elif domain in la.whitelist_domains:
        debug_info.append(f"Domain {domain} is whitelisted.")
    elif not la.active:
        debug_info.append("Linked account is not active.")
    else:
        if qs.exists():
            debug_info.append("Sender is in the contact list.")
        elif is_part_of_contact_thread(service, email_id, user, la):
            debug_info.append("Email is part of an existing thread.")
        else:
            debug_info.append("Email did not meet any criteria.")

    # Log debug info
    debug_info_str = " | ".join(debug_info)
    EmailDebugInfo.objects.create(
        date_processed=timezone.now(),
        process_status='passed' if (qs.exists() or is_part_of_contact_thread(
            service, email_id, user, la)) else 'filtered',
        owner=user,
        linked_account=la,
        debug_info=debug_info_str,
        from_email_hashed=encrypted_contact
    )

    # Early return if the user is not in an active state or the domain is whitelisted or LA is inactive
    if not is_user_active(user) or domain in la.whitelist_domains or not la.active:
        return

    # If the email is from a contact or existing thread, remove label (if previously assigned) or add contact-specific label
    if qs.exists() or is_part_of_contact_thread(service, email_id, user, la):
        update_label = {
            "addLabelIds": [],
            "removeLabelIds": [la.label]
        }
        # If using contact-specific labels, add that label
        if la.use_contact_labels and qs.exists():
            contact = qs.first()
            if contact.label:
                update_label["addLabelIds"] = [contact.label.gmail_label_id]

        service.users().messages().modify(
            userId='me', id=email_id, body=update_label
        ).execute()

        passed_email, created = FilteredEmails.objects.get_or_create(
            date_filtered=timezone.now(),
            process_status='passed',
            owner=user,
            linked_account=la,
            defaults={'owner': user, 'linked_account': la, 'process_status': 'passed'}
        )
        passed_email.count_emails += 1
        passed_email.save()
        return

    # Otherwise, filter the email
    update_label = {
        "addLabelIds": [la.label],
        "removeLabelIds": ["INBOX"]
    }
    if not la.archive_emails:
        update_label.pop('removeLabelIds', None)

    if la.trash_emails:
        update_label = {
            "addLabelIds": ["TRASH"],
            "removeLabelIds": ["INBOX"]
        }

    service.users().messages().modify(
        userId='me', id=email_id, body=update_label
    ).execute()

    filtered_email, created = FilteredEmails.objects.get_or_create(
        date_filtered=timezone.now(),
        process_status='filtered',
        owner=user,
        linked_account=la,
        defaults={'owner': user, 'linked_account': la, 'process_status': 'filtered'}
    )
    if not created:
        filtered_email.count_emails += 1
        filtered_email.save()


def stop_watcher(associated_email):
    """
    Calls Gmail's stop() watch method to stop receiving push notifications.
    """
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    credentials_dict = signer.unsign_object(la.credentials)
    credentials = google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"]
    )
    gmail = build('gmail', 'v1', credentials=credentials)
    try:
        gmail.users().stop(userId='me').execute()
    except Exception:
        pass


def watch_email(associated_email):
    """
    Sets up Gmail watch on the account identified by associated_email.
    Resets the watch daily via RQ scheduling.
    """
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    credentials_dict = signer.unsign_object(la.credentials)
    credentials = google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"]
    )

    if la.owner.subscription_status not in ['subscribed', 'trial'] or not la.active:
        return

    try:
        if not la.check_spam:
            request = {
                'labelIds': ['SPAM'],
                'labelFilterAction': 'exclude',
                'topicName': settings.GOOGLE_TOPIC_NAME
            }
        else:
            request = {
                'topicName': settings.GOOGLE_TOPIC_NAME
            }

        gmail = build('gmail', 'v1', credentials=credentials)
        gmail.users().stop(userId='me').execute()
        watcher = gmail.users().watch(userId='me', body=request).execute()

        last_history_id = watcher["historyId"]
        la.last_history_id = last_history_id
        la.save()

        job = Jobs.objects.filter(
            owner=la.owner,
            linked_account=la,
            job_type='watcher'
        )
        queue = get_queue('default')

        if job.exists():
            job_queue = queue.fetch_job(job[0].job_id)
            if not job_queue or job_queue.get_status() != 'scheduled':
                nq = queue.enqueue_in(timedelta(days=1), watch_email, associated_email)
                job.delete()
                Jobs.objects.create(job_id=nq.id, owner=la.owner,
                                    linked_account=la, job_type='watcher')
        else:
            nq = queue.enqueue_in(timedelta(days=1), watch_email, associated_email)
            Jobs.objects.create(job_id=nq.id, owner=la.owner,
                                linked_account=la, job_type='watcher')

    except Exception as error:
        print(f'An error occurred: {error}')


################################################################################
#                          CONTACT SYNC FUNCTIONS
################################################################################

def update_contacts(associated_email, selected_labels=None):
    """Update contact syncing to handle multiple labels per contact"""
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    print(f"\nSyncing contacts for {associated_email}...")

    # Clean up: Delete all existing labels and contacts for this linked account
    Label.objects.filter(linked_account=la).delete()  # This will also clear the M2M relationships
    Contact.objects.filter(linked_account=la).delete()

    # Build credentials and get contacts
    credentials_dict = signer.unsign_object(la.credentials)
    credentials = google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"]
    )

    contacts_data = get_contacts(
        credentials, 
        linked_account=la, 
        hashed=True,
        selected_labels=selected_labels
    )
    
    # Create contacts with their labels
    for data in contacts_data:
        contact = Contact.objects.create(
            linked_account=la,
            user=la.owner,
            hashed_email=data['hashed_email']
        )
        if data['labels']:
            contact.labels.add(*data['labels'])
            print(f" - Contact {data['hashed_email'][:8]}... assigned {len(data['labels'])} labels")
        else:
            print(f" - Contact {data['hashed_email'][:8]}... has no labels")

    print(f"Successfully created {len(contacts_data)} contacts.\n")

    # Update user contact count and reschedule job
    job = Jobs.objects.filter(owner=la.owner, linked_account=la, job_type='contact')
    queue = get_queue('default')

    if job.exists():
        job_queue = queue.fetch_job(job[0].job_id)
        if not job_queue or job_queue.get_status() != 'scheduled':
            nq = queue.enqueue_in(timedelta(hours=1), update_contacts, associated_email)
            job.delete()
            Jobs.objects.create(job_id=nq.id, owner=la.owner,
                                linked_account=la, job_type='contact')
    else:
        nq = queue.enqueue_in(timedelta(hours=1), update_contacts, associated_email)
        Jobs.objects.create(job_id=nq.id, owner=la.owner,
                            linked_account=la, job_type='contact')


def get_other_contacts(credentials, hashed=True):
    """
    Pulls 'Other Contacts' from the People API, returning either hashed or
    plain email addresses, depending on the `hashed` flag.
    """
    all_connections = []
    emails_list = []
    try:
        service = build('people', 'v1', credentials=credentials)
        has_next_page = True

        kwargs = {
            'resourceName': False,
            'pageSize': 1000,
            'readMask': 'emailAddresses',
            'pageToken': False
        }

        while has_next_page:
            results = service.otherContacts().list(
                **{k: v for k, v in kwargs.items() if v}
            ).execute()

            connections = results.get('otherContacts', [])
            all_connections.extend(connections)
            kwargs['pageToken'] = results.get('nextPageToken', False)
            has_next_page = kwargs['pageToken']

        for person in all_connections:
            emails = person.get('emailAddresses', [])
            for email_obj in emails:
                raw_email = email_obj['value']
                if hashed:
                    raw_email = sha256(raw_email.encode('utf-8')).hexdigest()
                emails_list.append(raw_email)

    except HttpError as err:
        print(err)
    return emails_list


def _get_contacts_email_list_only(credentials, hashed=True):
    """
    Helper for get_contacts when linked_account is False. Returns a flat list
    of emails (hashed or not) without any label processing.
    """
    emails_list = []
    try:
        service = build('people', 'v1', credentials=credentials)

        has_next_page = True
        kwargs = {
            'resourceName': 'people/me',
            'pageSize': 1000,
            'personFields': 'emailAddresses',
            'pageToken': None
        }

        while has_next_page:
            results = service.people().connections().list(
                **{k: v for k, v in kwargs.items() if v is not None}
            ).execute()

            connections = results.get('connections', [])
            for person in connections:
                for email_obj in person.get('emailAddresses', []):
                    raw_email = email_obj.get('value')
                    if raw_email:
                        if hashed:
                            raw_email = sha256(raw_email.encode('utf-8')).hexdigest()
                        emails_list.append(raw_email)

            kwargs['pageToken'] = results.get('nextPageToken', False)
            has_next_page = kwargs['pageToken']

    except HttpError as e:
        print(f"Error fetching contacts (email only): {e}")

    return emails_list


def get_contacts(credentials, linked_account, hashed=True, selected_labels=None):
    if not linked_account:
        return _get_contacts_email_list_only(credentials, hashed)

    try:
        # Build API services
        people_service = build('people', 'v1', credentials=credentials)
        gmail_service = build('gmail', 'v1', credentials=credentials)
        all_connections = []

        # 1) Get contact groups
        groups_result = people_service.contactGroups().list().execute()
        contact_groups = {
            group['resourceName']: group['name']
            for group in groups_result.get('contactGroups', [])
        }

        # 2) Collect all connections
        kwargs = {
            'resourceName': 'people/me',
            'pageSize': 1000,
            'personFields': 'names,emailAddresses,memberships,metadata,userDefined',
            'pageToken': None
        }
        while True:
            results = people_service.people().connections().list(**kwargs).execute()
            connections = results.get('connections', [])
            if not connections:
                break
            all_connections.extend(connections)
            if 'nextPageToken' not in results:
                break
            kwargs['pageToken'] = results['nextPageToken']

        # 3) Identify all unique label names
        unique_labels = set()
        for person in all_connections:
            memberships = person.get('memberships', [])
            for membership in memberships:
                grp = membership.get('contactGroupMembership', {})
                # >>> CHANGE: use contactGroupResourceName, not contactGroupId
                resource_name = grp.get('contactGroupResourceName')
                if resource_name and resource_name in contact_groups:
                    unique_labels.add(contact_groups[resource_name])

        # 4) Create/fetch corresponding Gmail labels (only selected ones)
        label_map = {}
        if selected_labels:
            for label_data in selected_labels:
                db_label, _ = Label.objects.get_or_create(
                    gmail_label_id=label_data['gmail_label_id'],
                    linked_account=linked_account,
                    defaults={'name': label_data['name']}
                )
                label_map[label_data['name']] = db_label

        # 5) Build up the data for each person (only using selected labels)
        contacts_data = {}
        for person in all_connections:
            memberships = person.get('memberships', [])
            person_label_names = set()

            for membership in memberships:
                grp = membership.get('contactGroupMembership', {})
                resource_name = grp.get('contactGroupResourceName')
                if resource_name and resource_name in contact_groups:
                    person_label_names.add(contact_groups[resource_name])

            emails = person.get('emailAddresses', [])
            for email_obj in emails:
                raw_email = email_obj.get('value')
                if not raw_email:
                    continue
                hashed_email = sha256(raw_email.encode('utf-8')).hexdigest() if hashed else raw_email

                # Store unique contact with all its labels
                if hashed_email not in contacts_data:
                    contacts_data[hashed_email] = {
                        'hashed_email': hashed_email,
                        'labels': set()
                    }
                
                # Add all labels for this contact
                for ln in person_label_names:
                    if ln in label_map:
                        contacts_data[hashed_email]['labels'].add(label_map[ln])

        return list(contacts_data.values())

    except HttpError as err:
        print(f"Error accessing Google People API: {err}")
        return []


################################################################################
#                          INVITE / REFERRAL FUNCTIONS
################################################################################

def send_invite_emails(user):
    """
    Enqueue a job to schedule chunked emails for invitations.
    """
    queue = get_queue('default')
    queue.enqueue(schedule_chunk_emails, user)


def schedule_chunk_emails(user, chunk_size=100):
    """
    Batches the user's contacts into scheduled RQ jobs to send invite emails.
    """
    linked_accounts = LinkedAccounts.objects.filter(owner=user, active=True, invites_sent=False)
    registered_emails = set(CustomUser.objects.values_list('email', flat=True))
    all_contacts = set()

    for la in linked_accounts:
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
            # get_contacts with second param=False => returns list of email strings
            contacts = get_contacts(credentials, linked_account=False, hashed=False)
            other_contacts = get_other_contacts(credentials, hashed=False)
            all_contacts.update(contacts + other_contacts)

            # Exclude already-registered emails
            all_contacts = all_contacts - registered_emails

            # Only invite those with gmail.com
            gmail_contacts = [email for email in all_contacts if email.endswith('@gmail.com')]

            queue = get_queue('default')
            for i in range(0, len(gmail_contacts), chunk_size):
                scheduled_mins = i // chunk_size
                email_chunk = gmail_contacts[i:i + chunk_size]
                queue.enqueue_in(
                    timedelta(minutes=scheduled_mins),
                    send_email_chunk,
                    email_chunk,
                    user=la.owner
                )

            la.invites_sent = True
            la.save()

        except Exception as e:
            print(f"Error scheduling invites for {la.associated_email}: {e}")


def send_email_chunk(email_chunk, user):
    """
    Sends out invite emails in chunks to avoid mass mail in a single moment.
    """
    try:
        for email in email_chunk:
            sender_name = user.full_name if user.full_name else user.email
            subject = f'{sender_name} is inviting you to try Emailgurus'
            context = {
                'name': sender_name,
                'code': user.referral_code
            }
            html_content = render_to_string('emails/referral_email.html', context)

            msg = EmailMessage(subject, html_content, to=[email])
            msg.content_subtype = 'html'
            msg.send()
        return "Email sent"
    except Exception as e:
        print(f"Error sending email chunk: {e}")


################################################################################
#                            LINKED ACCOUNT CREATION
################################################################################

def create_or_update_linked_account(request, credentials, email):
    """
    Creates or updates a LinkedAccounts entry for the user's Gmail connection.
    Also creates/fetches a system label used for archiving.
    """
    service = build('gmail', 'v1', credentials=credentials)
    new_label_body = {
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
            userId='me', body=new_label_body
        ).execute()
        created_label = created_label_object['id']
    except:
        # If it already exists, fetch the label from the API
        labels = service.users().labels().list(userId='me').execute()
        created_label = ''
        for label in labels.get('labels', []):
            if label.get('color'):
                # Attempt identification by name or color
                if label['name'] == settings.EG_LABEL or label['color'].get('backgroundColor') == '#8e63ce':
                    created_label = label['id']
                    break

    credentials_dict = credentials_to_dict(credentials)
    domain = get_email_domain(email)

    if credentials.refresh_token:
        # Link or create new LinkedAccount
        linked_account, created = LinkedAccounts.objects.get_or_create(
            associated_email=email,
            defaults={
                'owner': request.user,
                'credentials': credentials_dict,
                'whitelist_domains': [domain]
            }
        )
        if not created and linked_account.deleted:
            linked_account.deleted = False
            if domain not in linked_account.whitelist_domains:
                linked_account.whitelist_domains.append(domain)
            linked_account.save()

        # Immediately start watching the inbox
        django_rq.enqueue(watch_email, associated_email=email)
        return linked_account, created, credentials_dict, created_label, False
    else:
        # Possibly a re-activation scenario (already had this account, no new refresh token)
        linked_account = LinkedAccounts.objects.get(owner=request.user, associated_email=email)
        if linked_account.deleted:
            linked_account.deleted = False
        linked_account.label = created_label
        linked_account.save()

        # Immediately start watching the inbox
        django_rq.enqueue(watch_email, associated_email=email)

        return None, False, {}, '', True


################################################################################
#                            PAYPAL BUTTON FORM
################################################################################

def get_paypal_button(request):
    """
    Returns the PaymentButtonForm pre-initialized for a subscription.
    """
    paypal_dict = {
        "cmd": "_xclick-subscriptions",
        'business': settings.PAYPAL_RECEIVER_EMAIL,
        "a3": 12.99,  # monthly price
        "p3": 1,      # duration of each unit
        "t3": 'M',    # 'M' for month
        "src": "1",   # make payments recur
        "sra": "1",   # reattempt payment on payment error
        "no_note": "1",
        'item_name': 'Emailgurus subscription',
        'custom': request.user.id,     # pass user_id
        'currency_code': 'USD',
        'notify_url': request.build_absolute_uri(reverse_lazy('paypal-ipn')),
        'return_url': request.build_absolute_uri(reverse_lazy('payment_done')),
        'cancel_return': request.build_absolute_uri(reverse_lazy('payment_canceled')),
    }
    return PaymentButtonForm(initial=paypal_dict)