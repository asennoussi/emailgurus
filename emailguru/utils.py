import json
import re
import os
from datetime import datetime, timedelta
from hashlib import sha256

import django_rq
from django.conf import settings
from django.core.mail import EmailMessage
from django.core.signing import Signer
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils import timezone

from django_rq.queues import get_queue
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import google.oauth2.credentials
from google_auth_oauthlib.flow import Flow

from accounts.models import CustomUser, LinkedAccounts
from contacts.models import Contact, Label
from dashboard.forms import PaymentButtonForm
from dashboard.models import EmailDebugInfo, FilteredEmails, Jobs

signer = Signer()

################################################################################
#                             AUTH / OAUTH HELPERS
################################################################################

def credentials_to_dict(credentials):
    """
    Securely signs and returns a dictionary of credentials that can be stored in DB.
    """
    return signer.sign_object({
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    })

def _build_credentials(signed_credentials):
    """
    Helper to safely unsign and build a google.oauth2.credentials.Credentials object
    from a Signed JSON string stored in LinkedAccounts.
    """
    credentials_dict = signer.unsign_object(signed_credentials)
    return google.oauth2.credentials.Credentials(
        credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict["scopes"]
    )

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

################################################################################
#                             GENERAL UTILITIES
################################################################################

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

################################################################################
#                     GOOGLE PEOPLE / CONTACT IMPORT FUNCTIONS
################################################################################

def update_contacts(associated_email, selected_labels=None):
    """
    1) Delete all existing Contacts (M2M relationships removed automatically).
    2) Delete all existing Labels for the LinkedAccount.
    3) Create fresh Label objects for the selected labels (if any).
    4) Retrieve & create new Contacts from People API.
    5) Attach contacts to any relevant label(s).
    6) Reschedule contact sync job for repeated updates.
    """
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    print(f"\nSyncing contacts for {associated_email}...")

    # 1) Remove existing contacts -> also clears M2M rows in 'contacts_contact_labels'
    Contact.objects.filter(linked_account=la).delete()
    # 2) Remove existing labels
    Label.objects.filter(linked_account=la).delete()

    # 3) Create new labels based on user selections
    new_labels = []
    if selected_labels:
        for label_str in selected_labels:
            name, gmail_id = label_str.split('|')
            label = Label.objects.create(
                linked_account=la,
                gmail_label_id=gmail_id,
                name=name
            )
            new_labels.append(label)

        print(f"Created {len(new_labels)} new labels.")
    else:
        print("No labels selected, skipping label creation.")

    # 4) Fetch contacts from Google People API
    credentials = _build_credentials(la.credentials)
    contacts_data = get_contacts(
        credentials=credentials,
        linked_account=la,
        hashed=True,
        selected_labels=new_labels
    )

    # 5) Create new Contact objects and attach relevant labels
    created_count = 0
    for data in contacts_data:
        contact = Contact.objects.create(
            linked_account=la,
            user=la.owner,
            hashed_email=data['hashed_email']
        )
        # data['labels'] is the subset of new_labels that match the person’s membership
        if data['labels']:
            contact.labels.set(data['labels'])
        created_count += 1

    print(f"Successfully created {created_count} contacts.\n")

    # 6) Reschedule contact job
    _reschedule_contact_job(la)

def _reschedule_contact_job(linked_account):
    """
    Schedules or re-schedules the next automatic call to update_contacts in 1 hour.
    """
    queue = get_queue('default')
    job = Jobs.objects.filter(
        owner=linked_account.owner,
        linked_account=linked_account,
        job_type='contact'
    )

    if job.exists():
        existing_job = queue.fetch_job(job[0].job_id)
        if not existing_job or existing_job.get_status() != 'scheduled':
            nq = queue.enqueue_in(
                timedelta(hours=1),
                update_contacts,
                linked_account.associated_email
            )
            job.delete()
            Jobs.objects.create(
                job_id=nq.id,
                owner=linked_account.owner,
                linked_account=linked_account,
                job_type='contact'
            )
    else:
        nq = queue.enqueue_in(
            timedelta(hours=1),
            update_contacts,
            linked_account.associated_email
        )
        Jobs.objects.create(
            job_id=nq.id,
            owner=linked_account.owner,
            linked_account=linked_account,
            job_type='contact'
        )

def get_contacts(credentials, linked_account, hashed=True, selected_labels=None):
    """
    Fetches Google Contacts via People API for the provided linked_account.

    If selected_labels is provided, only label relationships in that set
    are assigned to the contact. Each returned dict has:
       {
         'hashed_email': <hashed or raw email>,
         'labels': [list_of_Label_objects_that_match]
       }
    """
    if not linked_account:
        # If no LinkedAccount is provided, fall back to a simple email list fetch
        return _get_contacts_email_list_only(credentials, hashed)

    try:
        people_service = build('people', 'v1', credentials=credentials)
        all_connections = []

        # (Optional) fetch all contact groups
        groups_result = people_service.contactGroups().list().execute()
        contact_groups = {
            group['resourceName']: group['name']
            for group in groups_result.get('contactGroups', [])
        }

        # Build a set of label names for quick membership check
        selected_label_names = {lbl.name for lbl in selected_labels} if selected_labels else set()

        next_page_token = None
        while True:
            response = people_service.people().connections().list(
                resourceName='people/me',
                pageSize=1000,
                pageToken=next_page_token,
                personFields='emailAddresses,memberships'
            ).execute()

            connections = response.get('connections', [])
            if not connections:
                break

            for person in connections:
                # Collect all contactGroups the person belongs to
                person_groups = set()
                for membership in person.get('memberships', []):
                    group_resource = membership.get(
                        'contactGroupMembership', {}
                    ).get('contactGroupResourceName')
                    if group_resource and group_resource in contact_groups:
                        person_groups.add(contact_groups[group_resource])

                # For each email in that person, build a record
                for email_obj in person.get('emailAddresses', []):
                    raw_email = email_obj.get('value')
                    if not raw_email:
                        continue
                    hashed_email = sha256(raw_email.encode('utf-8')).hexdigest() if hashed else raw_email

                    # Filter only the selected labels that match this person's group membership
                    matching_labels = [
                        lbl for lbl in selected_labels if lbl.name in person_groups
                    ] if selected_labels else []

                    all_connections.append({
                        'hashed_email': hashed_email,
                        'labels': matching_labels
                    })

            next_page_token = response.get('nextPageToken')
            if not next_page_token:
                break

        return all_connections

    except HttpError as err:
        print(f"Error accessing Google People API: {err}")
        return []

def _get_contacts_email_list_only(credentials, hashed=True):
    """
    Helper function for get_contacts when no LinkedAccount is provided.
    Returns a simple list of hashed or raw emails, ignoring label memberships.
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

################################################################################
#                         INVITE / REFERRAL EMAIL FUNCTIONS
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
        credentials = _build_credentials(la.credentials)
        try:
            # get_contacts with second param=False => returns list of plain emails
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

def get_other_contacts(credentials, hashed=True):
    """
    Pulls 'Other Contacts' from the People API, returning hashed or plain
    emails depending on the `hashed` flag.
    """
    all_connections = []
    emails_list = []
    try:
        service = build('people', 'v1', credentials=credentials)
        has_next_page = True

        kwargs = {
            'pageSize': 1000,
            'readMask': 'emailAddresses',
            'pageToken': None
        }

        while has_next_page:
            results = service.otherContacts().list(
                **{k: v for k, v in kwargs.items() if v is not None}
            ).execute()

            connections = results.get('otherContacts', [])
            all_connections.extend(connections)
            kwargs['pageToken'] = results.get('nextPageToken', None)
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

################################################################################
#                      GMAIL WATCH / PUSH NOTIFICATION FUNCTIONS
################################################################################

def watch_email(associated_email):
    """
    Sets up Gmail watch on the account identified by associated_email.
    Resets the watch daily via RQ scheduling.
    """
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    credentials = _build_credentials(la.credentials)

    # Check user subscription status
    if la.owner.subscription_status not in ['subscribed', 'trial'] or not la.active:
        return

    try:
        gmail = build('gmail', 'v1', credentials=credentials)
        # Configure request for watch
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

        # Stop any existing watchers, then create a new one
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
                Jobs.objects.create(
                    job_id=nq.id,
                    owner=la.owner,
                    linked_account=la,
                    job_type='watcher'
                )
        else:
            nq = queue.enqueue_in(timedelta(days=1), watch_email, associated_email)
            Jobs.objects.create(
                job_id=nq.id,
                owner=la.owner,
                linked_account=la,
                job_type='watcher'
            )

    except Exception as error:
        print(f'An error occurred: {error}')

def stop_watcher(associated_email):
    """
    Calls Gmail's stop() watch method to stop receiving push notifications.
    """
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    credentials = _build_credentials(la.credentials)
    gmail = build('gmail', 'v1', credentials=credentials)
    try:
        gmail.users().stop(userId='me').execute()
    except Exception:
        pass

################################################################################
#                        INCOMING EMAIL FILTERING
################################################################################

def handle_email(email_id, from_email, user, associated_email):
    """
    Determines how to handle an incoming email based on:
      - Whether the user is active.
      - Whether the LinkedAccount is active.
      - Whether the email domain is whitelisted.
      - Whether it's from an existing contact or an existing thread.
    Then applies the appropriate Gmail label modifications (pass or filter).
    """
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    encrypted_contact = sha256(from_email.encode('utf-8')).hexdigest()
    domain = get_email_domain(from_email)

    credentials = _build_credentials(la.credentials)
    service = build('gmail', 'v1', credentials=credentials)

    debug_info = []

    # Evaluate user & domain states
    if not is_user_active(user):
        debug_info.append("User is not active.")
    elif domain in la.whitelist_domains:
        debug_info.append(f"Domain {domain} is whitelisted.")
    elif not la.active:
        debug_info.append("Linked account is not active.")
    else:
        # If the email is from an existing contact or an existing thread, pass it
        if Contact.objects.filter(hashed_email=encrypted_contact, linked_account=la).exists() \
           or is_part_of_contact_thread(service, email_id, user, la):
            debug_info.append("Sender is in the contact list or existing thread.")
        else:
            debug_info.append("Email did not meet any pass criteria.")

    # Log debug info
    debug_info_str = " | ".join(debug_info)
    EmailDebugInfo.objects.create(
        date_processed=timezone.now(),
        process_status='passed' if ("Sender is in the contact list" in debug_info_str \
                                    or "existing thread" in debug_info_str) else 'filtered',
        owner=user,
        linked_account=la,
        debug_info=debug_info_str,
        from_email_hashed=encrypted_contact
    )

    # If user not active, domain whitelisted, or LA inactive => do nothing special
    if not is_user_active(user) or domain in la.whitelist_domains or not la.active:
        return

    # If the email is from a contact or existing thread, remove the filter label or add contact label
    if Contact.objects.filter(hashed_email=encrypted_contact, linked_account=la).exists() \
       or is_part_of_contact_thread(service, email_id, user, la):
        update_label = {
            "addLabelIds": [],
            "removeLabelIds": [la.label]
        }
        # If the user wants to use contact-specific labels, you could add logic here
        # to apply the relevant label for that contact. e.g.:
        # if la.use_contact_labels:
        #    contact = ...
        #    update_label["addLabelIds"] = [<some label ID>]

        service.users().messages().modify(
            userId='me', id=email_id, body=update_label
        ).execute()

        passed_email, _ = FilteredEmails.objects.get_or_create(
            date_filtered=timezone.now(),
            process_status='passed',
            owner=user,
            linked_account=la
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
        linked_account=la
    )
    if not created:
        filtered_email.count_emails += 1
    else:
        filtered_email.count_emails = 1
    filtered_email.save()

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
                        if Contact.objects.filter(hashed_email=encrypted_contact, linked_account=la).exists():
                            return True

    except HttpError as error:
        print(f"An error occurred: {error}")
        return False

    return False

################################################################################
#                      LINKED ACCOUNT CREATION / UPDATES
################################################################################

def create_or_update_linked_account(request, credentials, email):
    """
    Creates or updates a LinkedAccounts entry for the user's Gmail connection.
    Also creates/fetches a label used for archiving, then starts a watcher.
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
    
    # Try to create the label in Gmail
    try:
        created_label_object = service.users().labels().create(
            userId='me', body=new_label_body
        ).execute()
        created_label = created_label_object['id']
    except:
        # If it already exists, fetch from the API
        labels = service.users().labels().list(userId='me').execute()
        created_label = ''
        for label in labels.get('labels', []):
            if label.get('color'):
                # Attempt identification by name or color
                if label['name'] == settings.EG_LABEL or \
                   label['color'].get('backgroundColor') == '#8e63ce':
                    created_label = label['id']
                    break

    # Prepare dictionary for credentials
    credentials_dict = credentials_to_dict(credentials)
    domain = get_email_domain(email)

    # -----------------------------------------
    # Scenario A: We have a refresh token
    # -----------------------------------------
    if credentials.refresh_token:
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

        # Start inbox watching
        django_rq.enqueue(watch_email, associated_email=email)
        return linked_account, created, credentials_dict, created_label, False

    # -----------------------------------------
    # Scenario B: No refresh token
    # (Potential "re-activation" or partial token)
    # -----------------------------------------
    else:
        from django.core.exceptions import ObjectDoesNotExist
        try:
            # Attempt to fetch existing account
            linked_account = LinkedAccounts.objects.get(
                owner=request.user,
                associated_email=email
            )
            # "Re-activate" scenario
            if linked_account.deleted:
                linked_account.deleted = False

            # Update the label reference, if needed
            linked_account.label = created_label
            linked_account.save()

            # Start inbox watching
            django_rq.enqueue(watch_email, associated_email=email)
            return None, False, {}, '', True

        except ObjectDoesNotExist:
            # No LinkedAccount found -> fallback approach
            # If you prefer to block or show an error, you can do so.
            # Here, we create a new LinkedAccount with limited credentials.
            linked_account = LinkedAccounts.objects.create(
                owner=request.user,
                associated_email=email,
                credentials=credentials_dict,  # might be missing refresh_token
                label=created_label,
                whitelist_domains=[domain],
                deleted=False
            )
            django_rq.enqueue(watch_email, associated_email=email)
            return linked_account, True, credentials_dict, created_label, False

################################################################################
#                        PAYPAL BUTTON / SUBSCRIPTION
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