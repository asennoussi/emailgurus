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
        (user.subscription_status == 'canceled' and user.expires_at and user.expires_at.date() > today)
    )

################################################################################
#                     GOOGLE PEOPLE / CONTACT IMPORT FUNCTIONS
################################################################################

def update_contacts(associated_email, selected_labels=None):
    """
    1) Delete all existing Contacts (M2M relationships removed automatically).
    2) Delete all existing Labels for the LinkedAccount.
    3) Create fresh Label objects for the selected labels (if any).
    4) Retrieve & create new Contacts from People API, ensuring no duplicates.
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

    # --- FIX: Deduplicate by hashed_email before creating ---
    # Build a dict keyed by hashed_email, merging label sets for that email.
    # contacts_data is a list of {'hashed_email': x, 'labels': [Label, ...]}
    unique_contacts_map = {}
    for data in contacts_data:
        hashed_email = data['hashed_email']
        if hashed_email not in unique_contacts_map:
            unique_contacts_map[hashed_email] = {
                'hashed_email': hashed_email,
                'labels': set(data['labels']),
            }
        else:
            # Merge the label sets if we see the same hashed email again
            unique_contacts_map[hashed_email]['labels'].update(data['labels'])

    # 5) Create new Contact objects once per unique hashed_email
    created_count = 0
    for entry in unique_contacts_map.values():
        contact = Contact.objects.create(
            linked_account=la,
            user=la.owner,
            hashed_email=entry['hashed_email']
        )
        if entry['labels']:
            contact.labels.set(entry['labels'])
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

                    # Filter only the selected labels that match the person’s membership
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
            existing_job = queue.fetch_job(job[0].job_id)
            if not existing_job or existing_job.get_status() != 'scheduled':
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
      - Whether the user is active or domain is whitelisted or LA is inactive => pass.
      - If mark_first_outsider is ON and truly the first time we see this sender => 
        label outsider but do NOT remove from INBOX.
      - Else, if from a known contact or an existing thread => pass.
      - Otherwise => filter (archive or trash).
    
    Logs the outcome in EmailDebugInfo and increments FilteredEmails accordingly.
    """
    la = LinkedAccounts.objects.get(associated_email=associated_email)
    encrypted_contact = sha256(from_email.encode('utf-8')).hexdigest()
    domain = get_email_domain(from_email)

    credentials = _build_credentials(la.credentials)
    service = build('gmail', 'v1', credentials=credentials)

    debug_info = []
    process_status = ''

    # 1) Evaluate quick pass conditions
    if not is_user_active(user):
        debug_info.append("User is not active -> pass.")
        process_status = 'passed'
    elif domain in la.whitelist_domains:
        debug_info.append(f"Domain '{domain}' is whitelisted -> pass.")
        process_status = 'passed'
    elif not la.active:
        debug_info.append("Linked account is not active -> pass.")
        process_status = 'passed'

    # 2) If no pass condition triggered, proceed with advanced logic
    if not process_status:
        # Check if this hashed email is truly first-time for this LA
        prior_debug_exists = EmailDebugInfo.objects.filter(
            from_email_hashed=encrypted_contact,
            linked_account=la
        ).exists()

        # (A) If user wants to mark first-time outsiders, do so
        if la.mark_first_outsider and not prior_debug_exists:
            debug_info.append("First-time outsider. Labeling but not archiving.")
            process_status = 'outsider'

            # If you have an outsider label in settings, add it here:
            if hasattr(settings, 'EG_OUTSIDER_LABEL_ID') and settings.EG_OUTSIDER_LABEL_ID:
                update_label = {
                    "addLabelIds": [settings.EG_OUTSIDER_LABEL_ID],
                    "removeLabelIds": []
                }
                try:
                    service.users().messages().modify(userId='me', id=email_id, body=update_label).execute()
                except HttpError as e:
                    debug_info.append(f"Error labeling outsider: {e}")

        else:
            # (B) If from existing contact or existing thread => pass
            if Contact.objects.filter(hashed_email=encrypted_contact, linked_account=la).exists() \
               or is_part_of_contact_thread(service, email_id, user, la):
                debug_info.append("Sender in contact list or existing thread -> pass.")
                process_status = 'passed'

                # Possibly remove your filter label if it was applied previously
                if hasattr(settings, 'EG_LABEL') and settings.EG_LABEL:
                    remove_label_body = {
                        "addLabelIds": [],
                        "removeLabelIds": [settings.EG_LABEL]
                    }
                    try:
                        service.users().messages().modify(userId='me', id=email_id, body=remove_label_body).execute()
                    except HttpError as e:
                        debug_info.append(f"Error removing filter label: {e}")

            else:
                # (C) Not whitelisted or contact => filter (archive or trash)
                debug_info.append("Not whitelisted/contact -> filtering.")
                process_status = 'filtered'

                # Decide whether to trash or just archive
                if la.trash_emails:
                    update_label = {
                        "addLabelIds": ["TRASH"],
                        "removeLabelIds": ["INBOX"]
                    }
                else:
                    # If user wants to archive
                    if la.archive_emails:
                        filter_label_id = getattr(settings, 'EG_LABEL', '')
                        update_label = {
                            "addLabelIds": [filter_label_id] if filter_label_id else [],
                            "removeLabelIds": ["INBOX"]
                        }
                    else:
                        # Just label without removing INBOX
                        filter_label_id = getattr(settings, 'EG_LABEL', '')
                        update_label = {
                            "addLabelIds": [filter_label_id] if filter_label_id else [],
                            "removeLabelIds": []
                        }

                try:
                    service.users().messages().modify(userId='me', id=email_id, body=update_label).execute()
                except HttpError as e:
                    debug_info.append(f"Error filtering message: {e}")

    # 3) Record the debug info
    debug_info_str = " | ".join(debug_info)
    EmailDebugInfo.objects.create(
        date_processed=timezone.now(),
        process_status=process_status,
        owner=user,
        linked_account=la,
        debug_info=debug_info_str,
        from_email_hashed=encrypted_contact
    )

    # 4) Tally the day’s result in FilteredEmails
    if process_status in ['filtered', 'passed', 'outsider']:
        filt_obj, created = FilteredEmails.objects.get_or_create(
            date_filtered=timezone.now(),
            process_status=process_status,
            owner=user,
            linked_account=la
        )
        if not created:
            filt_obj.count_emails += 1
        else:
            filt_obj.count_emails = 1
        filt_obj.save()


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
                        encrypted_contact = sha256(from_email.encode('utf-8')).hexdigest()
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

    If you already handle label creation or store label IDs in settings, 
    you can adjust that logic accordingly.
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

    from django.core.exceptions import ObjectDoesNotExist

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

        # In either case, set the "label" field so we store the label ID if desired
        linked_account.label = created_label
        linked_account.save()

        # Start inbox watching
        django_rq.enqueue(watch_email, associated_email=email)
        return linked_account, created, credentials_dict, created_label, False

    # -----------------------------------------
    # Scenario B: No refresh token
    # (Potential "re-activation" or partial token)
    # -----------------------------------------
    else:
        try:
            # Attempt to fetch existing account
            linked_account = LinkedAccounts.objects.get(
                owner=request.user,
                associated_email=email
            )
            # "Re-activate" scenario
            if linked_account.deleted:
                linked_account.deleted = False
            linked_account.label = created_label
            linked_account.save()

            # Start inbox watching
            django_rq.enqueue(watch_email, associated_email=email)
            return None, False, {}, '', True

        except ObjectDoesNotExist:
            # No LinkedAccount found -> fallback approach
            linked_account = LinkedAccounts.objects.create(
                owner=request.user,
                associated_email=email,
                credentials=credentials_dict,
                label=created_label,
                whitelist_domains=[domain],
                deleted=False
            )
            django_rq.enqueue(watch_email, associated_email=email)
            return linked_account, True, credentials_dict, created_label, False


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