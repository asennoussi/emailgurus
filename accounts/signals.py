from django.template.loader import render_to_string
import datetime
import django_rq
from django.db.models import Sum

from accounts.models import CustomUser
from dashboard.models import FilteredEmails


def queue_expiry_emails(created, instance, ** kwargs):
    user = instance
    queue = django_rq.queues.get_queue('default')
    if created:
        # Only for testing
        # django_rq.enqueue(send_expiry_email, user.email, days_left=3)
        # django_rq.enqueue(send_expiry_email, user.email, days_left=2)
        # django_rq.enqueue(send_expiry_email, user.email, days_left=1)
        # django_rq.enqueue(send_expiry_email, user.email, days_left=0)
        # End of testing

        # Expiry J-3 Email
        queue.enqueue_in(datetime.timedelta(days=4),
                         send_expiry_email, user.email, days_left=3)
        # Expiry J-2 Email
        queue.enqueue_in(datetime.timedelta(days=5),
                         send_expiry_email, user.email, days_left=2)
        # Expiry J-1 Email
        queue.enqueue_in(datetime.timedelta(days=6),
                         send_expiry_email, user.email, days_left=1)
        # Expiry J-0 Email
        queue.enqueue_in(datetime.timedelta(days=7),
                         send_expiry_email, user.email, days_left=0)
    return True


def send_expiry_email(email_address, days_left):
    user = CustomUser.objects.get(email=email_address)
    processed_count = FilteredEmails.objects.filter(
        owner=user).aggregate(Sum('count_emails'))['count_emails__sum'] or 0
    filtered_count = FilteredEmails.objects.filter(
        owner=user, process_status='filtered').aggregate(Sum('count_emails'))['count_emails__sum'] or 0
    payload = {
        'user_id': user.id,
        'processed_count': processed_count,
        'filtered_count': filtered_count,
        'hours_saved': int(filtered_count / 100)
    }
    if user.subscription_status == 'subscribed':
        return
    match days_left:
        case 3:
            template_name = 'email-expiry-three.html'
            subject = 'Your Emailgurus account is expiring soon..'

        case 2:
            # You can connect more than 1 account. Connect your personal
            template_name = 'email-expiry-two.html'
            subject = 'Two days left until I come to your inbox..'
        case 1:
            template_name = 'email-expiry-one.html'
            subject = 'I\m almost there.. reaching.. your inbox..'
        case 0:
            template_name = 'email-expiry-zero.html'
            subject = 'Today is the day, email marketers are free to land on your inbox!'

    message = render_to_string(
        'emails/' + template_name,
        payload
    )

    return django_rq.enqueue(user.email_user,
                             subject, message, html_message=message)
