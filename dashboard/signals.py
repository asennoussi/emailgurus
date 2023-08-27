from paypal.standard.ipn.signals import valid_ipn_received
from django.dispatch import receiver
import datetime
from django.template.loader import render_to_string
import django_rq

from accounts.models import CustomUser
from dateutil import relativedelta
import pytz

from dashboard.models import FilteredEmails
from django.db.models import Sum


@receiver(valid_ipn_received)
def ipn_receiver(sender, **kwargs):
    ipn_obj = sender
    next_month = pytz.utc.localize(
        datetime.datetime.today() + relativedelta.relativedelta(months=1))
    id = ipn_obj.custom
    user = CustomUser.objects.get(id=id)
    processed_count = FilteredEmails.objects.filter(
        owner=user).aggregate(Sum('count_emails'))['count_emails__sum'] or 0
    filtered_count = FilteredEmails.objects.filter(
        owner=user, process_status='filtered').aggregate(Sum('count_emails'))['count_emails__sum'] or 0

    # check for Buy Now IPN
    match ipn_obj.txn_type:
        # case 'web_accept':
        #     pass

        # if ipn_obj.payment_status == ST_PP_COMPLETED:
        #     # payment was successful
        #     print('great!')
        #     order = get_object_or_404(Order, id=ipn_obj.invoice)

        #     if order.get_total_cost() == ipn_obj.mc_gross:
        #         # mark the order as paid
        #         order.paid = True
        #         order.save()

        # check for subscription signup IPN
        # case ('subscr_signup' | 'subscr_payment'):
        case 'subscr_signup':

            # get user id and activate the account

            user.subscription_status = 'subscribed'
            user.expires_at = next_month
            user.save()

            template_name = 'thank-you-subscription.html'

            subject = 'Thank you for trusting Emailgurus'

            message = render_to_string(
                'emails/' + template_name,
            )

        # check for failed subscription payment IPN
        case 'subscr_failed':
            template_name = 'subscription-failed.html'

            payload = {
                'user_id': user.id,
                'processed_count': processed_count,
                'filtered_count': filtered_count,
                'hours_saved': filtered_count / 100,
                'subscription_end_date': user.expires_at.strftime("%d %b, %Y")
            }

            subject = 'Your Emailgurus renewal or subscription failed '

            message = render_to_string(
                'emails/' + template_name,
                payload
            )

    # check for subscription cancellation IPN
        case 'subscr_cancel':
            user.subscription_status = 'canceled'
            user.save()
            template_name = 'subscription-canceled.html'

            payload = {
                'user_id': user.id,
                'processed_count': processed_count,
                'filtered_count': filtered_count,
                'hours_saved': filtered_count / 100,
                'subscription_end_date': user.expires_at.strftime("%d %b, %Y")}

            subject = 'Sorry to see you go..'

            message = render_to_string(
                'emails/' + template_name, payload
            )
    if ipn_obj.txn_type in ['subscr_cancel', 'subscr_failed', 'subscr_signup']:
        return django_rq.enqueue(user.email_user,
                                 subject, message, html_message=message)
    else:
        return 'OK'
