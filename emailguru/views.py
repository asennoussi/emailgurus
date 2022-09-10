# def process_subscription(request):

#     subscription_plan = request.session.get('subscription_plan')
#     host = request.get_host()

#     if subscription_plan == '1-month':
#         price = "10"
#         billing_cycle = 1
#         billing_cycle_unit = "M"
#     elif subscription_plan == '6-month':
#         price = "50"
#         billing_cycle = 6
#         billing_cycle_unit = "M"
#     else:
#         price = "90"
#         billing_cycle = 1
#         billing_cycle_unit = "Y"

#     paypal_dict = {
#         "cmd": "_xclick-subscriptions",
#         'business': settings.PAYPAL_RECEIVER_EMAIL,
#         "a3": price,  # monthly price
#         "p3": billing_cycle,  # duration of each unit (depends on unit)
#         "t3": billing_cycle_unit,  # duration unit ("M for Month")
#         "src": "1",  # make payments recur
#         "sra": "1",  # reattempt payment on payment error
#         "no_note": "1",  # remove extra notes (optional)
#         'item_name': 'Content subscription',
#         'custom': 1,     # custom data, pass something meaningful here
#         'currency_code': 'USD',
#         'notify_url': 'http://{}{}'.format(host,
#                                            reverse('paypal-ipn')),
#         'return_url': 'http://{}{}'.format(host,
#                                            reverse('payment:done')),
#         'cancel_return': 'http://{}{}'.format(host,
#                                               reverse('payment:canceled')),
#     }

#     form = PayPalPaymentsForm(initial=paypal_dict, button_type="subscribe")
#     return render(request, 'payment/process_subscription.html', locals())
