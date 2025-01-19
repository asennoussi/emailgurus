from django.shortcuts import render
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

@method_decorator(csrf_exempt, name='dispatch')
class PaymentDoneView(View):
    """
    Called when a payment is completed successfully.
    Renders a success page or handles any additional payment logic.
    """

    def post(self, request, *args, **kwargs):
        # You can add any post-payment logic here, e.g. creating Payment records, sending receipts, etc.
        return render(request, 'dashboard/success.html')

    def get(self, request, *args, **kwargs):
        # Sometimes payment gateways send success GET requests as well, 
        # so you might want to handle GET requests similarly.
        return render(request, 'dashboard/success.html')


@method_decorator(csrf_exempt, name='dispatch')
class PaymentCanceledView(View):
    """
    Called when a payment is cancelled or fails.
    Renders a cancellation page or handles any cleanup actions.
    """

    def post(self, request, *args, **kwargs):
        # You can add any logic here to handle cleanup or logging for a cancelled payment.
        return render(request, 'ecommerce_app/payment_cancelled.html')

    def get(self, request, *args, **kwargs):
        # Handle GET if the payment gateway redirects to this URL via GET instead of POST.
        return render(request, 'ecommerce_app/payment_cancelled.html')