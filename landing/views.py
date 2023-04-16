from django.shortcuts import render
from django.views.generic import TemplateView

# Create your views here.


class HomeView(TemplateView):
    template_name = "landing/index.html"

    def get(self, request):
        # Save the referral code in a cookie
        ref = request.GET.get('ref', '')
        response = render(request, self.template_name, {
                          'referral_code': ref})
        response.set_cookie('referral_code', ref)
        return response
