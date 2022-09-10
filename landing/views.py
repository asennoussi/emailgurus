from django.views.generic import TemplateView

# Create your views here.


class HomeView(TemplateView):
    template_name = "landing/index.html"
