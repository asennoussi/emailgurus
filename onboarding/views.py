from django.views.generic import TemplateView, UpdateView
from django.contrib.auth.mixins import LoginRequiredMixin

from accounts.models import LinkedAccounts
from dashboard.forms import OnboardingUpdateLinkedAccountForm, UpdateLinkedAccountForm


# Create your views here.


class OnboardingView(LoginRequiredMixin, TemplateView):
    def get_template_names(self):
        step_name = self.kwargs['step_name']
        match step_name:
            case 'link-account':
                return 'link_account.html'
            case 'contacts':
                return 'contacts.html'
            case 'allowlist-domains':
                return 'allowlist_domains.html'
            case 'done':
                return 'done.html'

    def get_context_data(self, **kwargs):
        context = super(OnboardingView, self).get_context_data(**kwargs)
        context['count_contact'] = self.request.user.count_contact
        context['linked_account'] = LinkedAccounts.objects.last()
        step_name = self.kwargs['step_name']
        step_number = 1
        match step_name:
            case 'link-account':
                step_number = 1
            case 'contacts':
                step_number = 2
            case 'whitelist-domains':
                step_number = 3
            case 'done':
                step_number = 4
        context['step_number'] = step_number
        return context


class OnboardingUpdateView(LoginRequiredMixin, UpdateView):
    context_object_name = 'account'
    form_class = OnboardingUpdateLinkedAccountForm

    def get_object(self):
        return LinkedAccounts.objects.last()

    def get_template_names(self):
        step_name = self.kwargs['step_name']
        match step_name:
            case 'contacts':
                return 'contacts.html'
            case 'allowlist-domains':
                return 'allowlist_domains.html'
            case 'done':
                return 'done.html'

    def get_context_data(self, **kwargs):
        context = super(OnboardingUpdateView, self).get_context_data(**kwargs)
        step_name = self.kwargs['step_name']
        step_number = 1
        match step_name:
            case 'contacts':
                step_number = 2
            case 'whitelist-domains':
                step_number = 3
        context['step_number'] = step_number
        return context
