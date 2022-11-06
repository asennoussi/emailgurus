from django.urls import path, re_path

from . import views

urlpatterns = [
    re_path(r'(?P<step_name>(contacts|allowlist-domains))/$',
            views.OnboardingUpdateView.as_view(), name="onboarding-update"),
    path('<str:step_name>/', views.OnboardingView.as_view(), name="onboarding"),
]
