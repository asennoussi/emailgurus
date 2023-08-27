"""emailguru URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from landing.views import HomeView
from accounts.views import ActivateView, LoginView, PasswordResetConfirmView, PasswordResetView, SignUpView, LogoutView, CustomUserEditView
from dashboard.views import EmailCatcher


urlpatterns = [
    path('', HomeView.as_view(), name='home'),
    path('onboarding/', include('onboarding.urls')),
    path('accounts/', include('django.contrib.auth.urls')),
    path('settings/', CustomUserEditView.as_view(), name='settings'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('sign-up/', SignUpView.as_view(), name='signup'),
    path('password-reset/', PasswordResetView.as_view(), name='password_reset'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('activate/<uidb64>/<token>/', ActivateView.as_view(), name="activate"),
    path('contacts/', include('contacts.urls')),
    path('dashboard/', include('dashboard.urls')),
    path('admin/', admin.site.urls),
    path('django-rq/', include('django_rq.urls')),
    path('paypal/', include('paypal.standard.ipn.urls')),
    path('catch/new-email', EmailCatcher.catch_email, name='catch_email'),
]
