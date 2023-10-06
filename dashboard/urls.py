from django.urls import path

from . import views

urlpatterns = [
    path('', views.DashboardView.as_view(), name='dashboard'),
    path('linked-accounts', views.LinkedaccountsView.as_view(),
         name='linked_accounts'),
    path('account_settings/<int:pk>', views.AccountSettings.as_view(),
         name='account_settings'),
    path('linked-accounts/toggle-status/<int:pk>',
         views.ToggleStatusRedirectView.as_view(), name="toggle_status"),
    path('linked-accounts/refresh-listener/<int:pk>',
         views.RefreshListenerRedirectView.as_view(), name="refresh_listener"),
    path('linked-accounts/sync-contacts/<int:pk>',
         views.SyncContactsRedirectView.as_view(), name="sync_contacts"),
    path('link/google', views.LinkGoogleRedirectView.as_view(), name="link_google"),
    path('link/google-callback', views.LinkAccounts.as_view()),
    path('link/<str:status>', views.LinkStatusView.as_view(), name='link_status'),
    path('payment-done/', views.DashboardView.payment_done, name='payment_done'),
    path('payment-cancelled/', views.DashboardView.payment_canceled,
         name='payment_canceled'),
    path('linked-accounts/unlink/<int:pk>',
         views.UnlinkAccountRedirectView.as_view(), name="unlink_account"),
    path('referrals/', views.UserReferralsView.as_view(), name='user_referrals'),
    path('debugger/', views.DebuggerView.as_view(), name='email_debugger'),
]
