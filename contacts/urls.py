from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('referrals/invite', views.InviteContactsRedirectView.as_view(),
         name='invite_contacts'),
    path('select-labels/<int:pk>/', views.SelectLabelsView.as_view(), name='select_labels'),
    # Add this new URL pattern:
    path('sync-with-labels/<int:pk>/', views.SyncContactsWithLabelsView.as_view(), name='sync_contacts_with_labels'),
]
