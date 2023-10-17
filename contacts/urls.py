from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('referrals/invite', views.InviteContactsRedirectView.as_view(),
         name='invite_contacts'),
]
