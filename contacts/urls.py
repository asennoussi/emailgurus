from django.urls import path
from .views import SelectLabelsView

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('referrals/invite', views.InviteContactsRedirectView.as_view(),
         name='invite_contacts'),
    path('select-labels/<int:pk>/', SelectLabelsView.as_view(), name='select_labels'),
]
