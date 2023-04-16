from django.db import models
from accounts.models import CustomUser


class Referral(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='referred_by')
    referred_users = models.ManyToManyField(
        CustomUser)
