from django.db import models
from accounts.models import CustomUser


class Referral(models.Model):
    inviter = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='referrals_made',  null=True)
    referred_user = models.OneToOneField(
        CustomUser, on_delete=models.CASCADE, related_name='referred_by', null=True)

    # Additional fields to track referral information
    created_at = models.DateTimeField(auto_now_add=True)
    successful = models.BooleanField(default=False)

    class Meta:
        unique_together = ('inviter', 'referred_user')

    def __str__(self):
        return self.referred_user.email + " From " + self.inviter.email + " " + str(self.successful)
