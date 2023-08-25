from django.db.models.signals import post_save
from django.dispatch import receiver
from datetime import timedelta
from accounts.models import CustomUser
from .models import Referral
from django.utils import timezone


@receiver(post_save, sender=CustomUser)
def process_referral(sender, instance, **kwargs):
    user = instance
    print("Signal Referral received")

    # Check if the user's subscription_status has become 'subscribed'
    if user.subscription_status == 'subscribed':
        try:
            # Fetch the referral object where the user is the referred_user
            referral = Referral.objects.get(referred_user=user)

            # If the referral is not successful yet, process it
            if not referral.successful:
                inviter = referral.inviter

                if inviter.expires_at:
                    inviter.expires_at += timedelta(days=14)
                else:
                    # Handle the case where expires_at is None
                    # You might want to set it to some default datetime value or log an error.
                    inviter.expires_at = timezone.now() + timedelta(days=14)

                # Extend the inviter's payment due date by 14 days
                inviter.expires_at += timedelta(days=14)
                inviter.save()

                # Mark the referral as successful
                referral.successful = True
                referral.save()
        except Referral.DoesNotExist:
            # No referral exists for this user, do nothing
            pass
