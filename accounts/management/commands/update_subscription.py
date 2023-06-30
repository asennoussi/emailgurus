from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from accounts.models import CustomUser
from django.conf import settings


class Command(BaseCommand):
    help = 'Updates user subscription statuses'

    def handle(self, *args, **kwargs):
        trial_users = CustomUser.objects.filter(subscription_status='trial')
        canceled_users = CustomUser.objects.filter(
            subscription_status='canceled')
        count = 0  # Counter for affected users

        for user in trial_users:
            if user.created_at.date() < timezone.now().date() - timedelta(days=settings.TRIAL_DAYS_LEGNTH):
                user.subscription_status = 'free'
                user.save()
                count += 1  # Increase the counter if a user was updated

        for user in canceled_users:
            if user.expires_at and user.expires_at.date() < timezone.now().date():
                user.subscription_status = 'free'
                user.save()
                count += 1  # Increase the counter if a user was updated

        self.stdout.write(self.style.SUCCESS(
            'Successfully updated subscription status for %s user(s)' % count))
