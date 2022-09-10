from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.password_validation import validate_password


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if validate_password(password, user=user):
            user.set_password(password)

        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    SUBSCRIPTION_STATUS = (
        ('subscribed', 'SUBSCRIBED'),
        ('canceled', 'CANCELED'),
        ('trial', 'TRIAL'),
        ('free', 'FREE'),
    )
    username = None
    email = models.EmailField(_('email address'), unique=True)
    count_contact = models.IntegerField(default=0)
    subscription_status = models.CharField(
        max_length=20, choices=SUBSCRIPTION_STATUS, default='trial')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True)
    is_verified = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def is_trial(self):
        "Returns the user's trial status."
        import datetime
        today = datetime.date.today()
        if self.created_at.date() < today - datetime.timedelta(days=settings.TRIAL_DAYS_LEGNTH):
            return False
        else:
            return True

    def days_left(self):
        "Returns days left for user"
        import datetime
        today = datetime.date.today()
        days_left = (self.created_at.date(
        ) + datetime.timedelta(days=settings.TRIAL_DAYS_LEGNTH) - today).days
        return days_left if days_left >= 0 else 0

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)

    def save(self, *args, **kwargs):
        # This function is going to get called everyday when we pull
        # The new contacts list (see /utils/update_contacts)
        # so the user gets maximum the difference in timezone or less
        # of that.
        import datetime
        today = datetime.date.today()
        beyond_trial = self.created_at.date() < today - \
            datetime.timedelta(
                days=settings.TRIAL_DAYS_LEGNTH) if self.created_at else False
        if beyond_trial and self.subscription_status == 'trial':
            self.subscription_status = 'free'
        super().save(*args, **kwargs)


class LinkedAccounts(models.Model):
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    credentials = models.JSONField('Credentials')
    account_type = models.CharField(default='Google', max_length=255)
    label = models.CharField(max_length=255)
    active = models.BooleanField(default=True)
    deleted = models.BooleanField(default=False)
    associated_email = models.EmailField(unique=True)
    archive_emails = models.BooleanField(default=True)
    last_history_id = models.CharField(default='', max_length=255)
    whitelist_domains = ArrayField(
        models.CharField(max_length=255), blank=True)

    def __str__(self):
        return self.associated_email


class deletedAccounts(models.Model):
    linked_account = models.CharField(max_length=255)
    deleted_on = models.DateField(auto_now_add=True)
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return self.linked_account
