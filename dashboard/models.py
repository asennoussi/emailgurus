from django.db import models

from accounts.models import CustomUser, LinkedAccounts

# Create your models here.


class FilteredEmails(models.Model):
    PROCESS_STATUS = (
        ('filtered', 'FILTERED'),
        ('passed', 'PASSED'),
    )

    linked_account = models.ForeignKey(
        LinkedAccounts, on_delete=models.CASCADE)
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    date_filtered = models.DateField(auto_now_add=True)
    count_emails = models.IntegerField(default=1)
    process_status = models.CharField(
        max_length=20, choices=PROCESS_STATUS)

    def __str__(self):
        return self.linked_account.associated_email + ' ' + self.process_status + ' ' + self.date_filtered.strftime("%m/%d/%Y")


class Jobs(models.Model):
    JOB_TYPE = (
        ('watcher', 'WATCHER'),
        ('contact', 'CONTACT'),
    )

    linked_account = models.ForeignKey(
        LinkedAccounts, on_delete=models.CASCADE)
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    job_id = models.CharField(max_length=255)
    job_type = models.CharField(
        max_length=20, choices=JOB_TYPE)

    def __str__(self):
        return self.job_type + ' on ' + self.linked_account.associated_email
