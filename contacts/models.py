from django.db import models
from accounts.models import CustomUser, LinkedAccounts


# Create your models here.


class Contact(models.Model):
    hashed_email = models.CharField(max_length=64)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    linked_account = models.ForeignKey(
        LinkedAccounts, on_delete=models.CASCADE)

    def __str__(self):
        return self.hashed_email
