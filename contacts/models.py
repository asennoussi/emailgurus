from django.db import models
from accounts.models import CustomUser, LinkedAccounts

class Label(models.Model):
    gmail_label_id = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    linked_account = models.ForeignKey(
        LinkedAccounts, 
        on_delete=models.CASCADE,
        related_name='contact_labels'  # Add this line
    )
    
    class Meta:
        unique_together = ('gmail_label_id', 'linked_account')

    def __str__(self):
        return self.name

class Contact(models.Model):
    hashed_email = models.CharField(max_length=64)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    linked_account = models.ForeignKey(LinkedAccounts, on_delete=models.CASCADE)
    labels = models.ManyToManyField(Label, blank=True)  # Replace single label field with M2M

    class Meta:
        indexes = [
            models.Index(fields=['linked_account', 'hashed_email']),
        ]
        unique_together = ['hashed_email', 'linked_account']  # Ensure one contact per email per account

    def __str__(self):
        return self.hashed_email
