# Generated by Django 5.1.3 on 2025-01-20 06:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0021_linkedaccounts_use_contact_labels'),
    ]

    operations = [
        migrations.AddField(
            model_name='linkedaccounts',
            name='mark_first_outsider',
            field=models.BooleanField(default=False),
        ),
    ]
