# Generated by Django 4.1.1 on 2022-11-06 11:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0012_customuser_is_verified'),
    ]

    operations = [
        migrations.AddField(
            model_name='linkedaccounts',
            name='trash_emails',
            field=models.BooleanField(default=False),
        ),
    ]