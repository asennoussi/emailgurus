# Generated by Django 4.1.1 on 2023-08-26 20:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('referral', '0003_referral_created_at_referral_inviter_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='referral',
            name='paid',
            field=models.BooleanField(default=False),
        ),
    ]