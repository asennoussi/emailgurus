# Generated by Django 4.1.1 on 2023-08-26 20:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0016_customuser_paypal_email'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='paypal_email',
            field=models.EmailField(blank=True, max_length=254, null=True, verbose_name='Paypal email address'),
        ),
    ]
