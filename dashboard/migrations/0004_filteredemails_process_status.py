# Generated by Django 4.0 on 2022-04-30 11:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0003_rename_date_filteredemails_date_filtered'),
    ]

    operations = [
        migrations.AddField(
            model_name='filteredemails',
            name='process_status',
            field=models.CharField(choices=[('filtered', 'FILTERED'), ('passed', 'PASSED')], default='filtered', max_length=20),
            preserve_default=False,
        ),
    ]
