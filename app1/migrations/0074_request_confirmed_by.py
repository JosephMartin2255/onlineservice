# Generated by Django 5.0.4 on 2024-06-26 11:08

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0073_remove_request_confirmed_by_request_worker'),
    ]

    operations = [
        migrations.AddField(
            model_name='request',
            name='confirmed_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='confirmed_requests', to=settings.AUTH_USER_MODEL),
        ),
    ]
