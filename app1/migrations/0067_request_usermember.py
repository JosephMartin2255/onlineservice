# Generated by Django 5.0.4 on 2024-06-23 16:47

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0066_remove_request_worker_delete_workername'),
    ]

    operations = [
        migrations.AddField(
            model_name='request',
            name='usermember',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='app1.usermember'),
        ),
    ]
