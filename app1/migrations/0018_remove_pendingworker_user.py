# Generated by Django 5.0.4 on 2024-06-02 16:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0017_pendingworker_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='pendingworker',
            name='user',
        ),
    ]
