# Generated by Django 5.0.4 on 2024-06-17 17:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0046_remove_pendingworker_username'),
    ]

    operations = [
        migrations.AddField(
            model_name='pendingworker',
            name='username',
            field=models.CharField(default='', max_length=150),
        ),
    ]
