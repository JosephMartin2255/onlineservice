# Generated by Django 5.0.4 on 2024-05-30 16:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0011_usermember_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='usermember',
            name='waiting_for_department_approval',
            field=models.BooleanField(default=False),
        ),
    ]
