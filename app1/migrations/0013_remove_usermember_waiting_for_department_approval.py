# Generated by Django 5.0.4 on 2024-05-31 03:53

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0012_usermember_waiting_for_department_approval'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='usermember',
            name='waiting_for_department_approval',
        ),
    ]
