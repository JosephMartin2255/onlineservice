# Generated by Django 5.0.4 on 2024-06-11 06:55

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0031_rename_fname_userrequest_first_name_and_more'),
    ]

    operations = [
        migrations.DeleteModel(
            name='UserRequest',
        ),
    ]
