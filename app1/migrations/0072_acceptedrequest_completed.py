# Generated by Django 5.0.4 on 2024-06-26 07:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0071_acceptedrequest_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='acceptedrequest',
            name='completed',
            field=models.BooleanField(default=False),
        ),
    ]
