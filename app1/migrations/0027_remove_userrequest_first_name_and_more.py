# Generated by Django 5.0.4 on 2024-06-10 16:45

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0026_userrequest'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userrequest',
            name='first_name',
        ),
        migrations.RemoveField(
            model_name='userrequest',
            name='image',
        ),
        migrations.RemoveField(
            model_name='userrequest',
            name='last_name',
        ),
        migrations.AddField(
            model_name='userrequest',
            name='photo',
            field=models.ImageField(blank=True, null=True, upload_to='photos/'),
        ),
        migrations.AlterField(
            model_name='userrequest',
            name='department',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='userrequest',
            name='service',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='userrequest',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected')], max_length=20),
        ),
        migrations.AlterField(
            model_name='userrequest',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_requests', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='userrequest',
            name='worker',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='worker_requests', to='app1.usermember'),
        ),
    ]
