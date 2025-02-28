# Generated by Django 5.0.4 on 2024-05-29 14:43

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0009_usermember_is_pending'),
    ]

    operations = [
        migrations.AddField(
            model_name='department',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='department_requests', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='departmentapprovalrequest',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='approval_department_requests', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='departmentapprovalrequest',
            name='requested_by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='approval_requests', to=settings.AUTH_USER_MODEL),
        ),
    ]
