# Generated by Django 5.0.4 on 2024-06-10 05:11

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0022_remove_pendingworker_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='WorkerRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=255)),
                ('last_name', models.CharField(max_length=255)),
                ('address', models.TextField()),
                ('date', models.DateField()),
                ('age', models.IntegerField()),
                ('email', models.EmailField(max_length=254)),
                ('contact_number', models.CharField(max_length=20)),
                ('department', models.CharField(max_length=255)),
                ('service', models.CharField(max_length=255)),
                ('photo', models.ImageField(blank=True, null=True, upload_to='request_photos/')),
                ('status', models.CharField(default='Pending', max_length=10)),
                ('worker', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app1.usermember')),
            ],
        ),
    ]
