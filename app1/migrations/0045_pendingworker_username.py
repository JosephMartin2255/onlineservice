# Generated by Django 5.0.4 on 2024-06-17 16:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0044_alter_review_suggestions_alter_review_user_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='pendingworker',
            name='username',
            field=models.CharField(max_length=150, null=True, unique=True),
        ),
    ]
