# Generated by Django 5.1 on 2024-09-20 19:55

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('socialApp', '0002_remove_friendship_unique_friendship_and_more'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='friendship',
            unique_together={('user1', 'user2')},
        ),
        migrations.AlterField(
            model_name='friendship',
            name='user1',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='friendships1', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='friendship',
            name='user2',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='friendships2', to=settings.AUTH_USER_MODEL),
        ),
        migrations.RemoveField(
            model_name='friendship',
            name='accepted',
        ),
    ]
