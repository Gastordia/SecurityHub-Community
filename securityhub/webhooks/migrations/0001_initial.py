import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='WebhookConfig',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('url', models.URLField(max_length=500)),
                ('secret', models.CharField(blank=True, max_length=200)),
                ('events', models.JSONField(default=list)),
                ('enabled', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='webhook_configs',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='WebhookDelivery',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('event_type', models.CharField(max_length=50)),
                ('payload', models.JSONField()),
                ('response_status', models.IntegerField(blank=True, null=True)),
                ('response_body', models.TextField(blank=True, null=True)),
                ('success', models.BooleanField(default=False)),
                ('delivered_at', models.DateTimeField(auto_now_add=True)),
                ('attempt', models.IntegerField(default=1)),
                ('config', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='deliveries',
                    to='webhooks.webhookconfig',
                )),
            ],
            options={
                'ordering': ['-delivered_at'],
            },
        ),
    ]
