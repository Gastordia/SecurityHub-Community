# Generated migration for dashboard app

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('project', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DashboardSnapshot',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('date', models.DateField()),
                ('critical_open', models.IntegerField(default=0)),
                ('high_open', models.IntegerField(default=0)),
                ('medium_open', models.IntegerField(default=0)),
                ('low_open', models.IntegerField(default=0)),
                ('informational_open', models.IntegerField(default=0)),
                ('total_open', models.IntegerField(default=0)),
                ('mttr_critical', models.FloatField(blank=True, null=True)),
                ('mttr_high', models.FloatField(blank=True, null=True)),
                ('mttr_medium', models.FloatField(blank=True, null=True)),
                ('mttr_low', models.FloatField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='snapshots',
                    to='project.project',
                )),
            ],
            options={
                'ordering': ['-date'],
            },
        ),
        migrations.AlterUniqueTogether(
            name='dashboardsnapshot',
            unique_together={('project', 'date')},
        ),
    ]
